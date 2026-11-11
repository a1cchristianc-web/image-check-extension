// Service worker: context menu -> (safe) fetch -> analyze -> show panel in the page.
import { analyzeImage, analyzeImageFull, extractThumbnail } from './analyzer/report.js';
import { analyzeUrl } from './analyzer/tracking.js';
import { sniffType, mimeFor, dimensions } from './analyzer/sniff.js';
import { pemToDers } from './analyzer/der.js';
import { buildAnchorIndex } from './analyzer/pki.js';
import { renderPanel } from './panel.js';

const MENU_ID = 'image-check';
const MAX_BYTES = 25 * 1024 * 1024;
const PIXEL_MAX_SIDE = 512; // the edit check works on a downscaled copy
const PIXEL_MAX_PIXELS = 100e6;

// C2PA trust list: an optional PEM bundle shipped with the extension (see trust/README.md).
// Without it, signatures are still verified but signer identity is reported as "not checked".
let anchorsPromise = null;
function loadAnchors() {
  anchorsPromise ??= (async () => {
    try {
      const res = await fetch(chrome.runtime.getURL('trust/c2pa-trust.pem'));
      if (!res.ok) return null;
      return buildAnchorIndex(pemToDers(await res.text()));
    } catch {
      return null;
    }
  })();
  return anchorsPromise;
}

// Decode the image (and its embedded preview thumbnail, if any) to RGBA for the edit check.
// EXIF orientation is ignored on purpose: the check compares both copies in all 4 orientations.
async function decodeFor(bytes) {
  const type = sniffType(bytes);
  if (!['jpeg', 'png', 'webp', 'gif', 'bmp'].includes(type)) return { input: null, reason: 'this image type is not supported by the check' };
  const dims = dimensions(bytes, type);
  if (!dims) return { input: null, reason: 'the image size could not be read' };
  if (dims.w * dims.h > PIXEL_MAX_PIXELS) return { input: null, reason: 'the image is too large to decode safely' };
  const toRgba = async (data, mime, maxSide, d) => {
    const scale = maxSide ? Math.min(1, maxSide / Math.max(d.w, d.h)) : 1;
    const opts = { imageOrientation: 'none' };
    if (scale < 1) Object.assign(opts, { resizeWidth: Math.max(1, Math.round(d.w * scale)), resizeHeight: Math.max(1, Math.round(d.h * scale)), resizeQuality: 'high' });
    const bmp = await createImageBitmap(new Blob([data], { type: mime }), opts);
    try {
      const canvas = new OffscreenCanvas(bmp.width, bmp.height);
      const ctx = canvas.getContext('2d', { willReadFrequently: true });
      ctx.drawImage(bmp, 0, 0);
      const px = ctx.getImageData(0, 0, bmp.width, bmp.height);
      return { rgba: px.data, width: px.width, height: px.height };
    } finally {
      bmp.close();
    }
  };
  try {
    const input = await toRgba(bytes, mimeFor(type), PIXEL_MAX_SIDE, dims);
    const tb = extractThumbnail(bytes);
    if (tb) {
      try {
        const td = dimensions(tb, 'jpeg');
        if (td) input.thumb = await toRgba(tb, 'image/jpeg', 0, td);
      } catch { /* thumbnail undecodable: compare nothing */ }
    }
    return { input, reason: '' };
  } catch {
    return { input: null, reason: 'the browser could not decode this image' };
  }
}

chrome.runtime.onInstalled.addListener(() => {
  chrome.contextMenus.create({
    id: MENU_ID,
    title: 'Check this image (privacy & authenticity)',
    contexts: ['image'],
  });
});

chrome.contextMenus.onClicked.addListener(async (info, tab) => {
  if (info.menuItemId !== MENU_ID || !tab || tab.id === undefined || !info.srcUrl) return;
  const pageUrl = info.pageUrl || tab.url || '';
  const urlFindings = analyzeUrl(info.srcUrl, pageUrl);

  // Ask for access first, while the click still counts as a user gesture.
  let access = false;
  const wantsFetch = /^https?:/i.test(info.srcUrl) && !urlFindings.some((f) => f.skipFetch);
  if (wantsFetch) access = await ensureAccess(info.srcUrl);

  let report;
  try {
    report = await buildReport(info.srcUrl, pageUrl, urlFindings, wantsFetch, access);
  } catch (e) {
    report = analyzeImage({ url: info.srcUrl, pageUrl, urlFindings, note: 'Analysis failed unexpectedly.' });
  }

  try {
    await chrome.scripting.executeScript({ target: { tabId: tab.id }, func: renderPanel, args: [report] });
  } catch {
    // Pages where scripts can't be injected (chrome://, the Web Store, PDF viewer): use the badge.
    const worst = report.summary.map((s) => s.level).find((l) => l === 'alert')
      || report.summary.map((s) => s.level).find((l) => l === 'warning');
    chrome.action.setBadgeText({ tabId: tab.id, text: worst ? '!' : 'OK' });
    chrome.action.setTitle({ tabId: tab.id, title: report.summary.map((s) => `${s.label}: ${s.headline}`).join('\n') });
  }
});

async function ensureAccess(url) {
  try {
    const u = new URL(url);
    const perm = { origins: [`${u.protocol}//${u.hostname}/*`] };
    if (await chrome.permissions.contains(perm)) return true;
    return await chrome.permissions.request(perm);
  } catch {
    return false;
  }
}

async function buildReport(url, pageUrl, urlFindings, wantsFetch, access) {
  let bytes = null;
  let contentType = '';
  let note = '';

  if (url.startsWith('data:')) {
    const d = decodeDataUrl(url);
    if (d) ({ bytes, contentType } = d);
    else note = 'Could not decode the embedded image.';
  } else if (!/^https?:/i.test(url)) {
    note = 'This kind of image address (for example blob:) can only be read by the page itself.';
  } else if (!wantsFetch) {
    note = 'Download skipped on purpose: the URL looks like a tracker, and fetching it would ping the tracker. Only URL checks were run.';
  } else if (!access) {
    note = 'No permission to download this image, so only URL checks were run. Allow access when prompted, or via the extension details page (Site access).';
  } else {
    try {
      ({ bytes, contentType } = await fetchLimited(url));
    } catch (e) {
      note = `Could not download the image (${e.message}). Only URL checks were run.`;
    }
  }
  if (!bytes) return analyzeImage({ url, pageUrl, bytes, contentType, urlFindings, note });
  const [anchors, pixels] = await Promise.all([loadAnchors(), decodeFor(bytes)]);
  return analyzeImageFull(
    { url, pageUrl, bytes, contentType, urlFindings, note },
    { anchors, pixelInput: pixels.input, pixelReason: pixels.reason },
  );
}

// Privacy-minded fetch: no cookies, no referrer, size and time limits.
async function fetchLimited(url) {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), 15000);
  try {
    const res = await fetch(url, { credentials: 'omit', referrerPolicy: 'no-referrer', redirect: 'follow', signal: ctrl.signal });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    if (Number(res.headers.get('content-length') || 0) > MAX_BYTES) throw new Error('file larger than 25 MB');
    const reader = res.body.getReader();
    const chunks = [];
    let total = 0;
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.length;
      if (total > MAX_BYTES) { ctrl.abort(); throw new Error('file larger than 25 MB'); }
      chunks.push(value);
    }
    const bytes = new Uint8Array(total);
    let o = 0;
    for (const c of chunks) { bytes.set(c, o); o += c.length; }
    return { bytes, contentType: res.headers.get('content-type') || '' };
  } finally {
    clearTimeout(timer);
  }
}

function decodeDataUrl(url) {
  try {
    const comma = url.indexOf(',');
    if (comma < 0) return null;
    const meta = url.slice(5, comma);
    const body = url.slice(comma + 1);
    let bytes;
    if (/;base64/i.test(meta)) {
      const bin = atob(body);
      bytes = new Uint8Array(bin.length);
      for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
    } else {
      bytes = new TextEncoder().encode(decodeURIComponent(body));
    }
    if (bytes.length > MAX_BYTES) return null;
    return { bytes, contentType: meta.split(';')[0] };
  } catch {
    return null;
  }
}
