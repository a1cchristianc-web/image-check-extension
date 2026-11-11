// Combines every check into one report: four sections, each with a level and findings.
// Levels: clear | notice | warning | alert | unknown. Finding severities add 'info' (never raises a level).
import { clean } from './bytes.js';
import { sniffType, mimeFor, dimensions, trailingData, svgInfo } from './sniff.js';
import { parseJpegMeta, parsePngMeta, parseWebpMeta, parseIsoMeta, provenance } from './meta.js';
import { verifyC2pa } from './c2pa.js';
import { analyzePixels } from './pixels.js';

const ORDER = { info: 0, notice: 1, warning: 2, alert: 3 };
const LEVELS = ['clear', 'notice', 'warning', 'alert'];
const EXT_TYPE = {
  png: 'png', jpg: 'jpeg', jpeg: 'jpeg', gif: 'gif', webp: 'webp', bmp: 'bmp', ico: 'ico',
  svg: 'svg', avif: 'avif', heic: 'heic', heif: 'heic',
};
const MIME_ALIAS = {
  'image/jpg': 'image/jpeg', 'image/pjpeg': 'image/jpeg', 'image/x-png': 'image/png',
  'image/vnd.microsoft.icon': 'image/x-icon', 'image/heif': 'image/heic',
};

function levelOf(findings) {
  return LEVELS[Math.max(0, ...findings.map((f) => ORDER[f.sev] || 0))];
}
function headlineOf(findings, fallback) {
  const max = Math.max(0, ...findings.map((f) => ORDER[f.sev] || 0));
  if (max === 0) return fallback;
  return findings.find((f) => (ORDER[f.sev] || 0) === max).text;
}
function urlExt(url) {
  try {
    const m = new URL(url).pathname.match(/\.([a-z0-9]+)$/i);
    return m ? m[1].toLowerCase() : '';
  } catch { return ''; }
}

function exposureFindings(parsed, out) {
  const ex = parsed.exif || {};
  const text = parsed.text || {};
  if (ex.gps) {
    const alt = Number.isFinite(ex.gps.alt) ? ` (altitude ${Math.round(ex.gps.alt)} m)` : '';
    out.push({
      sev: 'alert',
      text: `Embedded GPS location: ${ex.gps.lat.toFixed(4)}, ${ex.gps.lon.toFixed(4)}${alt}. Anyone who saves or re-shares this file passes the location along.`,
    });
  } else if (parsed.xmp && /GPSLatitude/i.test(parsed.xmp)) {
    out.push({ sev: 'warning', text: 'XMP metadata contains GPS location fields.' });
  }
  if (ex.BodySerialNumber || ex.LensSerialNumber) {
    out.push({ sev: 'warning', text: 'Camera or lens serial number is embedded; it can link photos to one device or owner.' });
  }
  if (ex.CameraOwnerName || ex.Artist) {
    out.push({ sev: 'notice', text: `Names a person: ${clean(ex.CameraOwnerName || ex.Artist, 60)}` });
  }
  if (ex.Make || ex.Model) {
    out.push({ sev: 'notice', text: `Device model embedded: ${clean([ex.Make, ex.Model].filter(Boolean).join(' '), 60)}` });
  }
  if (ex.DateTimeOriginal || ex.DateTime) {
    out.push({ sev: 'notice', text: `Capture or edit time embedded: ${clean(ex.DateTimeOriginal || ex.DateTime, 30)}` });
  }
  if (ex.ImageDescription) {
    out.push({ sev: 'notice', text: `Embedded description: ${clean(ex.ImageDescription, 80)}` });
  }
  if (ex.MakerNote) out.push({ sev: 'info', text: `Manufacturer-specific data block present (${ex.MakerNote}).` });
  for (const key of ['Author', 'Copyright', 'Source', 'Description', 'Creation Time', 'Title']) {
    if (text[key]) out.push({ sev: 'notice', text: `Embedded ${key.toLowerCase()}: ${clean(text[key], 80)}` });
  }
}

function analyzeBytes({ bytes, url, contentType, sec, info, c2pa }) {
  const type = sniffType(bytes);
  info.type = type;
  info.dims = dimensions(bytes, type);
  const mime = mimeFor(type);

  // ---- integrity
  if (type === 'html') {
    sec.integrity.push({ sev: 'alert', text: 'This "image" is actually a web page (HTML). Disguised pages are a common phishing and script-injection trick.' });
  } else if (type === 'unknown') {
    sec.integrity.push({ sev: 'warning', text: 'The file is not in a recognised image format.' });
  }
  const knownType = type !== 'unknown' && type !== 'html';
  const extType = EXT_TYPE[urlExt(url)];
  if (knownType && extType && extType !== type) {
    sec.integrity.push({ sev: 'notice', text: `The URL ends in .${urlExt(url)} but the file is really ${type.toUpperCase()}.` });
  }
  const ct = String(contentType).split(';')[0].trim().toLowerCase();
  if (ct) {
    if (!ct.startsWith('image/')) {
      if (!/octet-stream/.test(ct)) sec.integrity.push({ sev: 'warning', text: `The server labels this file as "${clean(ct, 40)}", not an image.` });
    } else if (knownType && mime && (MIME_ALIAS[ct] || ct) !== mime) {
      sec.integrity.push({ sev: 'notice', text: `The server says ${clean(ct, 40)} but the file is really ${mime}.` });
    }
  }
  if (info.dims && info.dims.w * info.dims.h > 100e6) {
    sec.integrity.push({ sev: 'warning', text: `Extremely large dimensions (${info.dims.w}x${info.dims.h}); such files can exhaust memory when decoded.` });
  }
  const tr = trailingData(bytes, type);
  if (tr) {
    if (tr.signatures.length) {
      sec.integrity.push({ sev: 'alert', text: `${tr.length} bytes hidden after the image ends, containing what looks like ${tr.signatures.join(', ')}.` });
    } else if (tr.length > 16) {
      sec.integrity.push({ sev: 'warning', text: `${tr.length} bytes of unexplained data are appended after the image ends. This can hide payloads or metadata.` });
    }
  }
  if (type === 'svg') {
    const svg = svgInfo(bytes);
    if (svg.active.length) {
      sec.integrity.push({ sev: 'warning', text: `SVG contains active content (${svg.active.join(', ')}). Harmless inside an <img> tag, dangerous if opened directly.` });
    }
    if (svg.external) {
      sec.tracking.push({ sev: 'warning', text: 'SVG references other web addresses; opening it directly can make requests to them.' });
    }
  }

  // ---- tracking pixel by size
  if (info.dims && info.dims.w * info.dims.h <= 4) {
    const escalated = sec.tracking.some((f) => (ORDER[f.sev] || 0) >= 1);
    sec.tracking.push({
      sev: escalated ? 'alert' : 'warning',
      text: `The image is only ${info.dims.w}x${info.dims.h} pixels, the classic size of a tracking pixel.`,
    });
  }

  // ---- metadata (exposure + authenticity)
  let parsed = { exif: {}, text: {}, xmp: null, c2pa: false, c2paText: '' };
  if (type === 'jpeg') parsed = parseJpegMeta(bytes);
  else if (type === 'png') parsed = parsePngMeta(bytes);
  else if (type === 'webp') parsed = parseWebpMeta(bytes);
  else if (type === 'avif' || type === 'heic') parsed = parseIsoMeta(bytes);
  else sec.exposure.push({ sev: 'info', text: `Metadata reading is implemented for JPEG, PNG, WebP, AVIF and HEIC; ${type.toUpperCase()} files were not inspected for hidden data.` });
  exposureFindings(parsed, sec.exposure);
  const prov = provenance(parsed, c2pa);
  sec.authenticity.push(...prov.findings);
  return prov;
}

export function analyzeImage({ url, pageUrl = '', bytes = null, contentType = '', urlFindings = [], note = '', c2pa = null, pixels = null }) {
  const sec = { tracking: [], exposure: [], authenticity: [], integrity: [] };
  for (const f of urlFindings) sec.tracking.push({ sev: f.sev, text: f.text });
  const info = {
    url: clean(url, 300), pageUrl: clean(pageUrl, 300), size: bytes ? bytes.length : null,
    type: null, dims: null, contentType: clean(contentType, 60), note: clean(note, 300),
  };

  let prov = { level: 'unknown', headline: "Couldn't read the file, so authenticity wasn't checked" };
  if (bytes) {
    try {
      prov = analyzeBytes({ bytes, url, contentType, sec, info, c2pa });
    } catch {
      sec.integrity.push({ sev: 'notice', text: 'Analysis stopped early; the file may be malformed.' });
    }
  } else {
    sec.integrity.push({ sev: 'info', text: info.note || 'The image file was not analyzed.' });
  }

  const unread = !bytes;
  const summary = [
    {
      key: 'tracking', label: 'Tracking', findings: sec.tracking, level: levelOf(sec.tracking),
      headline: headlineOf(sec.tracking, unread ? 'No tracking signs in the URL (file not inspected)' : 'No tracking signs found'),
    },
    {
      key: 'exposure', label: 'Hidden data', findings: sec.exposure,
      level: unread ? 'unknown' : levelOf(sec.exposure),
      headline: unread ? "File wasn't read" : headlineOf(sec.exposure, 'No hidden personal data found'),
    },
    {
      key: 'authenticity', label: 'Authenticity', findings: sec.authenticity,
      level: prov.level, headline: prov.headline,
    },
    {
      key: 'integrity', label: 'File safety', findings: sec.integrity,
      level: unread ? 'unknown' : levelOf(sec.integrity),
      headline: unread ? "File wasn't read" : headlineOf(sec.integrity, 'File structure looks normal'),
    },
  ];
  // Experimental on-device pixel check: only present when the caller ran it.
  if (pixels) {
    summary.push({
      key: 'pixels', label: 'Edit check (experimental)', findings: pixels.findings,
      level: pixels.level, headline: pixels.headline,
    });
  }
  return { info, summary, limits: limitsFor(info, c2pa, pixels) };
}

// Plain-language list of what THIS check could not tell the user, tailored to the file and to what ran.
export function limitsFor(info, c2pa, pixels) {
  const out = [];
  const type = info && info.type;
  if (!type) {
    out.push('The image file itself was not read, so only its web address was looked at.');
    return out;
  }
  out.push('Nothing found does not mean an image is real, safe or untracked: platforms strip metadata, and metadata can be forged.');
  if (!['jpeg', 'png', 'webp', 'avif', 'heic'].includes(type)) out.push(`Hidden-data reading is not available for ${type.toUpperCase()} files.`);
  out.push('Information hidden inside the pixels themselves is not detected.');
  out.push('This is not a virus scan, and it cannot tell whether a picture is AI-generated from how it looks.');
  if (c2pa && c2pa.found) {
    out.push('Credentials show who signed an image and that it is unchanged since then. They do not show the content is true.');
    out.push('Certificate revocation and signing timestamps were not checked.');
  } else if (type === 'jpeg' || type === 'png' || type === 'webp') {
    out.push('No Content Credentials were found; most images online have them stripped, so this says nothing either way.');
  } else {
    out.push('Signatures can only be verified for JPEG, PNG and WebP files; credentials in other formats are reported as present but not verified.');
  }
  if (pixels) out.push('The edit check only compares the embedded preview with the full image, so it misses small retouching and files that have no preview.');
  return out;
}

// The embedded preview thumbnail (JPEG bytes) of a JPEG file, or null. The caller decodes it.
export function extractThumbnail(bytes) {
  try {
    return sniffType(bytes) === 'jpeg' ? parseJpegMeta(bytes).thumbnail : null;
  } catch {
    return null;
  }
}

// Full analysis including C2PA signature verification (async because it uses WebCrypto).
// opts: { anchors: DER trust anchors | Map, now: Date,
//         pixelInput: decoded pixels for the edit check (see pixels.js) | null,
//         pixelReason: why there are none }
// Pass `pixelInput: undefined` (omit it) to skip the edit check entirely.
export async function analyzeImageFull(args, opts = {}) {
  let c2pa = null;
  if (args.bytes) {
    try { c2pa = await verifyC2pa(args.bytes, opts); } catch { c2pa = null; }
  }
  const pixels = 'pixelInput' in opts && args.bytes ? analyzePixels(opts.pixelInput, opts.pixelReason) : null;
  return analyzeImage({ ...args, c2pa, pixels });
}
