// On-device pixel check. Pure functions over RGBA arrays (no DOM), so they run in the extension
// and in Node. Results are LOW-CONFIDENCE hints and never reach "alert" level.
//
// One signal, on purpose: the embedded-preview-thumbnail check. Editors often crop or replace an
// image but leave the camera's original preview inside the file. If that preview shows different
// content than the image does, the image was changed after it was captured.
//
// Deliberately NOT included (measured, see experimental/copy-move.js): cloned-region detection
// missed most clones after recompression or scaling, and the alternative gave false alarms on
// grass and other self-similar textures. ELA and noise-inconsistency maps were left out because
// they flag ordinary photos (depth of field, shadows, re-saves) and would mislead more than help.
//
// Measured with tools/export-thumbnail-cases.py + tools/calibrate-thumbnail.mjs on 14 public
// sample images (9 photos, 5 textures/documents) with small JPEG thumbnails made like a camera's:
//   benign (untouched, rotated preview, colour-graded, downscaled + recompressed): 0/56 flagged
//   replaced with a different image: 14/14 flagged
//   cropped to 70% / 50%: 11/14 and 12/14 flagged (a 90% crop: only 3/14, all textures)
//   ~8% of the area painted over (small retouch): 0/14 flagged  <- a known blind spot
// These are synthetic thumbnails on a small public set, not a field study; treat the numbers as a
// rough guide.
//
// Limits to keep in mind: this catches gross changes (a replaced image, a heavy crop), not subtle
// retouching, and a file with no embedded preview gives it nothing to compare.

export function toGray(rgba, w, h) {
  const g = new Float32Array(w * h);
  for (let i = 0, p = 0; i < g.length; i++, p += 4) g[i] = 0.299 * rgba[p] + 0.587 * rgba[p + 1] + 0.114 * rgba[p + 2];
  return g;
}

// Area-average resize (good for downscaling).
export function boxResize(src, w, h, nw, nh) {
  const out = new Float32Array(nw * nh);
  for (let y = 0; y < nh; y++) {
    const y0 = Math.floor((y * h) / nh);
    const y1 = Math.max(y0 + 1, Math.floor(((y + 1) * h) / nh));
    for (let x = 0; x < nw; x++) {
      const x0 = Math.floor((x * w) / nw);
      const x1 = Math.max(x0 + 1, Math.floor(((x + 1) * w) / nw));
      let s = 0;
      for (let yy = y0; yy < y1; yy++) for (let xx = x0; xx < x1; xx++) s += src[yy * w + xx];
      out[y * nw + x] = s / ((y1 - y0) * (x1 - x0));
    }
  }
  return out;
}

const N = 32;
export const MISMATCH_BELOW = 0.5;

function rotate(gray, w, h, quarter) {
  if (quarter === 0) return { g: gray, w, h };
  const out = new Float32Array(w * h);
  if (quarter === 2) { for (let i = 0; i < out.length; i++) out[i] = gray[out.length - 1 - i]; return { g: out, w, h }; }
  for (let y = 0; y < h; y++) {
    for (let x = 0; x < w; x++) {
      const nx = quarter === 1 ? h - 1 - y : y;
      const ny = quarter === 1 ? x : w - 1 - x;
      out[ny * h + nx] = gray[y * w + x];
    }
  }
  return { g: out, w: h, h: w };
}

function pearson(a, b) {
  let ma = 0; let mb = 0;
  for (let i = 0; i < a.length; i++) { ma += a[i]; mb += b[i]; }
  ma /= a.length; mb /= b.length;
  let sab = 0; let saa = 0; let sbb = 0;
  for (let i = 0; i < a.length; i++) { const x = a[i] - ma; const y = b[i] - mb; sab += x * y; saa += x * x; sbb += y * y; }
  return saa < 1e-6 || sbb < 1e-6 ? null : sab / Math.sqrt(saa * sbb);
}

// Both inputs are grayscale. Tries the 4 right-angle orientations (EXIF thumbnails are often stored
// unrotated). Returns { similarity, mismatch } or null when either image is too flat to compare.
export function compareThumbnail(main, mw, mh, thumb, tw, th) {
  const a = boxResize(main, mw, mh, N, N);
  let best = null;
  for (let q = 0; q < 4; q++) {
    const r = rotate(thumb, tw, th, q);
    const s = pearson(a, boxResize(r.g, r.w, r.h, N, N));
    if (s !== null && (best === null || s > best)) best = s;
  }
  if (best === null) return null;
  return { similarity: best, mismatch: best < MISMATCH_BELOW };
}

const SAFE = 'This does not mean the image is untouched.';
const rank = { info: 0, notice: 1, warning: 2 };

// input: { rgba, width, height, thumb?: { rgba, width, height } }, or null when decoding failed.
// reason (optional): why there is no input.
export function analyzePixels(input, reason = '') {
  const out = { ran: false, findings: [], level: 'unknown', headline: '', thumbnail: null };
  if (!input || !input.rgba || !input.width || !input.height) {
    out.headline = `Not run: ${reason || 'the image could not be decoded for this check'}.`;
    return out;
  }
  out.ran = true;
  if (!input.thumb || !input.thumb.rgba) {
    out.headline = `Nothing to compare: this file has no embedded preview thumbnail. ${SAFE}`;
    return out;
  }
  try {
    const { rgba, width: w, height: h, thumb: t } = input;
    const cmp = compareThumbnail(toGray(rgba, w, h), w, h, toGray(t.rgba, t.width, t.height), t.width, t.height);
    out.thumbnail = cmp;
    if (!cmp) {
      out.findings.push({ sev: 'info', text: 'The image or its embedded preview is too uniform to compare.' });
    } else if (cmp.mismatch) {
      out.findings.push({
        sev: 'warning',
        text: `The preview thumbnail embedded in the file looks different from the image (similarity ${cmp.similarity.toFixed(2)} on a 0 to 1 scale). This can happen when software crops, replaces or heavily edits an image but leaves the original preview behind, which can also reveal what the image looked like before. Low confidence.`,
      });
    } else {
      out.findings.push({ sev: 'info', text: `The embedded preview thumbnail matches the image (similarity ${cmp.similarity.toFixed(2)}). That is a weak sign the picture was not cropped or replaced, but it cannot show small retouching.` });
    }
  } catch {
    out.findings.push({ sev: 'info', text: 'The pixel check could not finish on this image.' });
  }
  const max = Math.max(0, ...out.findings.map((f) => rank[f.sev] || 0));
  out.level = ['unknown', 'notice', 'warning'][max];
  const top = out.findings.reduce((a, f) => (rank[f.sev] > rank[a.sev] ? f : a), out.findings[0]);
  out.headline = max
    ? 'The embedded preview thumbnail differs from the image (possible edit, low confidence)'
    : (top && /matches/.test(top.text) ? `Embedded preview matches the image. ${SAFE}` : `No clear result from this check. ${SAFE}`);
  return out;
}
