import test from 'node:test';
import assert from 'node:assert/strict';
import { analyzeImageFull, extractThumbnail } from '../analyzer/report.js';
import { analyzePixels, boxResize } from '../analyzer/pixels.js';
import { buildAnchorIndex } from '../analyzer/pki.js';
import { pemToDers } from '../analyzer/der.js';
import { jpeg, png } from './fixtures.js';
import { signedFile, readCert } from './c2pa-builder.js';

const NOW = new Date('2026-11-07T00:00:00Z');
const anchors = pemToDers(readCert('ca.pem'));
const sec = (r, key) => r.summary.find((s) => s.key === key);
const full = (file, opts = { anchors, now: NOW }) =>
  analyzeImageFull({ url: 'https://example.com/a.jpg', bytes: file, contentType: 'image/jpeg' }, opts);

// ------------------------------------------------------------------ report integration (C2PA)
test('valid, trusted credentials give a green Authenticity section', async () => {
  const r = await full(signedFile().file);
  const a = sec(r, 'authenticity');
  assert.equal(a.level, 'clear');
  assert.match(a.headline, /Valid Content Credentials, signed by Test Signer ES256/);
  assert.equal(r.summary.length, 4); // no pixel check unless the caller ran it
});

test('tampered image gives a red Authenticity section naming the cause', async () => {
  const bad = Uint8Array.from(signedFile().file);
  bad[bad.length - 20] ^= 0xff;
  const a = sec(await full(bad), 'authenticity');
  assert.equal(a.level, 'alert');
  assert.match(a.headline, /INVALID/);
  assert.ok(a.findings.some((f) => /image data does not match/.test(f.text)));
});

test('without a trust list the section is a notice that says the signer was not checked', async () => {
  const a = sec(await full(signedFile().file, { now: NOW }), 'authenticity');
  assert.equal(a.level, 'notice');
  assert.match(a.headline, /not checked/);
});

test('signed AI-generation claim is shown as an AI warning, not as reassurance', async () => {
  const a = sec(await full(signedFile({ ai: true }).file), 'authenticity');
  assert.equal(a.level, 'warning');
  assert.match(a.headline, /say this image is AI-generated/);
});

test('PNG credentials work through the full report too', async () => {
  const r = await analyzeImageFull({ url: 'https://example.com/a.png', bytes: signedFile({ format: 'png' }).file, contentType: 'image/png' }, { anchors, now: NOW });
  assert.equal(sec(r, 'authenticity').level, 'clear');
});

test('plain images are unaffected (still "unknown", honest about it)', async () => {
  const a = sec(await full(jpeg()), 'authenticity');
  assert.equal(a.level, 'unknown');
});

test('trust list helpers: PEM bundle -> index, garbage -> null', () => {
  assert.equal(buildAnchorIndex(anchors).size_, 1);
  assert.equal(buildAnchorIndex([]), null);
  assert.equal(buildAnchorIndex([new Uint8Array([1, 2, 3])]), null);
  assert.deepEqual(pemToDers('not a pem'), []);
});

test('fuzz through the full report: never throws, always a well-formed report', async () => {
  const { file } = signedFile({ maxSegData: 900 });
  let state = 99;
  const rnd = () => (state = (state * 1103515245 + 12345) & 0x7fffffff) / 0x7fffffff;
  for (let i = 0; i < 120; i++) {
    const copy = Uint8Array.from(file);
    copy[Math.floor(rnd() * copy.length)] ^= 1 + Math.floor(rnd() * 255);
    const r = await full(rnd() < 0.3 ? copy.subarray(0, Math.floor(rnd() * copy.length)) : copy);
    assert.equal(r.summary.length, 4);
    for (const s of r.summary) assert.ok(typeof s.headline === 'string' && Array.isArray(s.findings));
  }
});

// ------------------------------------------------------------------ embedded thumbnail extraction
function tiffWithThumb(thumb, { badOffset = false } = {}) {
  const b = Buffer.alloc(44);
  b.write('II', 0, 'latin1'); b.writeUInt16LE(42, 2); b.writeUInt32LE(8, 4);
  b.writeUInt16LE(0, 8); b.writeUInt32LE(14, 10); // IFD0: no entries, next IFD at 14
  b.writeUInt16LE(2, 14); // IFD1
  b.writeUInt16LE(0x0201, 16); b.writeUInt16LE(4, 18); b.writeUInt32LE(1, 20); b.writeUInt32LE(badOffset ? 5000 : 44, 24);
  b.writeUInt16LE(0x0202, 28); b.writeUInt16LE(4, 30); b.writeUInt32LE(1, 32); b.writeUInt32LE(thumb.length, 36);
  b.writeUInt32LE(0, 40);
  return Buffer.concat([b, thumb]);
}
const fakeThumb = Buffer.concat([Buffer.from([0xff, 0xd8]), Buffer.alloc(200, 7), Buffer.from([0xff, 0xd9])]);

test('EXIF preview thumbnail is extracted from a JPEG', () => {
  const t = extractThumbnail(jpeg({ tiff: tiffWithThumb(fakeThumb) }));
  assert.ok(t && Buffer.from(t).equals(fakeThumb));
});

test('thumbnail extraction rejects bad offsets, non-JPEG data, other formats and hostile input', () => {
  assert.equal(extractThumbnail(jpeg({ tiff: tiffWithThumb(fakeThumb, { badOffset: true }) })), null);
  assert.equal(extractThumbnail(jpeg({ tiff: tiffWithThumb(Buffer.alloc(300, 1)) })), null); // not a JPEG
  assert.equal(extractThumbnail(jpeg()), null);
  assert.equal(extractThumbnail(png()), null);
  assert.equal(extractThumbnail(new Uint8Array(0)), null);
  const t = tiffWithThumb(fakeThumb);
  let state = 5;
  const rnd = () => (state = (state * 1103515245 + 12345) & 0x7fffffff) / 0x7fffffff;
  for (let i = 0; i < 300; i++) {
    const c = Buffer.from(t);
    c[Math.floor(rnd() * c.length)] ^= 1 + Math.floor(rnd() * 255);
    extractThumbnail(jpeg({ tiff: c })); // must not throw
  }
});

// ------------------------------------------------------------------ pixel (edit) check
function blobs(w, h, seed) { // detailed, photo-like synthetic image (RGBA); different seeds are independent
  let s = (Math.imul(seed, 2654435761) ^ 0x9e3779b9) >>> 0;
  const rnd = () => { s = (Math.imul(s, 1664525) + 1013904223) >>> 0; s ^= s >>> 15; return (s >>> 0) / 4294967296; };
  for (let i = 0; i < 8; i++) rnd(); // warm-up
  const bl = Array.from({ length: 45 }, () => ({ x: rnd() * w, y: rnd() * h, r: 3 + rnd() * w * 0.07, a: 40 + rnd() * 160, c: [rnd(), rnd(), rnd()] }));
  const rgba = new Uint8ClampedArray(w * h * 4);
  for (let y = 0; y < h; y++) for (let x = 0; x < w; x++) {
    const rgb = [20, 20, 20];
    for (const b of bl) {
      const g = b.a * Math.exp(-((x - b.x) ** 2 + (y - b.y) ** 2) / (2 * b.r * b.r));
      for (let k = 0; k < 3; k++) rgb[k] += g * b.c[k];
    }
    const p = (y * w + x) * 4;
    for (let k = 0; k < 3; k++) rgba[p + k] = Math.min(255, rgb[k]);
    rgba[p + 3] = 255;
  }
  return { rgba, width: w, height: h };
}
function shrink(img, nw, nh) {
  const out = new Uint8ClampedArray(nw * nh * 4);
  for (let k = 0; k < 3; k++) {
    const ch = new Float32Array(img.width * img.height);
    for (let i = 0; i < ch.length; i++) ch[i] = img.rgba[i * 4 + k];
    const sm = boxResize(ch, img.width, img.height, nw, nh);
    for (let i = 0; i < sm.length; i++) out[i * 4 + k] = sm[i];
  }
  for (let i = 0; i < nw * nh; i++) out[i * 4 + 3] = 255;
  return { rgba: out, width: nw, height: nh };
}
function rotate90(img) {
  const { width: w, height: h } = img;
  const out = new Uint8ClampedArray(w * h * 4);
  for (let y = 0; y < h; y++) for (let x = 0; x < w; x++) out.set(img.rgba.subarray((y * w + x) * 4, (y * w + x) * 4 + 4), (x * h + (h - 1 - y)) * 4);
  return { rgba: out, width: h, height: w };
}

test('edit check: a matching preview is a weak, non-alarming result', () => {
  const main = blobs(160, 120, 1);
  const r = analyzePixels({ ...main, thumb: shrink(main, 40, 30) });
  assert.equal(r.ran, true);
  assert.equal(r.level, 'unknown');
  assert.ok(r.thumbnail.similarity > 0.95);
  assert.match(r.headline, /does not mean the image is untouched/);
});

test('edit check: a preview stored sideways still matches', () => {
  const main = blobs(160, 120, 2);
  const r = analyzePixels({ ...main, thumb: rotate90(shrink(main, 40, 30)) });
  assert.equal(r.thumbnail.mismatch, false);
});

test('edit check: unrelated images are mostly flagged as low confidence, never above "warning"', () => {
  // Probabilistic by nature: smooth, low-detail images can look alike at thumbnail size, so a
  // different image is sometimes missed (here 5 of 7 pairs are clearly flagged, 1 sits at 0.49
  // and 1 at 0.52). Assert the rate, not a hand-picked pair, and never tune the threshold to it.
  let flagged = 0;
  const pairs = [[1, 101], [2, 202], [3, 303], [4, 404], [5, 505], [6, 606], [7, 707]];
  for (const [x, y] of pairs) {
    const r = analyzePixels({ ...blobs(160, 120, x), thumb: shrink(blobs(160, 120, y), 40, 30) });
    assert.notEqual(r.level, 'alert');
    if (r.level === 'warning') { flagged++; assert.match(r.findings[0].text, /Low confidence/); }
  }
  assert.ok(flagged >= 5, `only ${flagged}/${pairs.length} unrelated pairs flagged`);
});

test('edit check: honest when there is nothing to compare, nothing decoded, or a flat image', () => {
  assert.match(analyzePixels(blobs(60, 40, 5)).headline, /no embedded preview/);
  assert.match(analyzePixels(null, 'the browser could not decode this image').headline, /^Not run: the browser could not decode/);
  assert.equal(analyzePixels(null).ran, false);
  const flat = { rgba: new Uint8ClampedArray(40 * 30 * 4).fill(128), width: 40, height: 30 };
  const r = analyzePixels({ ...flat, thumb: flat });
  assert.equal(r.level, 'unknown');
  assert.equal(r.thumbnail, null);
});

test('edit check: hostile input never throws', () => {
  for (const bad of [{}, { rgba: new Uint8Array(3), width: 5, height: 5 }, { rgba: new Uint8Array(16), width: 2, height: 2, thumb: { rgba: new Uint8Array(1), width: 9, height: 9 } }]) {
    const r = analyzePixels(bad);
    assert.ok(r && typeof r.headline === 'string');
  }
});

test('report gains a fifth section only when the edit check was run', async () => {
  const file = jpeg();
  const base = { url: 'https://example.com/a.jpg', bytes: file, contentType: 'image/jpeg' };
  assert.equal((await analyzeImageFull(base, { now: NOW })).summary.length, 4);
  const main = blobs(160, 120, 1);
  const r = await analyzeImageFull(base, { now: NOW, pixelInput: { ...main, thumb: shrink(blobs(160, 120, 101), 40, 30) } });
  assert.equal(r.summary.length, 5);
  assert.equal(sec(r, 'pixels').level, 'warning');
  assert.match(sec(r, 'pixels').label, /experimental/i);
  const skipped = await analyzeImageFull(base, { now: NOW, pixelInput: null, pixelReason: 'the image is too large to decode safely' });
  assert.match(sec(skipped, 'pixels').headline, /Not run: the image is too large/);
});
