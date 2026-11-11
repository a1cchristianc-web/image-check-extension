import test from 'node:test';
import assert from 'node:assert/strict';
import { analyzeImage } from '../analyzer/report.js';
import { analyzeUrl } from '../analyzer/tracking.js';
import { png, jpeg, trackingGif, tiff } from './fixtures.js';

const run = (bytes, extra = {}) => analyzeImage({ url: 'https://example.com/a.png', bytes, ...extra });
const sec = (r, key) => r.summary.find((s) => s.key === key);
const has = (section, re) => section.findings.some((f) => re.test(f.text));
const enc = (s) => new Uint8Array(Buffer.from(s, 'latin1'));

test('plain image: nothing alarming, and provenance honestly says "unknown"', () => {
  const r = run(png());
  assert.equal(sec(r, 'tracking').level, 'clear');
  assert.equal(sec(r, 'exposure').level, 'clear');
  assert.equal(sec(r, 'integrity').level, 'clear');
  assert.equal(sec(r, 'authenticity').level, 'unknown');
  assert.match(sec(r, 'authenticity').headline, /does not mean/);
  assert.deepEqual(r.info.dims, { w: 16, h: 16 });
});

test('EXIF: GPS location, serial number and device are surfaced', () => {
  const t = tiff({
    ifd0: [[0x010f, 2, 'ACME'], [0x0110, 2, 'Cam-1']],
    exif: [[0xa431, 2, 'SN12345678']],
    gps: [
      [1, 2, 'N'], [2, 5, [[40, 1], [42, 1], [4608, 100]]],
      [3, 2, 'W'], [4, 5, [[74, 1], [0, 1], [216, 10]]],
    ],
  });
  const r = run(jpeg({ tiff: t }), { url: 'https://example.com/a.jpg' });
  const ex = sec(r, 'exposure');
  assert.equal(ex.level, 'alert');
  assert.ok(has(ex, /40\.7128, -74\.0060/), 'GPS decimal degrees');
  assert.ok(has(ex, /serial number/i));
  assert.ok(has(ex, /ACME Cam-1/));
  assert.equal(sec(r, 'authenticity').level, 'notice'); // camera metadata, flagged as forgeable
  assert.match(sec(r, 'authenticity').headline, /forged/);
});

test('editing software is reported', () => {
  const r = run(jpeg({ tiff: tiff({ ifd0: [[0x0131, 2, 'Adobe Photoshop 25.0']] }) }), { url: 'https://x.test/a.jpg' });
  assert.match(sec(r, 'authenticity').headline, /Photoshop/);
});

test('IPTC digital source type marks an image as AI-generated', () => {
  const xmp = '<x:xmpmeta><rdf:Description Iptc4xmpExt:DigitalSourceType="http://cv.iptc.org/newscodes/digitalsourcetype/trainedAlgorithmicMedia"/></x:xmpmeta>';
  const r = run(jpeg({ xmp }), { url: 'https://x.test/a.jpg' });
  assert.equal(sec(r, 'authenticity').level, 'warning');
  assert.match(sec(r, 'authenticity').headline, /AI-generated/);
});

test('composite-with-AI label is reported as partial', () => {
  const xmp = 'digitalsourcetype/compositeWithTrainedAlgorithmicMedia';
  const r = run(jpeg({ xmp }), { url: 'https://x.test/a.jpg' });
  assert.match(sec(r, 'authenticity').headline, /AI-generated elements/);
});

test('Stable Diffusion settings in PNG text are detected', () => {
  const r = run(png({ text: { parameters: 'a cat\nSteps: 20, Sampler: Euler a, CFG scale: 7' } }));
  assert.equal(sec(r, 'authenticity').level, 'warning');
  assert.ok(has(sec(r, 'authenticity'), /Stable Diffusion/));
});

test('C2PA Content Credentials are detected but flagged as unverified', () => {
  const r = run(png({ extra: [['caBX', 'jumb c2pa.claim claim_generator Example/1.0']] }));
  const a = sec(r, 'authenticity');
  assert.equal(a.level, 'notice');
  assert.ok(has(a, /does NOT verify/));
  const j = run(jpeg({ c2pa: 'JP\0\0jumb c2pa' }), { url: 'https://x.test/a.jpg' });
  assert.equal(sec(j, 'authenticity').level, 'notice');
});

test('C2PA naming an AI generator is flagged', () => {
  const r = run(png({ extra: [['caBX', 'jumb c2pa claim_generator OpenAI']] }));
  assert.equal(sec(r, 'authenticity').level, 'warning');
});

test('script hidden after the image end is an alert', () => {
  const r = run(png({ trailing: '<script>alert(1)</script>' }));
  const s = sec(r, 'integrity');
  assert.equal(s.level, 'alert');
  assert.ok(has(s, /JavaScript/));
});

test('unexplained appended data is a warning; a trailing newline is not', () => {
  assert.equal(sec(run(jpeg({ trailing: 'x'.repeat(100) }), { url: 'https://x.test/a.jpg' }), 'integrity').level, 'warning');
  assert.equal(sec(run(jpeg({ trailing: '\n' }), { url: 'https://x.test/a.jpg' }), 'integrity').level, 'clear');
});

test('HTML disguised as an image is an alert', () => {
  const r = run(enc('<html><script>steal()</script></html>'));
  assert.equal(sec(r, 'integrity').level, 'alert');
});

test('URL extension and Content-Type mismatches', () => {
  assert.equal(sec(run(png(), { url: 'https://x.test/a.jpg' }), 'integrity').level, 'notice');
  assert.equal(sec(run(png(), { contentType: 'text/html' }), 'integrity').level, 'warning');
  assert.equal(sec(run(png(), { contentType: 'image/png; charset=binary' }), 'integrity').level, 'clear');
});

test('decompression-bomb dimensions are flagged', () => {
  const r = run(png({ w: 50000, h: 50000 }));
  assert.equal(sec(r, 'integrity').level, 'warning');
});

test('SVG with scripts is flagged', () => {
  const r = run(enc('<svg xmlns="http://www.w3.org/2000/svg"><script>x()</script></svg>'), { url: 'https://x.test/a.svg' });
  assert.equal(sec(r, 'integrity').level, 'warning');
});

test('tracking pixel: 1x1 GIF with an identifier in the URL', () => {
  const url = 'https://mail.example.com/pixel.gif?uid=abcdefghijklmnopqrstuvwx';
  const findings = analyzeUrl(url, 'https://news.example.org/');
  assert.ok(findings.some((f) => f.skipFetch), 'must not be fetched');
  const r = analyzeImage({ url, bytes: trackingGif(), urlFindings: findings });
  assert.equal(sec(r, 'tracking').level, 'alert');
  assert.deepEqual(r.info.dims, { w: 1, h: 1 });
});

test('a bare 1x1 image on a clean URL is a warning, not an alert', () => {
  const r = analyzeImage({ url: 'https://cdn.example.com/spacer.gif', bytes: trackingGif() });
  assert.equal(sec(r, 'tracking').level, 'warning');
});

test('URL analysis: known trackers, emails, campaign params, clean CDN URLs', () => {
  assert.equal(analyzeUrl('https://www.facebook.com/tr?id=1&ev=PageView')[0].sev, 'alert');
  assert.equal(analyzeUrl('https://www.facebook.com/photo.jpg').filter((f) => f.sev === 'alert').length, 0);
  assert.ok(analyzeUrl('https://x.test/i.gif?e=bob%40example.com').some((f) => f.sev === 'alert' && f.skipFetch));
  assert.ok(analyzeUrl('https://x.test/a.jpg?utm_source=n&fbclid=1').some((f) => f.sev === 'notice'));
  const clean = analyzeUrl('https://images.example.com/a/b/photo.jpg?w=800&q=80&s=0123456789abcdef0123', 'https://example.com/');
  assert.equal(clean.filter((f) => f.sev !== 'info').length, 0, 'signed CDN URLs are not trackers');
});

test('URL analysis: data: and blob: URLs are handled without errors', () => {
  assert.equal(analyzeUrl('data:image/png;base64,AAAA')[0].sev, 'info');
  assert.equal(analyzeUrl('blob:https://x.test/uuid')[0].sev, 'info');
  assert.equal(analyzeUrl('not a url')[0].sev, 'info');
});

test('unreadable file: report still shaped correctly and honest', () => {
  const r = analyzeImage({ url: 'https://x.test/a.png', note: 'blocked' });
  assert.equal(r.summary.length, 4);
  assert.equal(sec(r, 'exposure').level, 'unknown');
  assert.equal(sec(r, 'authenticity').level, 'unknown');
});

test('fuzz: corrupted and truncated files never throw', () => {
  const t = tiff({ ifd0: [[0x010f, 2, 'ACME']], gps: [[1, 2, 'N'], [2, 5, [[1, 1], [2, 1], [3, 1]]]] });
  const seeds = [
    jpeg({ tiff: t, xmp: 'digitalsourcetype/trainedAlgorithmicMedia', c2pa: 'JP\0\0jumb c2pa', trailing: '<script>' }),
    png({ text: { parameters: 'Steps: 5, Sampler: x' }, extra: [['caBX', 'jumb c2pa']], trailing: 'junk' }),
    trackingGif(),
  ];
  let state = 12345;
  const rnd = () => (state = (state * 1103515245 + 12345) & 0x7fffffff) / 0x7fffffff;
  for (const seed of seeds) {
    for (let i = 0; i < 300; i++) {
      const copy = Uint8Array.from(seed);
      for (let k = 0; k < 1 + Math.floor(rnd() * 6); k++) copy[Math.floor(rnd() * copy.length)] = Math.floor(rnd() * 256);
      const bytes = rnd() < 0.4 ? copy.subarray(0, Math.floor(rnd() * copy.length)) : copy;
      const r = run(bytes);
      assert.equal(r.summary.length, 4);
    }
  }
  assert.equal(run(new Uint8Array(0)).summary.length, 4);
});

// ---- limits shown in the panel
import { limitsFor } from '../analyzer/report.js';
test('limits: tailored to the file, never claim more than was checked', () => {
  assert.match(limitsFor({ type: null }, null, null).join(' '), /not read/);
  const jpg = limitsFor({ type: 'jpeg' }, null, { findings: [] }).join(' ');
  assert.match(jpg, /does not mean an image is real/);
  assert.match(jpg, /pixels themselves/);
  assert.match(jpg, /No Content Credentials were found/);
  assert.match(jpg, /preview with the full image/);
  const heic = limitsFor({ type: 'heic' }, null, null).join(' ');
  assert.match(heic, /only be verified for JPEG, PNG and WebP/);
  assert.doesNotMatch(heic, /preview with the full image/);
  assert.match(limitsFor({ type: 'png' }, { found: true }, null).join(' '), /revocation/i);
});
