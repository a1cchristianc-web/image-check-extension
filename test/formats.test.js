// WebP (RIFF) and AVIF/HEIC (ISO-BMFF) metadata parsing, using synthetic files.
import test from 'node:test';
import assert from 'node:assert/strict';
import { parseWebpMeta, parseIsoMeta } from '../analyzer/meta.js';
import { analyzeImage } from '../analyzer/report.js';
import { tiff } from './fixtures.js';

const u32le = (n) => { const b = Buffer.alloc(4); b.writeUInt32LE(n); return b; };
const u32 = (n) => { const b = Buffer.alloc(4); b.writeUInt32BE(n); return b; };
const u16 = (n) => { const b = Buffer.alloc(2); b.writeUInt16BE(n); return b; };

function chunk(type, data) {
  const pad = data.length & 1 ? Buffer.from([0]) : Buffer.alloc(0);
  return Buffer.concat([Buffer.from(type, 'latin1'), u32le(data.length), data, pad]);
}
function webp(chunks) {
  const body = Buffer.concat([Buffer.from('WEBP'), ...chunks]);
  return new Uint8Array(Buffer.concat([Buffer.from('RIFF'), u32le(body.length), body]));
}
const exifTiff = () => Buffer.from(tiff({ ifd0: [[0x0131, 2, 'Adobe Photoshop 25.0'], [0x010f, 2, 'AcmeCam']] }));

test('WebP: EXIF, XMP and C2PA chunks are read (including odd-length padding)', () => {
  const r = parseWebpMeta(webp([
    chunk('VP8X', Buffer.alloc(10)),
    chunk('EXIF', exifTiff()),
    chunk('XMP ', Buffer.from('<x:xmpmeta>abc</x:xmpmeta>')), // odd length -> padded
    chunk('C2PA', Buffer.from('jumb-test')),
  ]));
  assert.equal(r.exif.Software, 'Adobe Photoshop 25.0');
  assert.equal(r.exif.Make, 'AcmeCam');
  assert.match(r.xmp, /xmpmeta/);
  assert.equal(r.c2pa, true);
});

test('WebP: a chunk that claims to be larger than the file does not throw or read out of bounds', () => {
  const evil = webp([Buffer.concat([Buffer.from('EXIF'), u32le(0x7fffffff), Buffer.from('short')])]);
  assert.doesNotThrow(() => parseWebpMeta(evil));
  assert.doesNotThrow(() => parseWebpMeta(new Uint8Array(Buffer.from('RIFF\0\0\0\0WEBP'))));
});

// --- minimal HEIC/AVIF: ftyp + meta{ iinf, iloc } + mdat holding the Exif / XMP items
function box(type, ...parts) {
  const payload = Buffer.concat(parts);
  return Buffer.concat([u32(8 + payload.length), Buffer.from(type, 'latin1'), payload]);
}
function iso({ exif = null, xmp = null, brand = 'heic', c2paUuid = false } = {}) {
  const items = [];
  if (exif) items.push({ id: 1, type: 'Exif', data: Buffer.concat([u32(0), exif]) });
  if (xmp) items.push({ id: 2, type: 'mime', mime: 'application/rdf+xml', data: Buffer.from(xmp) });
  const ftyp = box('ftyp', Buffer.from(brand), u32(0), Buffer.from(brand));
  const infe = (it) => box('infe', Buffer.from([2, 0, 0, 0]), u16(it.id), u16(0), Buffer.from(it.type),
    Buffer.from('item\0'), ...(it.mime ? [Buffer.from(it.mime + '\0')] : []));
  const iinf = box('iinf', Buffer.from([0, 0, 0, 0]), u16(items.length), ...items.map(infe));
  const mkIloc = (locs) => box('iloc', Buffer.from([0, 0, 0, 0]), Buffer.from([0x44, 0x00]), u16(items.length),
    ...items.map((it, i) => Buffer.concat([u16(it.id), u16(0), u16(1), u32(locs[i]), u32(it.data.length)])));
  const metaLen = 8 + 4 + iinf.length + mkIloc(items.map(() => 0)).length;
  let dataOff = ftyp.length + metaLen + 8; // mdat payload start
  const locs = items.map((it) => { const o = dataOff; dataOff += it.data.length; return o; });
  const iloc2 = mkIloc(locs);
  const meta = box('meta', Buffer.from([0, 0, 0, 0]), iinf, iloc2);
  const mdat = box('mdat', ...items.map((it) => it.data));
  const extra = c2paUuid ? [box('uuid', Buffer.from('d8fec3d61b0e483c92975828877ec481', 'hex'), Buffer.from('jumb'))] : [];
  return new Uint8Array(Buffer.concat([ftyp, meta, mdat, ...extra]));
}

test('HEIC/AVIF: Exif and XMP items are located through iinf/iloc', () => {
  for (const brand of ['heic', 'avif']) {
    const r = parseIsoMeta(iso({ exif: exifTiff(), xmp: '<x:xmpmeta>hi</x:xmpmeta>', brand }));
    assert.equal(r.exif.Software, 'Adobe Photoshop 25.0', brand);
    assert.match(r.xmp, /xmpmeta/, brand);
  }
});

test('HEIC/AVIF: a C2PA uuid box is detected as present', () => {
  assert.equal(parseIsoMeta(iso({ c2paUuid: true })).c2pa, true);
  assert.equal(parseIsoMeta(iso()).c2pa, false);
});

test('HEIC/AVIF: truncation and corruption never throw (fuzz)', () => {
  const good = iso({ exif: exifTiff(), xmp: '<x/>' });
  let seed = 12345;
  const rnd = () => (seed = (seed * 1103515245 + 12345) & 0x7fffffff) / 0x7fffffff;
  for (let i = 0; i < 400; i++) {
    const f = Uint8Array.from(good.subarray(0, Math.floor(rnd() * good.length) + 1));
    for (let k = 0; k < 4; k++) f[Math.floor(rnd() * f.length)] = Math.floor(rnd() * 256);
    assert.doesNotThrow(() => parseIsoMeta(f));
    assert.doesNotThrow(() => parseWebpMeta(f));
  }
});

test('report: WebP and HEIC files now get a metadata review instead of "not inspected"', () => {
  for (const [bytes, contentType] of [
    [webp([chunk('EXIF', exifTiff())]), 'image/webp'],
    [iso({ exif: exifTiff() }), 'image/heic'],
  ]) {
    const rep = JSON.stringify(analyzeImage({ url: 'https://example.com/a', bytes, contentType }));
    assert.doesNotMatch(rep, /not inspected for hidden data/);
  }
});
