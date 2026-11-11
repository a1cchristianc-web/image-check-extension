// Synthetic image builders for tests (no real photos needed).
import { deflateSync } from 'node:zlib';

const CRC = (() => {
  const t = [];
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    t[n] = c >>> 0;
  }
  return t;
})();
export const crc32 = (buf) => {
  let c = 0xffffffff;
  for (const b of buf) c = CRC[(c ^ b) & 255] ^ (c >>> 8);
  return (c ^ 0xffffffff) >>> 0;
};

function chunk(type, data) {
  const len = Buffer.alloc(4);
  len.writeUInt32BE(data.length);
  const td = Buffer.concat([Buffer.from(type, 'latin1'), data]);
  const crc = Buffer.alloc(4);
  crc.writeUInt32BE(crc32(td));
  return Buffer.concat([len, td, crc]);
}

export function png({ w = 16, h = 16, text = {}, extra = [], trailing = null } = {}) {
  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(w, 0);
  ihdr.writeUInt32BE(h, 4);
  ihdr[8] = 8;
  ihdr[9] = 2;
  const rows = w <= 64 && h <= 64 ? Buffer.alloc(h * (1 + 3 * w)) : Buffer.alloc(4);
  const parts = [Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]), chunk('IHDR', ihdr)];
  for (const [k, v] of Object.entries(text)) {
    parts.push(chunk('tEXt', Buffer.concat([Buffer.from(k, 'latin1'), Buffer.from([0]), Buffer.from(v, 'latin1')])));
  }
  for (const [t, d] of extra) parts.push(chunk(t, Buffer.from(d, 'latin1')));
  parts.push(chunk('IDAT', deflateSync(rows)), chunk('IEND', Buffer.alloc(0)));
  if (trailing) parts.push(Buffer.from(trailing, 'latin1'));
  return new Uint8Array(Buffer.concat(parts));
}

const seg = (marker, payload) => {
  const head = Buffer.alloc(4);
  head[0] = 0xff;
  head[1] = marker;
  head.writeUInt16BE(payload.length + 2, 2);
  return Buffer.concat([head, payload]);
};

export function jpeg({ w = 16, h = 16, tiff = null, xmp = null, c2pa = null, trailing = null } = {}) {
  const parts = [Buffer.from([0xff, 0xd8])];
  if (tiff) parts.push(seg(0xe1, Buffer.concat([Buffer.from('Exif\0\0', 'latin1'), Buffer.from(tiff)])));
  if (xmp) parts.push(seg(0xe1, Buffer.concat([Buffer.from('http://ns.adobe.com/xap/1.0/\0', 'latin1'), Buffer.from(xmp, 'utf8')])));
  if (c2pa) parts.push(seg(0xeb, Buffer.from(c2pa, 'latin1')));
  parts.push(seg(0xc0, Buffer.from([8, h >> 8, h & 255, w >> 8, w & 255, 1, 1, 0x11, 0])));
  parts.push(seg(0xda, Buffer.from([1, 1, 0, 0, 0x3f, 0])), Buffer.from([0x12, 0x34]), Buffer.from([0xff, 0xd9]));
  if (trailing) parts.push(Buffer.from(trailing, 'latin1'));
  return new Uint8Array(Buffer.concat(parts));
}

// The well-known 43-byte transparent 1x1 GIF used by tracking pixels.
export const trackingGif = () =>
  new Uint8Array(Buffer.from('47494638396101000100800000000000ffffff21f90401000000002c00000000010001000002024401003b', 'hex'));

// Little-endian TIFF/EXIF builder. Entries are [tag, type, value]: type 2 = string,
// 5 = rationals as [[num, den], ...], 1/7 = byte array.
export function tiff({ ifd0 = [], exif = [], gps = [] }) {
  const sizeOf = (n) => 2 + 12 * n + 4;
  const n0 = ifd0.length + (exif.length ? 1 : 0) + (gps.length ? 1 : 0);
  const off0 = 8;
  const offExif = off0 + sizeOf(n0);
  const offGps = offExif + (exif.length ? sizeOf(exif.length) : 0);
  const dataStart = offGps + (gps.length ? sizeOf(gps.length) : 0);
  const data = [];
  const out = [];
  const w16 = (v) => out.push(v & 255, (v >> 8) & 255);
  const w32 = (v) => out.push(v & 255, (v >> 8) & 255, (v >> 16) & 255, (v >>> 24) & 255);

  const encode = (type, value) => {
    if (type === 2) { const b = [...Buffer.from(value + '\0', 'latin1')]; return { b, count: b.length }; }
    if (type === 5) {
      const b = [];
      for (const [n, d] of value) {
        b.push(n & 255, (n >> 8) & 255, (n >> 16) & 255, (n >>> 24) & 255, d & 255, (d >> 8) & 255, (d >> 16) & 255, (d >>> 24) & 255);
      }
      return { b, count: value.length };
    }
    if (type === 4) return { b: [value & 255, (value >> 8) & 255, (value >> 16) & 255, (value >>> 24) & 255], count: 1 };
    return { b: [...value], count: value.length };
  };
  const writeIfd = (entries) => {
    w16(entries.length);
    for (const [tag, type, value] of [...entries].sort((a, b) => a[0] - b[0])) {
      const { b, count } = encode(type, value);
      w16(tag); w16(type); w32(count);
      if (b.length <= 4) { out.push(...b); for (let i = b.length; i < 4; i++) out.push(0); }
      else {
        if (data.length % 2) data.push(0);
        w32(dataStart + data.length);
        data.push(...b);
      }
    }
    w32(0);
  };

  out.push(0x49, 0x49, 42, 0);
  w32(off0);
  const e0 = [...ifd0];
  if (exif.length) e0.push([0x8769, 4, offExif]);
  if (gps.length) e0.push([0x8825, 4, offGps]);
  writeIfd(e0);
  if (exif.length) writeIfd(exif);
  if (gps.length) writeIfd(gps);
  out.push(...data);
  return new Uint8Array(out);
}
