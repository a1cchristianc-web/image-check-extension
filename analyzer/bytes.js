// Small, bounds-checked helpers. All input is untrusted: readers throw RangeError
// instead of returning garbage, and parsers catch that and return partial results.
const latin1Decoder = new TextDecoder('latin1');
const utf8Decoder = new TextDecoder('utf-8');

export const latin1 = (u8, start = 0, end = u8.length) =>
  latin1Decoder.decode(u8.subarray(start, Math.min(end, u8.length)));

export const utf8Text = (u8, start = 0, end = u8.length) =>
  utf8Decoder.decode(u8.subarray(start, Math.min(end, u8.length)));

// Make embedded strings safe to display: strip control characters and cap length.
export const clean = (s, n = 120) =>
  String(s).replace(/[\u0000-\u001f\u007f]/g, ' ').trim().slice(0, n);

export function u16(u8, o, le = false) {
  if (o < 0 || o + 2 > u8.length) throw new RangeError('out of bounds');
  return le ? u8[o] | (u8[o + 1] << 8) : (u8[o] << 8) | u8[o + 1];
}

export function u32(u8, o, le = false) {
  if (o < 0 || o + 4 > u8.length) throw new RangeError('out of bounds');
  const v = le
    ? u8[o] | (u8[o + 1] << 8) | (u8[o + 2] << 16) | (u8[o + 3] << 24)
    : (u8[o] << 24) | (u8[o + 1] << 16) | (u8[o + 2] << 8) | u8[o + 3];
  return v >>> 0;
}

export const startsWith = (u8, sig, off = 0) => sig.every((b, i) => u8[off + i] === b);
