// Minimal CBOR (RFC 8949) decoder + encoder. Input is untrusted: strict bounds, depth and item
// limits. Maps decode to JS Map (keys may be numbers or strings), byte strings to Uint8Array
// views, tags to { isTag: true, tag, value }.
const utf8 = new TextDecoder('utf-8');
const LIMIT_DEPTH = 32;
const LIMIT_ITEMS = 200000;

export class CborError extends Error {}

const concat = (parts) => {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let o = 0;
  for (const p of parts) { out.set(p, o); o += p.length; }
  return out;
};

export function decodeCbor(u8, pos = 0, end = u8.length) {
  let items = 0;
  const need = (n, p) => { if (n < 0 || p + n > end) throw new CborError('truncated CBOR'); };

  function item(p, depth) {
    if (depth > LIMIT_DEPTH) throw new CborError('CBOR nested too deeply');
    if (++items > LIMIT_ITEMS) throw new CborError('CBOR too large');
    need(1, p);
    const ib = u8[p++];
    const major = ib >> 5;
    const ai = ib & 31;

    if (major === 7) {
      if (ai === 20) return [false, p];
      if (ai === 21) return [true, p];
      if (ai === 22) return [null, p];
      if (ai === 23) return [undefined, p];
      const dv = (n) => { need(n, p); return new DataView(u8.buffer, u8.byteOffset + p, n); };
      if (ai === 25) {
        const h = dv(2).getUint16(0);
        const e = (h >> 10) & 31;
        const f = h & 1023;
        const v = e === 0 ? f * 2 ** -24 : e === 31 ? (f ? NaN : Infinity) : (1 + f / 1024) * 2 ** (e - 15);
        return [h & 0x8000 ? -v : v, p + 2];
      }
      if (ai === 26) return [dv(4).getFloat32(0), p + 4];
      if (ai === 27) return [dv(8).getFloat64(0), p + 8];
      throw new CborError('unsupported CBOR simple value');
    }

    let n = 0;
    let indefinite = false;
    if (ai < 24) n = ai;
    else if (ai === 24) { need(1, p); n = u8[p]; p += 1; }
    else if (ai === 25) { need(2, p); n = (u8[p] << 8) | u8[p + 1]; p += 2; }
    else if (ai === 26) { need(4, p); n = u8[p] * 2 ** 24 + (u8[p + 1] << 16) + (u8[p + 2] << 8) + u8[p + 3]; p += 4; }
    else if (ai === 27) {
      need(8, p);
      const hi = u8[p] * 2 ** 24 + (u8[p + 1] << 16) + (u8[p + 2] << 8) + u8[p + 3];
      const lo = u8[p + 4] * 2 ** 24 + (u8[p + 5] << 16) + (u8[p + 6] << 8) + u8[p + 7];
      if (hi > 0x1fffff) throw new CborError('integer too large');
      n = hi * 2 ** 32 + lo;
      p += 8;
    } else if (ai === 31) indefinite = true;
    else throw new CborError('invalid CBOR header');

    switch (major) {
      case 0:
        if (indefinite) throw new CborError('invalid CBOR header');
        return [n, p];
      case 1:
        if (indefinite) throw new CborError('invalid CBOR header');
        return [-1 - n, p];
      case 2:
      case 3: {
        if (!indefinite) {
          need(n, p);
          const b = u8.subarray(p, p + n);
          return [major === 2 ? b : utf8.decode(b), p + n];
        }
        const parts = [];
        for (;;) {
          need(1, p);
          if (u8[p] === 0xff) { p++; break; }
          const [c, np] = item(p, depth + 1);
          if (major === 2 ? !(c instanceof Uint8Array) : typeof c !== 'string') throw new CborError('bad chunk');
          parts.push(c);
          p = np;
        }
        return [major === 2 ? concat(parts) : parts.join(''), p];
      }
      case 4: {
        const arr = [];
        if (indefinite) {
          for (;;) {
            need(1, p);
            if (u8[p] === 0xff) { p++; break; }
            const [v, np] = item(p, depth + 1);
            arr.push(v);
            p = np;
          }
        } else {
          need(n, p); // every element needs at least one byte
          for (let i = 0; i < n; i++) { const [v, np] = item(p, depth + 1); arr.push(v); p = np; }
        }
        return [arr, p];
      }
      case 5: {
        const map = new Map();
        const read = () => {
          const [k, p1] = item(p, depth + 1);
          const [v, p2] = item(p1, depth + 1);
          map.set(k, v);
          p = p2;
        };
        if (indefinite) {
          for (;;) { need(1, p); if (u8[p] === 0xff) { p++; break; } read(); }
        } else {
          need(n * 2, p);
          for (let i = 0; i < n; i++) read();
        }
        return [map, p];
      }
      default: { // 6: tag
        const [v, np] = item(p, depth + 1);
        return [{ isTag: true, tag: n, value: v }, np];
      }
    }
  }

  const [value, next] = item(pos, 0);
  return { value, end: next };
}

// ---------------------------------------------------------------- encoder
function head(major, n) {
  if (n < 24) return [(major << 5) | n];
  if (n < 256) return [(major << 5) | 24, n];
  if (n < 65536) return [(major << 5) | 25, n >> 8, n & 255];
  if (n < 2 ** 32) return [(major << 5) | 26, (n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255];
  const big = BigInt(n);
  const out = [(major << 5) | 27];
  for (let i = 7; i >= 0; i--) out.push(Number((big >> BigInt(i * 8)) & 0xffn));
  return out;
}

export function encodeCbor(v) {
  const out = [];
  const push = (b) => { for (const x of b) out.push(x); };
  (function enc(x) {
    if (x === null) out.push(0xf6);
    else if (x === undefined) out.push(0xf7);
    else if (x === true) out.push(0xf5);
    else if (x === false) out.push(0xf4);
    else if (typeof x === 'number') {
      if (Number.isInteger(x)) push(x >= 0 ? head(0, x) : head(1, -1 - x));
      else { out.push(0xfb); const b = new Uint8Array(8); new DataView(b.buffer).setFloat64(0, x); push(b); }
    } else if (typeof x === 'string') { const b = new TextEncoder().encode(x); push(head(3, b.length)); push(b); }
    else if (x instanceof Uint8Array) { push(head(2, x.length)); push(x); }
    else if (Array.isArray(x)) { push(head(4, x.length)); x.forEach(enc); }
    else if (x instanceof Map) { push(head(5, x.size)); for (const [k, val] of x) { enc(k); enc(val); } }
    else if (x && x.isTag) { push(head(6, x.tag)); enc(x.value); }
    else if (typeof x === 'object') {
      const keys = Object.keys(x);
      push(head(5, keys.length));
      for (const k of keys) { enc(k); enc(x[k]); }
    } else throw new CborError('cannot encode value');
  })(v);
  return Uint8Array.from(out);
}
