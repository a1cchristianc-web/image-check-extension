// Minimal DER / X.509 reader (enough to verify C2PA signing certificates). Untrusted input:
// every read is bounds-checked and malformed data throws a plain Error that callers catch.
const latin1Dec = new TextDecoder('latin1');
const utf8Dec = new TextDecoder('utf-8');

export const hex = (u8) => Array.from(u8, (b) => b.toString(16).padStart(2, '0')).join('');
export const bytesEqual = (a, b) => a.length === b.length && a.every((x, i) => x === b[i]);

export function readTlv(u8, pos, limit = u8.length) {
  if (pos < 0 || pos + 2 > limit) throw new Error('DER truncated');
  const tag = u8[pos];
  let len = u8[pos + 1];
  let p = pos + 2;
  if (len & 0x80) {
    const n = len & 0x7f;
    if (n === 0 || n > 4 || p + n > limit) throw new Error('DER bad length');
    len = 0;
    for (let i = 0; i < n; i++) len = len * 256 + u8[p++];
  }
  if (p + len > limit) throw new Error('DER length exceeds data');
  return { tag, hdr: pos, start: p, end: p + len, len };
}

export function children(u8, tlv) {
  const out = [];
  let p = tlv.start;
  while (p < tlv.end) {
    if (out.length > 5000) throw new Error('DER too many items');
    const t = readTlv(u8, p, tlv.end);
    out.push(t);
    p = t.end;
  }
  return out;
}

export function oidOf(u8, tlv) {
  if (tlv.tag !== 0x06 || tlv.len === 0) throw new Error('DER expected OID');
  const b = u8.subarray(tlv.start, tlv.end);
  const parts = [Math.floor(b[0] / 40), b[0] % 40];
  let v = 0;
  for (let i = 1; i < b.length; i++) {
    v = v * 128 + (b[i] & 0x7f);
    if (!(b[i] & 0x80)) { parts.push(v); v = 0; }
  }
  return parts.join('.');
}

// INTEGER content without a leading sign-padding zero.
export function intBytes(u8, tlv) {
  let s = tlv.start;
  while (s < tlv.end - 1 && u8[s] === 0) s++;
  return u8.subarray(s, tlv.end);
}

function parseTime(u8, t) {
  const s = latin1Dec.decode(u8.subarray(t.start, t.end));
  let m;
  if (t.tag === 0x17 && (m = /^(\d\d)(\d\d)(\d\d)(\d\d)(\d\d)(\d\d)?Z$/.exec(s))) {
    const yy = +m[1];
    return new Date(Date.UTC(yy >= 50 ? 1900 + yy : 2000 + yy, +m[2] - 1, +m[3], +m[4], +m[5], +(m[6] || 0)));
  }
  if (t.tag === 0x18 && (m = /^(\d{4})(\d\d)(\d\d)(\d\d)(\d\d)(\d\d)Z$/.exec(s))) {
    return new Date(Date.UTC(+m[1], +m[2] - 1, +m[3], +m[4], +m[5], +m[6]));
  }
  throw new Error('DER bad time');
}

function decodeString(u8, t) {
  const b = u8.subarray(t.start, t.end);
  if (t.tag === 0x1e) return new TextDecoder('utf-16be').decode(b);
  if (t.tag === 0x0c) return utf8Dec.decode(b);
  return latin1Dec.decode(b);
}

// Extensions this parser understands or that do not restrict how a certificate may be used.
const HANDLED_EXT = new Set(['2.5.29.19', '2.5.29.15', '2.5.29.37', '2.5.29.14', '2.5.29.35', '2.5.29.17', '2.5.29.31', '1.3.6.1.5.5.7.1.1']);

function parseName(u8, tlv) {
  const out = {};
  for (const rdn of children(u8, tlv)) {
    for (const atv of children(u8, rdn)) {
      const [o, v] = children(u8, atv);
      if (!o || !v) continue;
      const oid = oidOf(u8, o);
      const text = decodeString(u8, v).replace(/[\u0000-\u001f]/g, ' ').slice(0, 120);
      if (oid === '2.5.4.3') out.cn = out.cn || text;
      else if (oid === '2.5.4.10') out.o = out.o || text;
      else if (oid === '2.5.4.6') out.c = out.c || text;
    }
  }
  return out;
}

function parseAlgId(u8, tlv) {
  const kids = children(u8, tlv);
  const oid = oidOf(u8, kids[0]);
  return { oid, params: kids[1] || null };
}

function parsePssParams(u8, params) {
  // RSASSA-PSS-params: hash [0], mgf [1], saltLength [2], trailer [3]; defaults sha1 / 20.
  const out = { hashOid: '1.3.14.3.2.26', saltLength: 20 };
  if (!params || params.tag !== 0x30) return out;
  for (const t of children(u8, params)) {
    if (t.tag === 0xa0) out.hashOid = parseAlgId(u8, children(u8, t)[0]).oid;
    else if (t.tag === 0xa2) {
      const ib = intBytes(u8, children(u8, t)[0]);
      out.saltLength = ib.reduce((a, b) => a * 256 + b, 0);
    }
  }
  return out;
}

export function parseCertificate(input) {
  const top = readTlv(input, 0);
  if (top.tag !== 0x30) throw new Error('not a certificate');
  const der = input.subarray(0, top.end);
  const [tbs, sigAlgTlv, sigBits] = children(der, top);
  if (!tbs || !sigAlgTlv || !sigBits || sigBits.tag !== 0x03) throw new Error('bad certificate');
  const t = children(der, tbs);
  let i = 0;
  if (t[i].tag === 0xa0) i++;
  i++; // serial
  i++; // tbs signature algorithm
  const issuer = t[i++];
  const validity = t[i++];
  const subject = t[i++];
  const spkiTlv = t[i++];
  const extTlv = t.slice(i).find((x) => x.tag === 0xa3);

  const [nb, na] = children(der, validity);
  const spkiKids = children(der, spkiTlv);
  const spkiAlg = parseAlgId(der, spkiKids[0]);
  const spki = {
    der: der.subarray(spkiTlv.hdr, spkiTlv.end),
    algOid: spkiAlg.oid,
    curveOid: spkiAlg.params && spkiAlg.params.tag === 0x06 ? oidOf(der, spkiAlg.params) : null,
    bits: 0,
  };
  if (spki.algOid === '1.2.840.113549.1.1.1' || spki.algOid === '1.2.840.113549.1.1.10') {
    try {
      const rsa = readTlv(der, spkiKids[1].start + 1, spkiKids[1].end);
      const n = intBytes(der, children(der, rsa)[0]);
      spki.bits = n.length * 8 - (n.length ? Math.clz32(n[0]) - 24 : 0);
    } catch { /* leave 0 */ }
  }

  const sigAlg = parseAlgId(der, sigAlgTlv);
  const cert = {
    der,
    tbs: der.subarray(tbs.hdr, tbs.end),
    sigAlg: { oid: sigAlg.oid, pss: sigAlg.oid === '1.2.840.113549.1.1.10' ? parsePssParams(der, sigAlg.params) : null },
    signature: der.subarray(sigBits.start + 1, sigBits.end),
    issuerDer: der.subarray(issuer.hdr, issuer.end),
    subjectDer: der.subarray(subject.hdr, subject.end),
    issuer: parseName(der, issuer),
    subject: parseName(der, subject),
    notBefore: parseTime(der, nb),
    notAfter: parseTime(der, na),
    spki,
    ca: null,
    pathLen: null,
    keyUsage: null,
    eku: [],
    unknownCritical: false,
  };

  if (extTlv) {
    const exts = children(der, children(der, extTlv)[0]);
    for (const e of exts) {
      const parts = children(der, e);
      const oid = oidOf(der, parts[0]);
      const octet = parts[parts.length - 1];
      const crit = parts.length >= 3 && parts[1].tag === 0x01 && der[parts[1].start] !== 0;
      if (crit && !HANDLED_EXT.has(oid)) cert.unknownCritical = true;
      if (octet.tag !== 0x04) continue;
      const inner = readTlv(der, octet.start, octet.end);
      if (oid === '2.5.29.19') { // basicConstraints
        const kids = children(der, inner);
        cert.ca = kids.length > 0 && kids[0].tag === 0x01 ? der[kids[0].start] !== 0 : false;
        const pl = kids.find((k) => k.tag === 0x02);
        cert.pathLen = pl ? intBytes(der, pl).reduce((a, b) => a * 256 + b, 0) : null;
      } else if (oid === '2.5.29.15' && inner.tag === 0x03) { // keyUsage
        cert.keyUsage = der[inner.start + 1] || 0;
      } else if (oid === '2.5.29.37') { // extKeyUsage
        cert.eku = children(der, inner).map((o) => oidOf(der, o));
      }
    }
  }
  return cert;
}

export function pemToDers(text) {
  const out = [];
  const re = /-----BEGIN CERTIFICATE-----([\s\S]*?)-----END CERTIFICATE-----/g;
  let m;
  while ((m = re.exec(text))) {
    try {
      const bin = atob(m[1].replace(/\s+/g, ''));
      out.push(Uint8Array.from(bin, (c) => c.charCodeAt(0)));
    } catch { /* skip bad block */ }
  }
  return out;
}
