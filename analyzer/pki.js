// Signature verification (WebCrypto) + certificate chain / trust evaluation.
// Works in the extension service worker and in Node 20+ (both expose globalThis.crypto.subtle).
import { children, readTlv, intBytes, hex, bytesEqual, parseCertificate } from './der.js';

const CURVES = {
  '1.2.840.10045.3.1.7': ['P-256', 32],
  '1.3.132.0.34': ['P-384', 48],
  '1.3.132.0.35': ['P-521', 66],
};
const HASH_OIDS = {
  '2.16.840.1.101.3.4.2.1': 'SHA-256',
  '2.16.840.1.101.3.4.2.2': 'SHA-384',
  '2.16.840.1.101.3.4.2.3': 'SHA-512',
};
const CERT_SIG = {
  '1.2.840.10045.4.3.2': { kind: 'ecdsa', hash: 'SHA-256' },
  '1.2.840.10045.4.3.3': { kind: 'ecdsa', hash: 'SHA-384' },
  '1.2.840.10045.4.3.4': { kind: 'ecdsa', hash: 'SHA-512' },
  '1.2.840.113549.1.1.11': { kind: 'rsa', hash: 'SHA-256' },
  '1.2.840.113549.1.1.12': { kind: 'rsa', hash: 'SHA-384' },
  '1.2.840.113549.1.1.13': { kind: 'rsa', hash: 'SHA-512' },
  '1.2.840.113549.1.1.10': { kind: 'pss' },
  '1.3.101.112': { kind: 'ed25519' },
};
// emailProtection and documentSigning: the key purposes C2PA signing certificates carry.
// Key purposes that mark a certificate as allowed to sign content: emailProtection,
// documentSigning, Microsoft document signing, and the C2PA claim-signing purpose.
// (anyExtendedKeyUsage is deliberately NOT accepted.)
const SIGNING_EKUS = ['1.3.6.1.5.5.7.3.4', '1.3.6.1.5.5.7.3.36', '1.3.6.1.4.1.311.76.59.1.9', '1.3.6.1.4.1.62558.2.1'];
const KEY_OIDS = {
  ecdsa: ['1.2.840.10045.2.1'],
  rsa: ['1.2.840.113549.1.1.1', '1.2.840.113549.1.1.10'],
  pss: ['1.2.840.113549.1.1.1', '1.2.840.113549.1.1.10'],
  ed25519: ['1.3.101.112'],
};

const subtle = () => {
  const s = globalThis.crypto && globalThis.crypto.subtle;
  if (!s) throw new Error('WebCrypto is not available');
  return s;
};

// X.509 stores ECDSA signatures as DER SEQUENCE { r, s }; WebCrypto wants fixed-width r||s.
export function ecdsaDerToRaw(der, size) {
  const seq = readTlv(der, 0);
  const [r, s] = children(der, seq);
  const rb = intBytes(der, r);
  const sb = intBytes(der, s);
  if (rb.length > size || sb.length > size) throw new Error('ECDSA value too large');
  const out = new Uint8Array(size * 2);
  out.set(rb, size - rb.length);
  out.set(sb, size * 2 - sb.length);
  return out;
}

// scheme: { kind: 'ecdsa'|'rsa'|'pss'|'ed25519', hash?, salt? }; signature must already be raw for ECDSA.
export async function verifyWithSpki(spki, scheme, signature, data) {
  if (!KEY_OIDS[scheme.kind].includes(spki.algOid)) return false;
  const s = subtle();
  let alg;
  let verifyAlg;
  if (scheme.kind === 'ecdsa') {
    const curve = CURVES[spki.curveOid];
    if (!curve) throw new Error('unsupported elliptic curve');
    alg = { name: 'ECDSA', namedCurve: curve[0] };
    verifyAlg = { name: 'ECDSA', hash: scheme.hash };
  } else if (scheme.kind === 'rsa') {
    alg = { name: 'RSASSA-PKCS1-v1_5', hash: scheme.hash };
    verifyAlg = { name: 'RSASSA-PKCS1-v1_5' };
  } else if (scheme.kind === 'pss') {
    alg = { name: 'RSA-PSS', hash: scheme.hash };
    verifyAlg = { name: 'RSA-PSS', saltLength: scheme.salt };
  } else {
    alg = { name: 'Ed25519' };
    verifyAlg = { name: 'Ed25519' };
  }
  const key = await s.importKey('spki', spki.der, alg, false, ['verify']);
  return s.verify(verifyAlg, key, signature, data);
}

export function curveSize(spki) {
  const c = CURVES[spki.curveOid];
  return c ? c[1] : 0;
}

// Did `issuer` sign `cert`? (Signature check only; callers compare names and constraints.)
export async function verifyCertSignature(cert, issuer) {
  const info = CERT_SIG[cert.sigAlg.oid];
  if (!info) throw new Error(`unsupported certificate signature algorithm (${cert.sigAlg.oid})`);
  const scheme = { ...info };
  if (info.kind === 'pss') {
    scheme.hash = HASH_OIDS[cert.sigAlg.pss.hashOid];
    scheme.salt = cert.sigAlg.pss.saltLength;
    if (!scheme.hash) throw new Error('unsupported hash in certificate signature');
  }
  let sig = cert.signature;
  if (info.kind === 'ecdsa') {
    const size = curveSize(issuer.spki);
    if (!size) throw new Error('unsupported elliptic curve');
    sig = ecdsaDerToRaw(cert.signature, size);
  }
  return verifyWithSpki(issuer.spki, scheme, sig, cert.tbs);
}

// ---------------------------------------------------------------- trust anchors
export function buildAnchorIndex(derList) {
  const index = new Map();
  let count = 0;
  for (const der of derList) {
    try {
      const c = parseCertificate(der);
      const key = hex(c.subjectDer);
      if (!index.has(key)) index.set(key, []);
      index.get(key).push(c);
      count++;
    } catch { /* skip unparseable entries */ }
  }
  index.size_ = count;
  return count ? index : null;
}

// chain[0] is the leaf. Returns:
//   linksOk  - every certificate in the chain was signed by the next one
//   trusted  - true / false, or null when no trust list was supplied
//   problems - human-readable issues (expired, bad link, not a CA, ...)
export async function evaluateChain(chain, anchors, now) {
  // An invalid Date makes every "<" / ">" comparison false, which would silently disable expiry checks.
  if (!(now instanceof Date) || !Number.isFinite(+now)) throw new Error('invalid verification time');
  const r = { linksOk: true, trusted: anchors ? false : null, problems: [], expired: false, usageOk: true, anchorName: null };

  for (let i = 0; i < chain.length - 1; i++) {
    let ok = false;
    try {
      ok = bytesEqual(chain[i].issuerDer, chain[i + 1].subjectDer) && (await verifyCertSignature(chain[i], chain[i + 1]));
    } catch (e) {
      r.problems.push(`certificate #${i + 1}: ${e.message}`);
    }
    if (!ok) { r.linksOk = false; r.problems.push(`certificate #${i + 1} was not issued by the next certificate in the chain`); }
  }
  let caOk = true;
  for (let i = 1; i < chain.length; i++) {
    if (chain[i].ca !== true) { caOk = false; r.problems.push('an issuing certificate in the chain is not marked as a CA'); break; }
  }
  // Certificate-purpose rules. Any failure sets usageOk=false, which the caller treats as
  // "signature genuine but certificate problem": never "clear", and never "trusted" (see below).
  const policy = (msg) => { r.usageOk = false; r.problems.push(msg); };
  for (let i = 1; i < chain.length; i++) { // issuers: allowed to sign certificates, and pathLen respected
    const c = chain[i];
    if (c.keyUsage !== null && !(c.keyUsage & 0x04)) { policy('an issuing certificate is not allowed to sign certificates (key usage)'); break; }
    if (c.pathLen !== null && i - 1 > c.pathLen) { policy('the certificate chain is longer than an issuing certificate allows (path length)'); break; }
  }
  if (chain.some((c) => c.unknownCritical)) policy('a certificate has a critical extension this tool does not understand (RFC 5280 requires rejecting it)');
  const leaf = chain[0]; // the signer: must not be a CA, must be allowed to sign, must be marked for signing content
  if (leaf.ca === true) policy('the signing certificate is a CA certificate, which should not sign content');
  else if (leaf.keyUsage !== null && !(leaf.keyUsage & 0xc0)) policy('the signing certificate is not allowed to make digital signatures');
  if (!leaf.eku.some((o) => SIGNING_EKUS.includes(o))) policy('the signing certificate is not marked for signing content (missing key purpose)');

  for (const c of chain) {
    if (now < c.notBefore) { r.expired = true; r.problems.push('a certificate in the chain is not yet valid'); break; }
    if (now > c.notAfter) { r.expired = true; r.problems.push('a certificate in the chain has expired'); break; }
  }

  if (anchors && r.linksOk && caOk && r.usageOk) {
    outer:
    for (let j = 0; j < chain.length; j++) {
      for (const a of anchors.get(hex(chain[j].subjectDer)) || []) {
        if (bytesEqual(a.der, chain[j].der)) { r.trusted = true; r.anchorName = a.subject.cn || a.subject.o || null; break outer; }
      }
      for (const a of anchors.get(hex(chain[j].issuerDer)) || []) {
        if (a.ca !== true) continue;
        try {
          if (await verifyCertSignature(chain[j], a)) {
            r.trusted = true;
            r.anchorName = a.subject.cn || a.subject.o || null;
            if (now < a.notBefore || now > a.notAfter) { r.expired = true; r.problems.push('the trusted root certificate is outside its validity period'); }
            break outer;
          }
        } catch { /* try the next anchor */ }
      }
    }
  }
  return r;
}
