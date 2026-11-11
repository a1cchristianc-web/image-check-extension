// C2PA Content Credentials verifier (JPEG + PNG).
//
// What is checked, in order:
//   1. the manifest store is found and parsed (JPEG APP11 segments / PNG caBX chunk)
//   2. the claim's signature (COSE_Sign1) verifies against the signing certificate's key
//   3. every assertion hash listed in the claim matches the assertion bytes
//   4. the hard-binding hash (c2pa.hash.data) matches the actual image bytes, and the ranges it
//      excludes from hashing are ONLY the manifest itself (otherwise the binding is meaningless)
//   5. the certificate chain links up, is in date, and (if a trust list is supplied) ends at a
//      trusted anchor
// NOT checked: revocation (needs network), RFC 3161 timestamps, ingredient manifests' own
// signatures, c2pa.hash.boxes / BMFF bindings (other formats).
import { latin1, u16, u32 } from './bytes.js';
import { decodeCbor, encodeCbor } from './cbor.js';
import { parseCertificate, bytesEqual } from './der.js';
import { readBox, readBoxes, parseSuper } from './jumbf.js';
import { verifyWithSpki, evaluateChain, buildAnchorIndex } from './pki.js';

const MAX_STORE = 10 * 1024 * 1024;
const HASHES = { sha256: 'SHA-256', sha384: 'SHA-384', sha512: 'SHA-512' };
const COSE_ALGS = {
  '-7': { kind: 'ecdsa', hash: 'SHA-256', name: 'ES256' },
  '-35': { kind: 'ecdsa', hash: 'SHA-384', name: 'ES384' },
  '-36': { kind: 'ecdsa', hash: 'SHA-512', name: 'ES512' },
  '-37': { kind: 'pss', hash: 'SHA-256', salt: 32, name: 'PS256' },
  '-38': { kind: 'pss', hash: 'SHA-384', salt: 48, name: 'PS384' },
  '-39': { kind: 'pss', hash: 'SHA-512', salt: 64, name: 'PS512' },
  '-8': { kind: 'ed25519', name: 'EdDSA' },
};
const AI_SOURCE = /(trainedalgorithmicmedia|algorithmicmedia|compositesynthetic)/i;
// Text copied out of the file for display: control, zero-width and bidi-override characters
// are replaced so file content cannot reorder or hide the words around it.
// Strips control, format (incl. bidi, zero-width, soft hyphen, tag), line/paragraph separators and invisible filler characters.
const textOf = (v, n = 80) => String(v == null ? '' : v).replace(/[\p{Cc}\p{Cf}\p{Zl}\p{Zp}\u115f\u1160\u3164\uffa0\u180e]/gu, ' ').trim().slice(0, n);
const mapGet = (m, k) => (m instanceof Map ? m.get(k) : undefined);

class Unverifiable extends Error {}

// ---------------------------------------------------------------- locating the manifest store
function isManifestStore(u8) {
  try {
    const box = readBox(u8, 0);
    if (box.type !== 'jumb') return false;
    return parseSuper(u8, box).label === 'c2pa';
  } catch {
    return false;
  }
}

function jpegStores(u8) {
  const segs = [];
  let i = 2;
  while (i + 4 <= u8.length) {
    if (u8[i] !== 0xff) break;
    const m = u8[i + 1];
    if (m === 0xff) { i++; continue; }
    if (m === 0xd8 || m === 0x01 || (m >= 0xd0 && m <= 0xd7)) { i += 2; continue; }
    if (m === 0xd9 || m === 0xda) break;
    const len = u16(u8, i + 2);
    if (len < 2 || i + 2 + len > u8.length) break;
    const end = i + 2 + len;
    if (m === 0xeb && len >= 18 && u8[i + 4] === 0x4a && u8[i + 5] === 0x50) {
      const p = i + 4;
      const lbox = u32(u8, p + 8);
      const hdrLen = lbox === 1 ? 16 : 8;
      if (len - 2 >= 8 + hdrLen) {
        segs.push({
          start: i, end, en: u16(u8, p + 2), z: u32(u8, p + 4), lbox,
          tbox: latin1(u8, p + 12, p + 16), header: u8.subarray(p + 8, p + 8 + hdrLen),
          data: u8.subarray(p + 8 + hdrLen, end),
        });
      }
    }
    i = end;
  }

  const byEn = new Map();
  for (const s of segs) {
    if (!byEn.has(s.en)) byEn.set(s.en, []);
    byEn.get(s.en).push(s);
  }
  const stores = [];
  let candidates = 0;
  for (const fam of byEn.values()) {
    if (fam[0].tbox !== 'jumb') continue;
    candidates++;
    let ok = fam[0].z === 1;
    for (let k = 1; ok && k < fam.length; k++) {
      ok = fam[k].z === fam[k - 1].z + 1 && fam[k].start === fam[k - 1].end && bytesEqual(fam[k].header, fam[0].header);
    }
    if (!ok) continue;
    const parts = [fam[0].header, ...fam.map((s) => s.data)];
    const total = parts.reduce((n, p) => n + p.length, 0);
    if (total > MAX_STORE) continue;
    const data = new Uint8Array(total);
    let o = 0;
    for (const p of parts) { data.set(p, o); o += p.length; }
    const declared = fam[0].lbox === 1 ? u32(fam[0].header, 12) : fam[0].lbox;
    if (declared !== total || !isManifestStore(data)) continue;
    stores.push({ data, spans: [{ start: fam[0].start, end: fam[fam.length - 1].end }] });
  }
  return { stores, candidates };
}

function pngStores(u8) {
  const stores = [];
  let candidates = 0;
  let pos = 8;
  let n = 0;
  for (; pos + 12 <= u8.length && n < 20000; n++) {
    const len = u32(u8, pos);
    const type = latin1(u8, pos + 4, pos + 8);
    if (pos + 12 + len > u8.length) break;
    if (type === 'caBX') {
      candidates++;
      const data = u8.subarray(pos + 8, pos + 8 + len);
      if (len <= MAX_STORE && isManifestStore(data)) stores.push({ data, spans: [{ start: pos, end: pos + 12 + len }] });
    }
    if (type === 'IEND') break;
    pos += 12 + len;
  }
  // Gave up scanning (absurd chunk count) before reaching the end: the caller must say "not scanned",
  // which is different from (and must not look like) "this file has no credentials".
  return { stores, candidates, limited: n >= 20000 && !stores.length };
}

// WebP is a RIFF container; the credentials live in a 'C2PA' chunk. A chunk's span includes its 8-byte
// header and its padding byte (chunks are padded to even length).
function webpStores(u8) {
  const stores = [];
  let candidates = 0;
  const end = Math.min(u8.length, 8 + u32(u8, 4, true));
  let pos = 12;
  let n = 0;
  for (; pos + 8 <= end && n < 20000; n++) {
    const type = latin1(u8, pos, pos + 4);
    const len = u32(u8, pos + 4, true);
    const stop = pos + 8 + len + (len & 1);
    if (pos + 8 + len > end) break;
    if (type === 'C2PA') {
      candidates++;
      const data = u8.subarray(pos + 8, pos + 8 + len);
      if (len <= MAX_STORE && isManifestStore(data)) stores.push({ data, spans: [{ start: pos, end: Math.min(stop, u8.length) }] });
    }
    pos = stop;
  }
  return { stores, candidates, limited: n >= 20000 && !stores.length };
}

export function locateStores(u8) {
  if (u8.length > 16 && latin1(u8, 0, 4) === 'RIFF' && latin1(u8, 8, 12) === 'WEBP') return { format: 'webp', ...webpStores(u8) };
  if (u8.length > 12 && u8[0] === 0xff && u8[1] === 0xd8 && u8[2] === 0xff) return { format: 'jpeg', ...jpegStores(u8) };
  if (u8.length > 12 && u8[0] === 0x89 && latin1(u8, 1, 4) === 'PNG') return { format: 'png', ...pngStores(u8) };
  return { format: null, stores: [], candidates: 0 };
}

// ---------------------------------------------------------------- manifest structure
function loadManifest(data, box) {
  const sup = parseSuper(data, box);
  const byLabel = new Map();
  let dup = false;
  for (const child of sup.children) {
    if (child.type !== 'jumb') continue;
    const s = parseSuper(data, child);
    if (byLabel.has(s.label)) dup = true;
    else byLabel.set(s.label, s);
  }
  return { label: sup.label, byLabel, dup };
}

// Bytes of the CBOR/JSON content box inside a superbox, or null.
function contentBox(data, sup) {
  return sup.children.find((c) => c.type === 'cbor' || c.type === 'json') || null;
}

function decodeContent(data, sup) {
  const c = contentBox(data, sup);
  if (!c) return null;
  const bytes = data.subarray(c.payload, c.end);
  if (c.type === 'cbor') return decodeCbor(bytes).value;
  return JSON.parse(new TextDecoder().decode(bytes));
}

function assertionsOf(data, man) {
  const store = man.byLabel.get('c2pa.assertions');
  const out = new Map();
  if (!store) return out;
  for (const child of store.children) {
    if (child.type !== 'jumb') continue;
    const s = parseSuper(data, child);
    if (out.has(s.label)) out.dup = true;
    else out.set(s.label, { sup: s, region: data.subarray(child.payload, child.end) });
  }
  return out;
}

function hashedUris(claim) {
  const out = [];
  for (const key of ['assertions', 'created_assertions', 'gathered_assertions']) {
    const arr = mapGet(claim, key);
    if (Array.isArray(arr)) for (const it of arr) if (it instanceof Map) out.push(it);
  }
  return out;
}

const MAX_REFS = 256; // a claim lists a handful of assertions; more is hostile (CPU amplification)

// Accepts the relative form (c2pa.assertions/<label>) and the absolute forms (with or without a
// leading slash) that name THIS manifest. Anything else returns null, and the caller treats an
// unresolvable reference as "cannot fully verify", never as "nothing to check".
function labelFromUrl(url, manifestLabel) {
  const str = String(url);
  if (str.length > 512) return null; // real references are short; also keeps parsing cost bounded
  const m = /^self#jumbf=(.+)$/.exec(str);
  if (!m) return null;
  let body = m[1];
  while (body.endsWith('/')) body = body.slice(0, -1);
  let parts = body.split('/');
  if (parts[0] === '') parts = parts.slice(1);
  if (parts[0] === 'c2pa') {
    if (parts[1] !== manifestLabel) return null;
    parts = parts.slice(2);
  }
  return parts.length === 2 && parts[0] === 'c2pa.assertions' && parts[1] ? parts[1] : null;
}

async function digest(alg, data) {
  return new Uint8Array(await globalThis.crypto.subtle.digest(alg, data));
}

// ---------------------------------------------------------------- hard binding
function checkExclusions(excl, spans, fileLen) {
  if (!Array.isArray(excl)) throw new Error('exclusions missing');
  const list = [];
  for (const e of excl) {
    const start = mapGet(e, 'start');
    const length = mapGet(e, 'length');
    if (!Number.isSafeInteger(start) || !Number.isSafeInteger(length) || start < 0 || length < 0) throw new Error('bad exclusion');
    list.push({ start, end: start + length });
  }
  list.sort((a, b) => a.start - b.start);
  let prev = 0;
  for (const e of list) {
    if (e.start < prev) throw new Error('overlapping exclusions');
    if (e.end > fileLen) throw new Error('exclusion beyond end of file');
    prev = e.end;
  }
  const offending = list.filter((e) => e.end > e.start && !spans.some((s) => e.start >= s.start && e.end <= s.end));
  // The excluded bytes must be EXACTLY the credentials block. If the block in the file is larger than
  // the signed exclusion, its length fields (which are unhashed) were changed after signing, and a
  // decoder could be steered to skip over image data that the hash still covers.
  const merged = [];
  for (const e of list) {
    if (e.end === e.start) continue;
    const last = merged[merged.length - 1];
    if (last && e.start === last.end) last.end = e.end;
    else merged.push({ start: e.start, end: e.end });
  }
  const want = [...spans].sort((a, b) => a.start - b.start);
  const exact = merged.length === want.length && merged.every((m, i) => m.start === want[i].start && m.end === want[i].end);
  return { list, offending, exact };
}

async function hashWithExclusions(bytes, list, alg) {
  const parts = [];
  let pos = 0;
  for (const e of list) {
    if (e.start > pos) parts.push(bytes.subarray(pos, e.start));
    pos = Math.max(pos, e.end);
  }
  if (pos < bytes.length) parts.push(bytes.subarray(pos));
  const total = parts.reduce((n, p) => n + p.length, 0);
  const buf = new Uint8Array(total);
  let o = 0;
  for (const p of parts) { buf.set(p, o); o += p.length; }
  return digest(alg, buf);
}

// ---------------------------------------------------------------- signature
function coseChain(prot, unprot) {
  const raw = (prot && prot.get(33)) || (unprot && unprot.get(33));
  const arr = raw instanceof Uint8Array ? [raw] : Array.isArray(raw) ? raw : [];
  return arr.filter((x) => x instanceof Uint8Array);
}

async function verifySignature(claimBytes, sigValue) {
  const cose = sigValue && sigValue.isTag ? sigValue.value : sigValue;
  if (!Array.isArray(cose) || cose.length !== 4) throw new Unverifiable('signature is not a COSE_Sign1 structure');
  const [protectedBytes, unprot, payload, signature] = cose;
  if (!(protectedBytes instanceof Uint8Array) || !(signature instanceof Uint8Array)) throw new Unverifiable('malformed COSE signature');
  const prot = protectedBytes.length ? decodeCbor(protectedBytes).value : new Map();
  const algId = mapGet(prot, 1);
  const alg = typeof algId === 'number' && Object.hasOwn(COSE_ALGS, String(algId)) ? COSE_ALGS[String(algId)] : undefined;
  if (!alg) throw new Unverifiable(`the signature algorithm (${textOf(mapGet(prot, 1))}) is not supported by this tool`);
  const ders = coseChain(prot, unprot);
  if (!ders.length) throw new Unverifiable('no signing certificate in the signature');
  if (ders.length > 10) throw new Unverifiable('the certificate chain is unreasonably long');
  const chain = ders.map((d) => parseCertificate(d));
  const leaf = chain[0];

  if (payload instanceof Uint8Array && !bytesEqual(payload, claimBytes)) return { valid: false, alg, chain, unprot };
  if (leaf.spki.bits && leaf.spki.bits < 2048) throw new Unverifiable('the signing key is an RSA key shorter than 2048 bits');

  const sigStructure = encodeCbor(['Signature1', protectedBytes, new Uint8Array(0), claimBytes]);
  let valid = false;
  try {
    valid = await verifyWithSpki(leaf.spki, alg, signature, sigStructure);
  } catch (e) {
    throw new Unverifiable(`could not use the signing key (${e.message})`);
  }
  return { valid, alg, chain, unprot };
}

// ---------------------------------------------------------------- main entry
// opts: { anchors: DER certificate list (or a prebuilt index) | null, now: Date }
// Never throws: any unexpected failure is reported as status 'error'.
export async function verifyC2pa(bytes, opts = {}) {
  try {
    return await verifyInner(bytes, opts);
  } catch {
    return {
      found: true, status: 'error', trust: 'unchecked', ai: false, actions: [],
      findings: [{ sev: 'notice', text: 'The Content Credentials could not be verified because of an unexpected problem with the data.' }],
      level: 'notice', headline: 'Content Credentials present but could not be verified',
    };
  }
}

async function verifyInner(bytes, opts) {
  const now = opts.now === undefined ? new Date() : opts.now;
  // An invalid Date would make every expiry comparison false (checks silently disabled): fail closed.
  if (!(now instanceof Date) || !Number.isFinite(+now)) throw new Error('invalid verification time');
  const anchors = Array.isArray(opts.anchors) ? buildAnchorIndex(opts.anchors) : opts.anchors || null;
  let loc;
  try { loc = locateStores(bytes); } catch { return { found: true, status: 'error', format: null, findings: [{ sev: 'notice', text: 'Content Credentials seem to be present but could not be read.' }], level: 'notice', headline: 'Content Credentials present but could not be read', ai: false }; }
  if (!loc.format) return { found: false };
  if (loc.limited && !loc.candidates) {
    return {
      found: true, status: 'error', format: loc.format, trust: 'unchecked', ai: false, actions: [],
      findings: [{ sev: 'notice', text: 'This file has too many parts to scan for Content Credentials, so none were checked. That says nothing about whether it has any.' }],
      level: 'notice', headline: 'Content Credentials could not be checked (file too complex)',
    };
  }
  if (!loc.stores.length && !loc.candidates) return { found: false };

  const R = { found: true, format: loc.format, status: 'error', trust: 'unchecked', findings: [], ai: false, signer: null, generator: null, title: null, actions: [], ingredients: 0 };
  const F = (sev, text) => R.findings.push({ sev, text });
  const finish = (level, headline) => { R.level = level; R.headline = headline; return R; };

  if (!loc.stores.length) {
    F('notice', 'A Content Credentials block is present but is malformed or incomplete, so it could not be verified.');
    return finish('notice', 'Content Credentials present but could not be read');
  }
  if (loc.stores.length > 1) {
    F('warning', 'The file contains more than one Content Credentials block, which is not valid.');
    return finish('warning', 'Content Credentials are malformed (multiple blocks)');
  }

  const store = loc.stores[0];
  const invalid = []; // things that prove the file or credentials were altered
  const unsupported = []; // things this tool cannot check (so the result can never be "valid")
  const bindIssues = []; // the link to the pixels could not be confirmed (not proof of tampering)
  // Hash algorithm names come from the file: look them up only as own properties, never fall back
  // silently, and remember anything unknown.
  const pickAlg = (v, fallback) => {
    if (v === undefined || v === null || v === '') return fallback;
    const k = String(v).toLowerCase();
    if (Object.hasOwn(HASHES, k)) return HASHES[k];
    unsupported.push(`hash algorithm "${textOf(v, 20)}"`);
    return null;
  };
  let manifest;
  let manifestCount = 0;
  try {
    const kids = readBoxes(store.data, 0, store.data.length)[0];
    const top = parseSuper(store.data, kids);
    const mans = top.children.filter((c) => c.type === 'jumb');
    manifestCount = mans.length;
    if (!mans.length) throw new Error('no manifest');
    manifest = loadManifest(store.data, mans[mans.length - 1]);
  } catch {
    F('notice', 'The Content Credentials block could not be parsed, so it could not be verified.');
    return finish('notice', 'Content Credentials present but could not be read');
  }
  R.ingredients = Math.max(0, manifestCount - 1);

  const data = store.data;
  let claim;
  let claimBytes;
  try {
    const claimSup = manifest.byLabel.get('c2pa.claim.v2') || manifest.byLabel.get('c2pa.claim');
    const box = claimSup && contentBox(data, claimSup);
    if (!box) throw new Error('no claim');
    claimBytes = data.subarray(box.payload, box.end);
    claim = decodeCbor(claimBytes).value;
    if (!(claim instanceof Map)) throw new Error('bad claim');
  } catch {
    F('notice', 'The credentials have no readable claim, so they could not be verified.');
    return finish('notice', 'Content Credentials present but could not be read');
  }

  const info = mapGet(claim, 'claim_generator_info');
  const gi = Array.isArray(info) ? info[0] : info;
  const genName = textOf(mapGet(gi, 'name') || mapGet(claim, 'claim_generator'), 60);
  const genVersion = textOf(mapGet(gi, 'version'), 20);
  R.generator = (genName && genVersion ? `${genName} ${genVersion}` : genName) || null;
  R.title = textOf(mapGet(claim, 'dc:title'), 80) || null;

  // ---- signature
  let sig;
  try {
    const sigSup = manifest.byLabel.get('c2pa.signature');
    sig = await verifySignature(claimBytes, sigSup && decodeContent(data, sigSup));
  } catch (e) {
    F('notice', `The signature could not be checked: ${textOf(e.message, 120)}.`);
    return finish('notice', 'Content Credentials present but could not be verified');
  }
  const leaf = sig.chain[0];
  R.signer = textOf(leaf.subject.cn || leaf.subject.o || 'unknown signer', 80) || 'unknown signer';
  R.signatureValid = sig.valid;
  R.bindingValid = false;
  if (!sig.valid) invalid.push('The signature does not match the credentials: they were altered after signing, or the signature is forged.');

  // ---- assertion hashes
  const assertions = assertionsOf(data, manifest);
  const claimAlg = pickAlg(mapGet(claim, 'alg'), 'SHA-256') || 'SHA-256';
  const verified = new Set();
  const referenced = new Set();
  const unresolved = [];
  const refs = hashedUris(claim);
  if (refs.length > MAX_REFS) {
    F('warning', 'The credentials list an unreasonable number of assertions, so they were not verified.');
    return finish('warning', 'Content Credentials could not be fully verified');
  }
  const digests = new Map(); // (label, alg) -> digest, so repeated references cost one hash
  for (const item of refs) {
    const label = labelFromUrl(mapGet(item, 'url'), manifest.label);
    if (!label) { unresolved.push(textOf(mapGet(item, 'url'), 50)); continue; }
    referenced.add(label);
    const a = assertions.get(label);
    const alg = pickAlg(mapGet(item, 'alg'), claimAlg);
    if (!alg) continue;
    const want = mapGet(item, 'hash');
    if (!a || !(want instanceof Uint8Array)) { invalid.push(`The credentials refer to an assertion (${textOf(label, 40)}) that is missing.`); continue; }
    const key = `${label}|${alg}`;
    if (!digests.has(key)) digests.set(key, await digest(alg, a.region));
    if (bytesEqual(digests.get(key), want)) verified.add(label);
    else invalid.push(`The "${textOf(label, 40)}" section was modified after signing (its hash no longer matches the claim).`);
  }
  let extras = assertions.dup === true || manifest.dup === true;
  if (extras) F('warning', 'The credentials contain two sections with the same name; only the first was read, and the rest were ignored.');
  const unlisted = [...assertions.keys()].filter((l) => !referenced.has(l));
  if (unlisted.length) extras = true;
  if (unlisted.length) F('warning', `Content the signature does not cover: ${unlisted.slice(0, 3).map((l) => textOf(l, 30)).join(', ')} (ignore anything it claims).`);

  // ---- hard binding to the image bytes
  const bindLabels = [...verified].filter((l) => l === 'c2pa.hash.data' || l.startsWith('c2pa.hash.data__'));
  if (bindLabels.length > 4) {
    bindIssues.push('The credentials contain an unreasonable number of image-binding sections, so they were not checked.'); // each costs a full hash of the image
    bindLabels.length = 0;
  }
  let bound = null; // null = no binding assertion; otherwise EVERY binding assertion must match
  for (const bindLabel of bindLabels) {
    let ok = false;
    try {
      const hd = decodeContent(data, assertions.get(bindLabel).sup);
      const alg = pickAlg(mapGet(hd, 'alg'), claimAlg);
      const { list, offending, exact } = checkExclusions(mapGet(hd, 'exclusions'), store.spans, bytes.length);
      if (!alg) {
        // unknown hash algorithm: reported through `unsupported`
      } else if (offending.length) {
        invalid.push('The credentials exclude image data from the signed hash, so they do not actually protect the image.');
      } else {
        const want = mapGet(hd, 'hash');
        ok = want instanceof Uint8Array && bytesEqual(await hashWithExclusions(bytes, list, alg), want);
        if (!ok) invalid.push('The image data does not match the hash that was signed: the image was changed after it was signed.');
        else if (!exact) {
          ok = false;
          bindIssues.push('The credentials block in this file does not occupy exactly the byte range the signature says it should. It may have been altered after signing, or written by software this tool does not understand.');
        }
      }
    } catch (e) {
      invalid.push(`The image binding is malformed (${textOf(e.message, 60)}).`);
    }
    bound = (bound === null ? true : bound) && ok;
  }
  R.bindingValid = bound === true;

  if (unsupported.length && !invalid.length) {
    F('notice', `The credentials use something this tool does not support (${unsupported.slice(0, 3).join(', ')}), so they could not be fully verified.`);
    return finish('notice', 'Content Credentials present but could not be fully verified');
  }

  // ---- certificate chain and trust
  const chainRes = await evaluateChain(sig.chain, anchors, now);
  if (chainRes.trusted === true) R.trust = chainRes.expired ? 'expired' : 'trusted'; // never 'trusted' for an expired chain
  else if (chainRes.trusted === false) R.trust = 'untrusted';

  // ---- recorded actions (only from assertions whose hash verified)
  for (const label of [...verified].filter((l) => /^c2pa\.actions(\.v2)?(__\d+)?$/.test(l))) {
    try {
      const content = decodeContent(data, assertions.get(label).sup);
      const acts = mapGet(content, 'actions');
      const tpls = mapGet(content, 'templates');
      for (const a of [...(Array.isArray(acts) ? acts : []), ...(Array.isArray(tpls) ? tpls : [])]) {
        const name = textOf(mapGet(a, 'action'), 40).replace(/^c2pa\./, '');
        if (name && !R.actions.includes(name)) R.actions.push(name);
        if (AI_SOURCE.test(String(mapGet(a, 'digitalSourceType') || ''))) R.ai = true;
        const sw = mapGet(a, 'softwareAgent');
        if (!R.generator && sw) R.generator = textOf(sw instanceof Map ? mapGet(sw, 'name') : sw, 60);
      }
    } catch { /* optional detail */ }
  }

  // ---- compose result
  const who = R.signer;
  const problems = chainRes.problems.length ? ` (${chainRes.problems[0]})` : '';
  if (invalid.length) {
    R.status = 'invalid';
    for (const t of invalid) F('alert', t);
    finish('alert', 'Content Credentials are INVALID: the image or its credentials do not match what was signed');
  } else if (bindIssues.length) {
    R.status = 'error';
    for (const t of bindIssues.slice(0, 1)) F('warning', t);
    finish('warning', 'Content Credentials could not be fully verified');
  } else if (unresolved.length) {
    // A reference we cannot resolve is a part of the claim we could not check: never call it valid.
    R.status = 'error';
    F('warning', `The credentials refer to parts this tool could not locate or check (${unresolved.slice(0, 2).join(', ')}), so they were not fully verified.`);
    finish('warning', 'Content Credentials could not be fully verified');
  } else if (bound === null) {
    R.status = 'unbound';
    F('warning', 'The credentials are signed but contain no verifiable link to this image\'s pixels, so they could belong to a different picture.');
    finish('warning', 'Content Credentials are not tied to this image');
  } else {
    R.status = 'valid';
    if (!chainRes.linksOk || chainRes.expired || !chainRes.usageOk) {
      F('warning', `The signature is mathematically valid, but the signing certificate has a problem${problems}. This tool does not verify timestamps, so it cannot tell whether the certificate was valid when the image was signed.`);
      finish('warning', `Signature valid, but the signing certificate has a problem (${who})`);
    } else if (R.trust === 'trusted' && extras) {
      F('warning', `Signed by ${who} and chained to a trusted root, but the file contains content the signature does not cover, so the credentials are not fully clean.`);
      finish('warning', `Valid signature by ${who}, but the credentials contain uncovered or duplicate content`);
    } else if (R.trust === 'trusted') {
      F('info', `Signed by ${who}; the certificate chains to the trusted root "${textOf(chainRes.anchorName, 60)}". The image has not changed since signing.`);
      finish('clear', `Valid Content Credentials, signed by ${who}`);
    } else if (R.trust === 'untrusted') {
      F('warning', `The image is unchanged since it was signed by ${who}, but that signer is NOT on the C2PA trust list, so who they are cannot be confirmed.`);
      finish('warning', `Signature valid, but the signer (${who}) is not on the C2PA trust list`);
    } else {
      F('notice', `The image is unchanged since it was signed by "${who}", but no trust list is loaded, so the signer's identity was not checked.`);
      finish('notice', `Signature valid; signer "${who}" not checked (no trust list loaded)`);
    }
    if (chainRes.expired && chainRes.trusted === true) F('notice', 'A certificate has expired since signing; this tool does not verify timestamps, so the signing date cannot be confirmed.');
  }

  if (R.generator) F('info', `Created with: ${R.generator}`);
  if (R.title) F('info', `Title in credentials: ${R.title}`);
  if (R.actions.length) F('info', `Recorded actions: ${R.actions.slice(0, 8).join(', ')}`);
  if (R.ai) F('warning', 'The signed record states this content is AI-generated (IPTC source type: algorithmic media).');
  // Not covered by this signature (extra blocks in the file), so worded as a fact about the file only.
  if (R.ingredients) F('info', `The file also contains ${R.ingredients} other credentials block${R.ingredients > 1 ? 's' : ''} from earlier versions; they were not verified.`);
  F('info', 'Revocation status was not checked (needs network access).');
  // `trust` only means something for a file whose signature and binding checked out.
  if (R.status !== 'valid') R.trust = 'unchecked';
  return R;
}
