// TEST-ONLY: builds genuinely signed C2PA-style JPEG/PNG files (JUMBF + CBOR + COSE_Sign1) with
// the throw-away certificates from test/certs, so the verifier can be exercised end to end.
import crypto from 'node:crypto';
import fs from 'node:fs';
import { encodeCbor } from '../analyzer/cbor.js';
import { pemToDers } from '../analyzer/der.js';
import { jpeg, png, crc32 } from './fixtures.js';

const CERT_DIR = new URL('./certs/', import.meta.url);
export const readCert = (name) => fs.readFileSync(new URL(name, CERT_DIR), 'utf8');

const SIGNERS = {
  es256: { alg: -7, hash: 'sha256' },
  es384: { alg: -35, hash: 'sha384' },
  ps256: { alg: -37, hash: 'sha256', pss: 32 },
  ed25519: { alg: -8, hash: null },
  expired: { alg: -7, hash: 'sha256' },
  rogue: { alg: -7, hash: 'sha256' },
  selfsigned: { alg: -7, hash: 'sha256' },
  viarsa: { alg: -7, hash: 'sha256' },
  viapss: { alg: -7, hash: 'sha256' },
  leafca: { alg: -7, hash: 'sha256' },
  noksig: { alg: -7, hash: 'sha256' },
  noeku: { alg: -7, hash: 'sha256' },
  serverauth: { alg: -7, hash: 'sha256' },
  nokcs: { alg: -7, hash: 'sha256' },
  pl0: { alg: -7, hash: 'sha256' },
  bidi: { alg: -7, hash: 'sha256' },
  critext: { alg: -7, hash: 'sha256' },
};
const UUID = {
  store: '63327061-0011-0010-8000-00aa00389b71', manifest: '63326d61-0011-0010-8000-00aa00389b71',
  assertions: '63326173-0011-0010-8000-00aa00389b71', claim: '6332636c-0011-0010-8000-00aa00389b71',
  signature: '63326373-0011-0010-8000-00aa00389b71', cbor: '63626f72-0011-0010-8000-00aa00389b71',
};
const AI_URL = 'http://cv.iptc.org/newscodes/digitalsourcetype/trainedAlgorithmicMedia';

const u32 = (n) => { const b = Buffer.alloc(4); b.writeUInt32BE(n); return b; };
const box = (type, payload) => Buffer.concat([u32(8 + payload.length), Buffer.from(type, 'latin1'), payload]);
const jumd = (uuid, label) => box('jumd', Buffer.concat([Buffer.from(uuid.replace(/-/g, ''), 'hex'), Buffer.from([3]), Buffer.from(label + '\0')]));
const sup = (uuid, label, ...content) => box('jumb', Buffer.concat([jumd(uuid, label), ...content]));
const cborAssertion = (label, value) => sup(UUID.cbor, label, box('cbor', Buffer.from(encodeCbor(value))));
const digest = (alg, buf) => new Uint8Array(crypto.createHash(alg).update(buf).digest());

function sign(signerName, data) {
  const s = SIGNERS[signerName];
  const key = crypto.createPrivateKey(readCert(`${signerName}.key.pem`));
  if (signerName === 'ed25519') return crypto.sign(null, data, key);
  if (s.pss) return crypto.sign(s.hash, data, { key, padding: crypto.constants.RSA_PKCS1_PSS_PADDING, saltLength: s.pss });
  return crypto.sign(s.hash, data, { key, dsaEncoding: 'ieee-p1363' });
}

function app11(store, maxData) {
  const header = store.subarray(0, 8);
  const body = store.subarray(8);
  const out = [];
  for (let off = 0, z = 1; off < body.length || z === 1; off += maxData, z++) {
    const piece = body.subarray(off, off + maxData);
    const payload = Buffer.concat([Buffer.from('JP'), Buffer.from([0, 1]), u32(z), header, piece]);
    const len = Buffer.alloc(2);
    len.writeUInt16BE(payload.length + 2);
    out.push(Buffer.from([0xff, 0xeb]), len, payload);
  }
  return Buffer.concat(out);
}

// RIFF/WebP: a minimal file (VP8X chunk only; the verifier never decodes pixels) whose RIFF size covers `extra` more bytes.
function webpBase(extra) {
  const vp8x = Buffer.concat([Buffer.from('VP8X'), Buffer.from([10, 0, 0, 0]), Buffer.alloc(10)]);
  const body = Buffer.concat([Buffer.from('WEBP'), vp8x]);
  const size = Buffer.alloc(4);
  size.writeUInt32LE(body.length + extra);
  return Buffer.concat([Buffer.from('RIFF'), size, body]);
}
function webpChunk(store) {
  const len = Buffer.alloc(4);
  len.writeUInt32LE(store.length);
  return Buffer.concat([Buffer.from('C2PA'), len, store, store.length & 1 ? Buffer.from([0]) : Buffer.alloc(0)]);
}

function pngChunk(type, data) {
  const td = Buffer.concat([Buffer.from(type, 'latin1'), data]);
  return Buffer.concat([u32(data.length), td, u32(crc32(td))]);
}

// Returns { file, span: [start, end] } where span is the manifest's byte range in the file.
export function signedFile(opts = {}) {
  const {
    format = 'jpeg', signer = 'es256', claimV2 = false, x5 = 'protected', ai = false, exclusion = 'normal',
    maxSegData = 60000, title = 'Test image', extraAssertion = false, noBinding = false, algOverride = null,
    refUrl = (l) => `self#jumbf=c2pa.assertions/${l}`, repeatRefs = 0, aiTemplate = false, chainPad = 0,
    claimAlgName = 'sha256', extraLabel = 'stds.test.extra', bindCopies = 0,
  } = opts;
  const baseFor = (blockLen) => (format === 'jpeg' ? jpeg({ w: 32, h: 32 }) : format === 'webp' ? webpBase(blockLen) : png({ w: 32, h: 32 }));
  const at = format === 'jpeg' ? 2 : format === 'webp' ? 12 : 33;
  const chain = pemToDers(readCert(`${signer}.chain.pem`));
  for (let i = 0; i < chainPad; i++) chain.push(chain[chain.length - 1]);
  let blockLen = 1000;

  for (let iter = 0; iter < 8; iter++) {
    const base = baseFor(blockLen);
    const total = base.length + blockLen;
    const exclusions = exclusion === 'whole' ? [{ start: 0, length: total }] : [{ start: at, length: blockLen }];
    const hashed = exclusion === 'whole' ? new Uint8Array(0) : base;
    const assertions = [];
    if (!noBinding) {
      assertions.push(['c2pa.hash.data', { exclusions, name: 'jumbf manifest', alg: 'sha256', hash: digest('sha256', hashed), pad: new Uint8Array(0) }]);
    }
    for (let i = 1; i <= bindCopies; i++) assertions.push([`c2pa.hash.data__${i}`, assertions[0][1]]);
    assertions.push(['c2pa.actions', { actions: [ai
      ? { action: 'c2pa.created', digitalSourceType: AI_URL, softwareAgent: 'TestGen 1.0' }
      : { action: 'c2pa.created', softwareAgent: 'TestGen 1.0' }],
      ...(aiTemplate ? { templates: [{ action: 'c2pa.created', digitalSourceType: AI_URL }] } : {}) }]);
    const built = assertions.map(([label, value]) => ({ label, box: cborAssertion(label, value) }));
    if (extraAssertion) built.push({ label: extraLabel, extra: true, box: cborAssertion(extraLabel, { note: 'unsigned' }) });
    const listed = built.filter((a) => !a.extra);
    const refs = listed.map((a) => ({ url: refUrl(a.label), hash: digest('sha256', a.box.subarray(8)) }));
    for (let i = 0; i < repeatRefs; i++) refs.push({ ...refs[refs.length - 1] });

    const claim = claimV2
      ? { instance_id: 'xmp:iid:test', claim_generator_info: { name: 'ImageCheckTest', version: '1.0' }, signature: 'self#jumbf=c2pa.signature', created_assertions: refs, alg: claimAlgName, 'dc:title': title }
      : { 'dc:title': title, claim_generator: 'ImageCheckTest/1.0', claim_generator_info: [{ name: 'ImageCheckTest', version: '1.0' }], instanceID: 'xmp:iid:test', signature: 'self#jumbf=c2pa.signature', assertions: refs, alg: claimAlgName };
    const claimBytes = Buffer.from(encodeCbor(claim));

    const algId = algOverride ?? SIGNERS[signer].alg;
    const protectedBytes = Buffer.from(encodeCbor(new Map(x5 === 'protected' ? [[1, algId], [33, chain]] : [[1, algId]])));
    const unprotected = new Map(x5 === 'protected' ? [] : [[33, chain]]);
    const sigStructure = Buffer.from(encodeCbor(['Signature1', protectedBytes, new Uint8Array(0), claimBytes]));
    const cose = { isTag: true, tag: 18, value: [protectedBytes, unprotected, null, sign(signer, sigStructure)] };

    const manifest = sup(UUID.manifest, 'urn:uuid:test-manifest',
      sup(UUID.assertions, 'c2pa.assertions', ...built.map((a) => a.box)),
      sup(UUID.claim, claimV2 ? 'c2pa.claim.v2' : 'c2pa.claim', box('cbor', claimBytes)),
      sup(UUID.signature, 'c2pa.signature', box('cbor', Buffer.from(encodeCbor(cose)))));
    const store = sup(UUID.store, 'c2pa', manifest);
    const block = format === 'jpeg' ? app11(store, maxSegData) : format === 'webp' ? webpChunk(store) : pngChunk('caBX', store);

    if (block.length === blockLen) {
      return { file: new Uint8Array(Buffer.concat([base.subarray(0, at), block, base.subarray(at)])), span: [at, at + block.length] };
    }
    blockLen = block.length;
  }
  throw new Error('manifest size did not converge');
}
