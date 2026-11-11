import test from 'node:test';
import assert from 'node:assert/strict';
import { verifyC2pa } from '../analyzer/c2pa.js';
import { decodeCbor, encodeCbor } from '../analyzer/cbor.js';
import { pemToDers } from '../analyzer/der.js';
import { jpeg } from './fixtures.js';
import { signedFile, readCert } from './c2pa-builder.js';

const NOW = new Date('2026-11-07T00:00:00Z');
const anchors = (...names) => names.flatMap((n) => pemToDers(readCert(n)));
const verify = (file, a = anchors('ca.pem')) => verifyC2pa(file, { anchors: a, now: NOW });
const texts = (r) => r.findings.map((f) => f.text).join('\n');
const flipAt = (file, needle) => {
  const copy = Uint8Array.from(file);
  const idx = Buffer.from(copy).indexOf(Buffer.from(needle));
  assert.ok(idx > 0, `${needle} present`);
  copy[idx] ^= 0x01;
  return copy;
};

test('CBOR round-trips and rejects hostile input', () => {
  const v = new Map([[1, -7], ['a', [1, 2.5, null, true, new Uint8Array([1, 2])]], [33, { isTag: true, tag: 18, value: 'x' }]]);
  const back = decodeCbor(encodeCbor(v)).value;
  assert.equal(back.get(1), -7);
  assert.deepEqual(back.get('a').slice(0, 4), [1, 2.5, null, true]);
  assert.equal(back.get(33).tag, 18);
  assert.throws(() => decodeCbor(Uint8Array.from([0x9f, 0x01]))); // unterminated indefinite array
  assert.throws(() => decodeCbor(Uint8Array.from([0x5a, 0xff, 0xff, 0xff, 0xff, 1]))); // huge bstr length
  assert.throws(() => decodeCbor(Uint8Array.from(Array(100).fill(0x81)))); // nesting bomb
  assert.throws(() => decodeCbor(Uint8Array.from([0x9b, 0, 0, 0, 0xff, 0xff, 0xff, 0xff, 0xff]))); // huge array
});

test('valid, trusted credentials (JPEG, ES256) verify fully', async () => {
  const { file } = signedFile();
  const r = await verify(file);
  assert.equal(r.found, true);
  assert.equal(r.status, 'valid');
  assert.equal(r.trust, 'trusted');
  assert.equal(r.level, 'clear');
  assert.equal(r.signatureValid && r.bindingValid, true);
  assert.equal(r.signer, 'Test Signer ES256');
  assert.match(r.headline, /Valid Content Credentials, signed by Test Signer ES256/);
  assert.match(texts(r), /ImageCheckTest 1\.0/);
  assert.match(texts(r), /Revocation .* not checked/);
});

test('valid credentials in a PNG caBX chunk', async () => {
  const r = await verify(signedFile({ format: 'png' }).file);
  assert.equal(r.status, 'valid');
  assert.equal(r.trust, 'trusted');
});

test('every supported signature algorithm verifies', async () => {
  for (const signer of ['es256', 'es384', 'ps256', 'ed25519']) {
    const r = await verify(signedFile({ signer }).file);
    assert.equal(r.status, 'valid', `${signer}: ${r.headline}`);
    assert.equal(r.signatureValid, true, signer);
  }
});

test('manifest split over many APP11 segments is reassembled', async () => {
  const { file } = signedFile({ maxSegData: 700 });
  assert.ok(Buffer.from(file).toString('latin1').split('JP\x00\x01').length > 3, 'several segments');
  assert.equal((await verify(file)).status, 'valid');
});

test('C2PA 2.x layout (v2 claim, x5chain in protected header) and 1.x layout (unprotected)', async () => {
  assert.equal((await verify(signedFile({ claimV2: true }).file)).status, 'valid');
  assert.equal((await verify(signedFile({ x5: 'unprotected' }).file)).status, 'valid');
});

test('no trust list: signature valid but signer identity is not established', async () => {
  const r = await verify(signedFile().file, null);
  assert.equal(r.status, 'valid');
  assert.equal(r.trust, 'unchecked');
  assert.equal(r.level, 'notice');
  assert.match(texts(r), /trust list/);
});

test('signer outside the trust list is flagged, not trusted', async () => {
  const r = await verify(signedFile({ signer: 'rogue' }).file);
  assert.equal(r.signatureValid, true);
  assert.equal(r.trust, 'untrusted');
  assert.equal(r.level, 'warning');
  assert.match(r.headline, /not on the C2PA trust list/);
});

test('self-signed signer is untrusted unless its own certificate is pinned', async () => {
  const { file } = signedFile({ signer: 'selfsigned' });
  assert.equal((await verify(file)).trust, 'untrusted');
  assert.equal((await verify(file, anchors('selfsigned.chain.pem'))).trust, 'trusted');
});

test('chains issued by RSA (PKCS#1 and PSS) authorities are verified', async () => {
  assert.equal((await verify(signedFile({ signer: 'viarsa' }).file, anchors('rsa-ca.pem'))).trust, 'trusted');
  assert.equal((await verify(signedFile({ signer: 'viapss' }).file, anchors('rsa-pss-ca.pem'))).trust, 'trusted');
  // right file, wrong authority list
  assert.equal((await verify(signedFile({ signer: 'viarsa' }).file, anchors('ca.pem'))).trust, 'untrusted');
});

test('expired signing certificate is reported', async () => {
  const r = await verify(signedFile({ signer: 'expired' }).file);
  assert.equal(r.signatureValid, true);
  assert.equal(r.level, 'warning');
  assert.match(r.headline, /certificate has a problem/);
  assert.match(texts(r), /expired/);
});

test('TAMPER: changing the image after signing is detected', async () => {
  for (const format of ['jpeg', 'png']) {
    const { file } = signedFile({ format });
    const bad = Uint8Array.from(file);
    bad[bad.length - 20] ^= 0xff;
    const r = await verify(bad);
    assert.equal(r.status, 'invalid', format);
    assert.equal(r.level, 'alert');
    assert.match(texts(r), /image data does not match/);
  }
});

test('TAMPER: editing the claim breaks the signature', async () => {
  const r = await verify(flipAt(signedFile().file, 'Test image'));
  assert.equal(r.status, 'invalid');
  assert.match(texts(r), /signature does not match/);
});

test('TAMPER: editing an assertion breaks its hash', async () => {
  const r = await verify(flipAt(signedFile().file, 'TestGen'));
  assert.equal(r.status, 'invalid');
  assert.match(texts(r), /c2pa\.actions.*modified after signing/);
});

test('TAMPER: corrupting the signature bytes themselves is detected', async () => {
  const { file, span } = signedFile();
  const bad = Uint8Array.from(file);
  bad[span[1] - 5] ^= 0x01; // the store ends with the 64-byte ES256 signature
  const r = await verify(bad);
  assert.equal(r.status, 'invalid');
  assert.match(texts(r), /signature does not match/);
});

test('ATTACK: excluding the whole image from the hash is rejected', async () => {
  const r = await verify(signedFile({ exclusion: 'whole' }).file);
  assert.equal(r.status, 'invalid');
  assert.match(texts(r), /exclude image data/);
  assert.equal(r.level, 'alert');
});

test('credentials without an image hash are not treated as protecting the image', async () => {
  const r = await verify(signedFile({ noBinding: true }).file);
  assert.equal(r.status, 'unbound');
  assert.equal(r.level, 'warning');
});

test('unsupported signature algorithm is reported honestly, not as valid or invalid', async () => {
  const r = await verify(signedFile({ algOverride: -999 }).file);
  assert.equal(r.status, 'error');
  assert.match(texts(r), /not supported/);
});

test('sections not covered by the signature are flagged', async () => {
  const r = await verify(signedFile({ extraAssertion: true }).file);
  assert.equal(r.status, 'valid');
  assert.match(texts(r), /signature does not cover: stds\.test\.extra/);
});

test('signed AI-generation action is surfaced', async () => {
  const r = await verify(signedFile({ ai: true }).file);
  assert.equal(r.status, 'valid');
  assert.equal(r.ai, true);
  assert.match(texts(r), /AI-generated/);
  assert.deepEqual(r.actions, ['created']);
});

test('files without credentials, and non-images, report found:false', async () => {
  assert.deepEqual(await verify(jpeg()), { found: false });
  assert.deepEqual(await verify(new Uint8Array([1, 2, 3])), { found: false });
  assert.deepEqual(await verify(new Uint8Array(0)), { found: false });
});

test('fuzz: damaged files never throw, and image changes never verify as valid', async () => {
  for (const format of ['jpeg', 'png']) {
    const { file, span } = signedFile({ format, maxSegData: 900 });
    let state = 7;
    const rnd = () => (state = (state * 1103515245 + 12345) & 0x7fffffff) / 0x7fffffff;
    for (let i = 0; i < 250; i++) {
      const copy = Uint8Array.from(file);
      const idx = Math.floor(rnd() * copy.length);
      copy[idx] ^= 1 + Math.floor(rnd() * 255);
      const r = await verify(copy);
      assert.ok(r && typeof r === 'object');
      if (idx < span[0] || idx >= span[1]) {
        assert.ok(!(r.found && r.status === 'valid'), `${format}: mutation at ${idx} outside manifest verified as valid`);
      }
    }
    for (let i = 0; i < 60; i++) {
      const r = await verify(file.subarray(0, Math.floor(rnd() * file.length)));
      assert.ok(r && typeof r === 'object');
      assert.ok(!(r.found && r.status === 'valid'));
    }
  }
});
