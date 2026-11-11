// Regression tests for the findings of an independent adversarial review of the C2PA verifier.
// Each test pins a weakness that was found and fixed.
import test from 'node:test';
import assert from 'node:assert/strict';
import { verifyC2pa } from '../analyzer/c2pa.js';
import { pemToDers } from '../analyzer/der.js';
import { signedFile, readCert } from './c2pa-builder.js';

const NOW = new Date('2026-11-07T00:00:00Z');
const ca = pemToDers(readCert('ca.pem'));
const verify = (file, anchors = ca) => verifyC2pa(file, { anchors, now: NOW });
const texts = (r) => r.findings.map((f) => f.text).join('\n');
const MANIFEST = 'urn:uuid:test-manifest';

test('C1: a claim reference this tool cannot resolve is never reported as valid', async () => {
  for (const refUrl of [
    (l) => `self#jumbf=/c2pa/some-other-manifest/c2pa.assertions/${l}`, // names a different manifest
    () => 'self#jumbf=c2pa.assertions', // no label
    (l) => `https://example.com/${l}`, // not a self reference
    (l) => `self#jumbf=c2pa.assertions/nested/${l}`, // wrong depth
  ]) {
    const r = await verify(signedFile({ refUrl }).file);
    assert.notEqual(r.status, 'valid', refUrl('x'));
    assert.equal(r.status, 'error');
    assert.equal(r.level, 'warning');
    assert.match(texts(r), /could not locate or check/);
  }
});

test('C1: the legitimate spellings of a self reference still verify (and the AI flag is read)', async () => {
  for (const refUrl of [
    (l) => `self#jumbf=c2pa.assertions/${l}`,
    (l) => `self#jumbf=/c2pa/${MANIFEST}/c2pa.assertions/${l}`,
    (l) => `self#jumbf=c2pa/${MANIFEST}/c2pa.assertions/${l}`,
    (l) => `self#jumbf=c2pa.assertions/${l}/`,
  ]) {
    const r = await verify(signedFile({ refUrl, ai: true }).file);
    assert.equal(r.status, 'valid', refUrl('c2pa.actions'));
    assert.equal(r.ai, true);
  }
});

test('C1: tampering with an assertion referenced by an unusual-but-valid URL is still caught', async () => {
  const { file } = signedFile({ refUrl: (l) => `self#jumbf=/c2pa/${MANIFEST}/c2pa.assertions/${l}`, ai: true });
  const at = Buffer.from(file).indexOf('TestGen 1.0');
  assert.ok(at > 0);
  const bad = Uint8Array.from(file);
  bad[at] ^= 0x01;
  const r = await verify(bad);
  assert.equal(r.status, 'invalid');
  assert.match(texts(r), /c2pa\.actions.*modified after signing/);
});

test('C2: repeated references to one assertion are hashed once, and absurd counts are refused', async () => {
  const fine = await verify(signedFile({ repeatRefs: 100 }).file);
  assert.equal(fine.status, 'valid');
  const hostile = await verify(signedFile({ repeatRefs: 300 }).file);
  assert.notEqual(hostile.status, 'valid');
  assert.equal(hostile.level, 'warning');
  assert.match(texts(hostile), /unreasonable number of assertions/);
});

test('C4: an expired-but-otherwise-trusted chain is never reported as trust "trusted"', async () => {
  const r = await verify(signedFile({ signer: 'expired' }).file);
  assert.equal(r.status, 'valid');
  assert.equal(r.level, 'warning');
  assert.equal(r.trust, 'expired');
  assert.ok(!(r.status === 'valid' && r.trust === 'trusted'));
});

test('C5: an overlong certificate chain is refused', async () => {
  const r = await verify(signedFile({ chainPad: 12 }).file);
  assert.equal(r.status, 'error');
  assert.match(texts(r), /unreasonably long/);
});

test('S1: a CA certificate, or a key not allowed to sign, cannot act as the signer', async () => {
  for (const signer of ['leafca', 'noksig']) {
    const r = await verify(signedFile({ signer }).file);
    assert.equal(r.status, 'valid', 'the signature itself is genuine');
    assert.equal(r.level, 'warning', signer);
    assert.notEqual(r.trust, 'trusted', signer);
    assert.match(r.headline, /certificate has a problem/);
  }
});

test('S2: an AI source type declared in the signed actions templates is detected', async () => {
  const r = await verify(signedFile({ aiTemplate: true }).file);
  assert.equal(r.ai, true);
});

test('C3: nothing is displayed about timestamps or earlier versions that the signature does not vouch for', async () => {
  const r = await verify(signedFile().file);
  assert.doesNotMatch(texts(r), /trusted timestamp/);
});

// ---------------------------------------------------------------- second independent review
import { png } from './fixtures.js';

// The attack from the review: after signing, grow the UNSIGNED wrapper (APP11 length + the JUMBF box
// lengths, all inside the excluded bytes) so it swallows `k` bytes that follow. The hash still matches
// (those bytes are unchanged) but a decoder now skips over them, so what is displayed can change.
function widen(file, span, k) {
  const f = Buffer.from(file);
  const S = span[0];
  const bump = (off) => f.writeUInt32BE(f.readUInt32BE(off) + k, off);
  const lastChild = (o) => {
    const end = o + f.readUInt32BE(o) - k;
    let p = o + 8;
    let last = p;
    while (p < end) { last = p; p += f.readUInt32BE(p); }
    return last;
  };
  f.writeUInt16BE(f.readUInt16BE(S + 2) + k, S + 2);
  let off = S + 12;
  bump(off);
  for (let i = 0; i < 3; i++) { off = lastChild(off); bump(off); } // store -> manifest -> signature -> cbor
  return new Uint8Array(f);
}

test('R1: growing the credentials block over signed bytes is never reported as valid', async () => {
  const { file, span } = signedFile();
  assert.equal((await verify(file)).status, 'valid');
  const evil = widen(file, span, 4);
  const outside = [...evil].reduce((n, b, i) => n + ((i < span[0] || i >= span[1]) && b !== file[i] ? 1 : 0), 0);
  assert.equal(outside, 0, 'precondition: every byte that is hashed is unchanged');
  const r = await verify(evil);
  assert.notEqual(r.status, 'valid');
  assert.notEqual(r.level, 'clear');
  assert.notEqual(r.trust, 'trusted');
  assert.match(texts(r), /does not occupy exactly the byte range/);
});

test('R2: certificates with the wrong purpose never earn "clear" or "trusted"', async () => {
  for (const signer of ['noeku', 'serverauth', 'nokcs', 'pl0']) {
    const r = await verify(signedFile({ signer }).file);
    assert.equal(r.status, 'valid', `${signer}: the signature itself is genuine`);
    assert.equal(r.level, 'warning', signer);
    assert.notEqual(r.trust, 'trusted', signer);
    assert.match(r.headline, /certificate has a problem/, signer);
  }
  assert.equal((await verify(signedFile({ signer: 'es256' }).file)).level, 'clear', 'control: a proper certificate is still clear');
});

test('R3: an invalid verification time fails closed instead of disabling expiry checks', async () => {
  for (const signer of ['es256', 'expired']) {
    const { file } = signedFile({ signer });
    for (const now of [new Date('garbage'), 'not a date', null, NaN]) {
      const r = await verifyC2pa(file, { anchors: ca, now });
      assert.notEqual(r.status, 'valid', `${signer} / ${String(now)}`);
      assert.notEqual(r.level, 'clear');
    }
  }
});

test('R4: "trust" is only reported for files that verified', async () => {
  const bad = Uint8Array.from(signedFile().file);
  bad[bad.length - 20] ^= 0xff;
  const r = await verify(bad);
  assert.equal(r.status, 'invalid');
  assert.equal(r.trust, 'unchecked');
});

test('R5: unknown, weak or hostile hash algorithm names are refused, never treated as SHA-256', async () => {
  for (const claimAlgName of ['md5', 'sha1', '__proto__', 'constructor', 'toString']) {
    const r = await verify(signedFile({ claimAlgName }).file);
    assert.notEqual(r.status, 'valid', claimAlgName);
    assert.equal(r.status, 'error', claimAlgName);
    assert.match(texts(r), /hash algorithm/, claimAlgName);
  }
});

test('R6: control, zero-width and bidi characters from unsigned parts cannot reach displayed text', async () => {
  const r = await verify(signedFile({ extraAssertion: true, extraLabel: 'stds.‮gpj.​exe⁦' }).file);
  assert.equal(r.status, 'valid');
  assert.match(texts(r), /does not cover/);
  assert.doesNotMatch(texts(r), /[​-‏‪-‮⁦-⁩]/);
});

test('R7: a PNG with an absurd number of chunks is reported as not scanned, not as "no credentials"', async () => {
  const text = Object.fromEntries(Array.from({ length: 20100 }, (_, i) => [`k${i}`, 'v']));
  const r = await verify(png({ w: 32, h: 32, text }));
  assert.equal(r.found, true);
  assert.equal(r.status, 'error');
  assert.equal(r.level, 'notice');
  assert.match(texts(r), /too many parts to scan/);
  assert.match(texts(r), /says nothing about whether it has any/);
  assert.deepEqual(await verify(png({ w: 32, h: 32 })), { found: false }, 'an ordinary PNG is still simply "no credentials"');
});

// ---------------------------------------------------------------- third independent review
test('R8: a hostile claim URL (huge run of slashes) cannot make parsing slow', async () => {
  const t0 = Date.now();
  const r = await verify(signedFile({ refUrl: () => 'self#jumbf=' + '/'.repeat(80000) + 'x' }).file);
  assert.ok(Date.now() - t0 < 1500, `took ${Date.now() - t0} ms`);
  assert.notEqual(r.status, 'valid');
});

test('R9: the signer name from the certificate is sanitised like every other displayed field', async () => {
  const r = await verify(signedFile({ signer: 'bidi' }).file);
  assert.equal(r.status, 'valid');
  assert.doesNotMatch(r.signer + r.headline + texts(r), /[​-‏‪-‮⁦-⁩]/u);
});

test('R10: invisible, bidi-mark, tag and filler characters are stripped from displayed text', async () => {
  const bad = '؜ ⁠­\u{e0041}ㅤ᠎A';
  const r = await verify(signedFile({ title: 'x' + bad + 'y' }).file);
  assert.equal(r.status, 'valid');
  for (const cp of [0x61c, 0x2028, 0x2060, 0xad, 0xe0041, 0x3164, 0x180e]) assert.ok(!r.title.includes(String.fromCodePoint(cp)), `U+${cp.toString(16)} survived`);
});

test('R11: a certificate with an unknown critical extension never earns "clear" or "trusted"', async () => {
  const r = await verify(signedFile({ signer: 'critext' }).file);
  assert.equal(r.status, 'valid');
  assert.equal(r.level, 'warning');
  assert.notEqual(r.trust, 'trusted');
});

test('R12: a duplicate assertion label, or uncovered content, stops the result being "clear"', async () => {
  const dup = await verify(signedFile({ extraAssertion: true, extraLabel: 'c2pa.actions' }).file);
  assert.notEqual(dup.level, 'clear');
  assert.match(texts(dup), /same name/);
  const extra = await verify(signedFile({ extraAssertion: true }).file);
  assert.notEqual(extra.level, 'clear');
});

test('R13: many image-binding assertions are refused instead of hashing the image over and over', async () => {
  const r = await verify(signedFile({ bindCopies: 10 }).file);
  assert.notEqual(r.status, 'valid');
  assert.equal(r.level, 'warning');
  assert.equal((await verify(signedFile({ bindCopies: 1 }).file)).status, 'valid', 'a couple of bindings are fine');
});

// ---------------------------------------------------------------- WebP credentials
test('W1: a signed WebP verifies, and tampering with it is caught', async () => {
  const { file } = signedFile({ format: 'webp', ai: true });
  const r = await verify(file);
  assert.equal(r.found, true);
  assert.equal(r.format, 'webp');
  assert.equal(r.status, 'valid', texts(r));
  assert.equal(r.bindingValid, true);
  assert.equal(r.ai, true);
  const bad = Uint8Array.from(file);
  bad[bad.length - 1] ^= 0xff; // a byte of the file that is covered by the hash (or part of the manifest)
  assert.notEqual((await verify(bad)).status, 'valid');
  const at = Buffer.from(file).indexOf('TestGen 1.0');
  const bad2 = Uint8Array.from(file);
  bad2[at] ^= 1;
  assert.equal((await verify(bad2)).status, 'invalid');
});

test('W2: growing the WebP credentials chunk over signed bytes is not reported as valid', async () => {
  const { file, span } = signedFile({ format: 'webp' });
  const f = Buffer.from(file);
  f.writeUInt32LE(f.readUInt32LE(span[0] + 4) + 2, span[0] + 4); // chunk now claims 2 more bytes
  const r = await verify(new Uint8Array(f));
  assert.notEqual(r.status, 'valid');
  assert.notEqual(r.level, 'clear');
});

test('W3: a WebP without credentials is simply "none found"', async () => {
  const { file, span } = signedFile({ format: 'webp' });
  const plain = Uint8Array.from([...file.subarray(0, span[0]), ...file.subarray(span[1])]);
  assert.deepEqual(await verify(plain), { found: false });
});
