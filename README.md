# Image Check: privacy & authenticity (prototype)

A Chrome/Edge extension (Manifest V3). Right-click any image -> **Check this image** and a
panel shows what it found. All analysis happens on your device.

| Section | What it looks for |
|---|---|
| **Tracking** | Known tracker/ad endpoints, tracking-pixel URLs, email addresses or identifiers in the URL, campaign parameters, 1x1 images |
| **Hidden data** | GPS location, camera/lens serial numbers, owner names, device model, timestamps (EXIF/XMP/PNG text) |
| **Authenticity** | **C2PA Content Credentials, cryptographically verified** (see below), AI-generation labels (IPTC, Stable Diffusion/ComfyUI/NovelAI settings), editing software |
| **File safety** | Wrong file type, HTML disguised as an image, data hidden after the image ends, SVG scripts, decompression-bomb sizes |
| **Edit check (experimental)** | Whether the preview thumbnail embedded in a JPEG still matches the image (low confidence, see below) |

## Install (developer mode)

1. Open `chrome://extensions` (or `edge://extensions`) and switch on **Developer mode**.
2. Click **Load unpacked** and choose this folder (the one containing `manifest.json`).
3. Open any page, right-click an image, choose **Check this image (privacy & authenticity)**.

The first time you check an image from a new site, the browser asks permission to read from
that site. If you decline, the extension still runs URL-only checks.

## C2PA signature verification

For JPEG and PNG files carrying Content Credentials, the extension verifies:

1. **The signature**: the claim's COSE signature checks out against the signing certificate
   (ES256/384/512, PS256/384/512, EdDSA).
2. **Every assertion hash** listed in the claim matches its data (so the recorded actions, AI
   label, etc. are what the signer wrote).
3. **The link to the pixels**: the signed hash matches the actual file bytes, and the only bytes
   excluded from that hash are the credentials block itself. (A signer who "excludes" the image
   data would make the binding meaningless, so that is reported as invalid.)
4. **The certificate chain**: links verify, certificates are in date, and, if you supply a trust
   list, the chain ends at a trusted root.

Possible results, in the Authenticity section:

| Result | Meaning |
|---|---|
| **Valid, signer trusted** (green) | Unchanged since signing by a signer on your trust list |
| **Valid, signer not checked** (blue) | Signature genuine, but no trust list is loaded, so who signed is unknown |
| **Valid, signer not on the trust list** (amber) | Signature genuine, signer unknown to the list |
| **Certificate problem** (amber) | Signature genuine, but e.g. the certificate has expired |
| **Not tied to the image** (amber) | Signed, but nothing links the signature to these pixels |
| **INVALID** (red) | The image or the credentials were altered after signing |

A valid credential does **not** mean an image is real: AI tools sign their output too, and a
valid credential that states "AI-generated" is shown as an AI warning, not as reassurance.

**Trust list.** The extension ships without one on purpose. Run `node tools/update-trust-list.mjs`
on your computer to download the official C2PA list (see `trust/README.md`).

**Not checked:** certificate revocation (needs network), RFC 3161 timestamps (so an expired
certificate cannot be excused by a signing date), the signatures of earlier "ingredient"
versions, and non-JPEG/PNG formats.

**Certificate purpose rules.** A genuine signature is not enough for a "clear" result. The signing
certificate must not be a CA, must allow digital signatures, and must carry a content-signing key
purpose; issuing certificates must be allowed to sign certificates and respect path length. A
certificate failing any of these gets a warning ("certificate has a problem") and is never shown as
trusted, even if it chains to a trusted root.

**Binding is checked exactly.** The bytes excluded from the image hash must equal the credentials
block's real byte range. Otherwise an attacker could enlarge the unsigned wrapper after signing to
hide bytes from the hash while a viewer skips them. Because of this rule the verifier fails closed
("could not verify") on any real-world signer that lays out its exclusions differently, and that
is untested here.

**How well tested.** 92 tests cover valid files in every supported algorithm and container,
multi-segment JPEG manifests, tampered image/claim/assertion/signature, whole-image exclusion,
untrusted/expired/self-signed/wrong-purpose signers, RSA and RSA-PSS chains, hostile hash names,
invalid clocks, display-text sanitizing, huge PNGs, and fuzzing. Three independent adversarial
reviews found real problems (including a forgery path through the unsigned wrapper, two
slow-input hangs, and display-text spoofing through the certificate name); each fix has a
regression test in `test/review-regressions.test.js`, and the tests were checked by removing each fix
and confirming the test fails. **All test files were produced by this project's own builder, not by
Adobe, Leica, Google or other real signers.** The verifier follows the spec as described by the
C2PA documentation and other implementations, but it has not been run against real-world signed
files, so expect to find incompatibilities. To check, download samples from the
`c2pa-org/public-testfiles` repository and run them through `verifyC2pa`.

## Edit check (experimental)

JPEGs usually embed a small preview thumbnail made when the photo was taken. Editors often
crop or replace the image and leave that preview behind. The extension compares the two. This
is the only pixel-level signal shipped, and it is deliberately narrow:

| Case (14 public sample images, camera-style thumbnails) | Flagged |
|---|---|
| Untouched, rotated preview, colour-graded, downscaled + recompressed | 0 of 56 |
| Image replaced by a different one | 14 of 14 |
| Heavy crop (to 70% / 50%) | 11 of 14 / 12 of 14 |
| Mild crop (90%) | 3 of 14 |
| Small retouch (about 8% of the area painted over) | **0 of 14** |

So it catches gross changes and misses subtle ones, and files without an embedded preview (most
images that passed through social media or a CDN) give it nothing to compare. A "matches" result
means little. Results never go above "warning". Numbers come from `tools/export-thumbnail-cases.py`
and `tools/calibrate-thumbnail.mjs` on a small public set, not a field study.

**Considered and not shipped:** cloned-region detection (missed most clones after recompression
and gave false alarms on grass-like textures; code and measurements kept in `experimental/`),
error-level analysis and noise-inconsistency maps (flag ordinary photos), and AI/deepfake
classifiers (unreliable). Shipping any of these would produce confident-looking wrong answers.

## Privacy design

- **Nothing leaves your device.** There is no server and no analytics.
- **It will not fetch suspected trackers.** Re-downloading a tracking pixel would itself ping
  the tracker, so URL checks run first and trackers are skipped.
- **Clean fetches.** Downloads send no cookies and no referrer, and are capped at 25 MB / 15 s.
- **Per-site permission** instead of blanket access to all websites.
- **Reverse image search is opt-in** and hidden when the URL looks like it contains identifiers.
- Metadata is shown with `textContent` only, so a hostile file can't inject HTML into the panel.

## Honest limitations

The panel shows a tailored "What this check can't tell you" list for every image (from `limitsFor` in
`analyzer/report.js`), so the limits below are visible to users, not just to developers.

- This reports **signals, not verdicts.** Platforms strip metadata, and metadata can be forged,
  so "nothing found" never proves an image is real, safe, or untracked.
- **No AI/deepfake detection from pixels.** Those detectors are unreliable.
- Metadata parsing covers JPEG, PNG, WebP, AVIF and HEIC (EXIF, XMP, C2PA presence). The WebP and
  ISO-BMFF parsers were tested only on synthetic files. C2PA *signature verification* covers JPEG, PNG and
  WebP (WebP only against my own test builder: the spec's exact RIFF exclusion rules are unconfirmed, so a real
  signer may show as "could not verify"); AVIF/HEIC need a different binding method that is not implemented; for the other formats a credentials block is reported as present but not verified.
- The tracker list is a small sample; ship a maintained list (EasyPrivacy/Disconnect) for real use.
- Only images the browser shows can be checked (not CSS backgrounds or `blob:` images).
- The panel and service worker (including decoding images for the edit check) have only been
  syntax-checked, not run in a real browser.
- Chrome/Edge only for now; Firefox needs a small manifest change.

## Tests

```
node --test        # needs Node 20+; no packages to install
python3 test/make-certs.py   # only to regenerate the throw-away test certificates
```

The test certificates and private keys in `test/certs` are **published test fixtures. Never use
them for anything real.**

## Layout

```
manifest.json        extension manifest
background.js        context menu, safe fetching, trust list, image decoding for the edit check
panel.js             result panel injected into the page
analyzer/            pure JS analysis engine (also runs in Node)
  sniff.js           file type, dimensions, hidden trailing data, SVG checks
  meta.js            EXIF / XMP / PNG text parsing, preview thumbnail, provenance signals
  tracking.js        URL-based tracker heuristics
  c2pa.js            C2PA verifier (locate manifest, signature, hashes, binding)
  pki.js             WebCrypto signature checks, certificate chain and trust evaluation
  der.js cbor.js jumbf.js   bounded parsers for untrusted input
  pixels.js          edit check (embedded-thumbnail comparison)
  report.js          combines everything into the report
trust/               put c2pa-trust.pem here (see trust/README.md)
tools/               trust-list downloader, calibration scripts (developer only)
experimental/        code that was measured and NOT shipped, with the results
test/                fixtures, C2PA test signer, tests
```
