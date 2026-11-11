// Downloads the official C2PA trust list into trust/c2pa-trust.pem, so the extension can tell
// whether a Content Credentials signer is on it. Run this on YOUR computer (needs internet):
//
//   node tools/update-trust-list.mjs [URL]
//
// The default URL points at the `trust-list` directory of the c2pa-org/conformance-public
// repository. That path was NOT verified when this script was written (the build sandbox had no
// access to GitHub), so if the download fails, open
// https://github.com/c2pa-org/conformance-public/tree/main/trust-list in a browser, find the
// current PEM file, and pass its "raw" URL as the argument.
import fs from 'node:fs';
import { pemToDers } from '../analyzer/der.js';
import { buildAnchorIndex } from '../analyzer/pki.js';

const DEFAULT_URL = 'https://raw.githubusercontent.com/c2pa-org/conformance-public/main/trust-list/C2PA-TRUST-LIST.pem';
const url = process.argv[2] || DEFAULT_URL;
const out = new URL('../trust/c2pa-trust.pem', import.meta.url);

const res = await fetch(url);
if (!res.ok) {
  console.error(`Download failed: HTTP ${res.status} for ${url}`);
  process.exit(1);
}
const text = await res.text();
const ders = pemToDers(text);
const index = buildAnchorIndex(ders);
if (!index) {
  console.error('The downloaded file contains no usable certificates; not saving it.');
  process.exit(1);
}
fs.mkdirSync(new URL('../trust/', import.meta.url), { recursive: true });
fs.writeFileSync(out, text);
console.log(`Saved ${index.size_} certificates (of ${ders.length} found) to trust/c2pa-trust.pem`);
console.log('Reload the extension at chrome://extensions to use it.');
