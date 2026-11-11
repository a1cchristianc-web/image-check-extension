// Developer tool: measures how often the embedded-thumbnail check flags each kind of case.
// Usage: python3 tools/export-thumbnail-cases.py DIR && node tools/calibrate-thumbnail.mjs DIR
import fs from 'node:fs';
import path from 'node:path';
import { analyzePixels, MISMATCH_BELOW } from '../analyzer/pixels.js';

const dir = process.argv[2];
const cases = JSON.parse(fs.readFileSync(path.join(dir, 'cases.json'), 'utf8'));
const load = ([f, width, height]) => ({ rgba: new Uint8Array(fs.readFileSync(path.join(dir, f))), width, height });

const stats = {}; // group -> kind -> { n, flagged, sims[] }
for (const c of cases) {
  const main = load(c.main);
  const r = analyzePixels({ ...main, thumb: load(c.thumb) });
  const s = ((stats[c.group] ??= {})[c.kind] ??= { n: 0, flagged: 0, sims: [] });
  s.n++;
  if (r.level === 'warning') s.flagged++;
  if (r.thumbnail) s.sims.push(r.thumbnail.similarity);
}

console.log(`flag threshold: similarity < ${MISMATCH_BELOW}\n`);
for (const [group, kinds] of Object.entries(stats)) {
  console.log(`== ${group}s`);
  for (const [kind, s] of Object.entries(kinds)) {
    const sims = s.sims.sort((a, b) => a - b);
    const med = sims.length ? sims[Math.floor(sims.length / 2)].toFixed(2) : 'n/a';
    const lo = sims.length ? sims[0].toFixed(2) : 'n/a';
    const hi = sims.length ? sims[sims.length - 1].toFixed(2) : 'n/a';
    console.log(`${kind.padEnd(9)} flagged ${String(s.flagged).padStart(2)}/${s.n}   similarity min ${lo} median ${med} max ${hi}`);
  }
  console.log();
}
