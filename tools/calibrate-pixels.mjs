// Developer tool: measures false positives (untouched photos) and detections (cloned patches).
// Usage: python3 tools/export-samples.py DIR && node tools/calibrate-pixels.mjs DIR [key=value ...]
import fs from 'node:fs';
import path from 'node:path';
import { toGray, boxResize, copyMove, COPY_MOVE_DEFAULTS } from '../experimental/copy-move.js';

const dir = process.argv[2];
const overrides = Object.fromEntries(process.argv.slice(3).map((a) => { const [k, v] = a.split('='); return [k, Number(v)]; }));
const meta = JSON.parse(fs.readFileSync(path.join(dir, 'meta.json'), 'utf8'));
const opts = { ...COPY_MOVE_DEFAULTS, ...overrides };

let seed = 99;
const rnd = () => (seed = (seed * 1103515245 + 12345) & 0x7fffffff) / 0x7fffffff;
const gauss = () => Math.sqrt(-2 * Math.log(rnd() + 1e-9)) * Math.cos(2 * Math.PI * rnd());

function prep(gray, w, h) {
  const s = Math.min(1, opts.maxSide / Math.max(w, h));
  if (s >= 1) return { g: gray, w, h };
  const nw = Math.round(w * s); const nh = Math.round(h * s);
  return { g: boxResize(gray, w, h, nw, nh), w: nw, h: nh };
}
function run(gray, w, h) { const p = prep(gray, w, h); return copyMove(p.g, p.w, p.h, opts); }

function clone(gray, w, h, { sx, sy, size, dx, dy, noise = 0, gain = 1 }) {
  const g = Float32Array.from(gray);
  for (let y = 0; y < size; y++) for (let x = 0; x < size; x++) {
    const v = gray[(sy + y) * w + sx + x] * gain + (noise ? gauss() * noise : 0);
    g[(sy + dy + y) * w + sx + dx + x] = Math.max(0, Math.min(255, v));
  }
  return g;
}

console.log('options', JSON.stringify(opts));
console.log('\n== untouched photos / textures (want: detected=false) ==');
let fp = 0; let total = 0; let patterned = 0;
for (const [name, [w, h]] of Object.entries(meta)) {
  const rgba = new Uint8Array(fs.readFileSync(path.join(dir, name + '.rgba')));
  const gray = toGray(rgba, w, h);
  const t0 = performance.now();
  const r = run(gray, w, h);
  const ms = Math.round(performance.now() - t0);
  total++; if (r.detected) fp++; if (r.patterned) patterned++;
  console.log(`${name.padEnd(22)} ${String(w + 'x' + h).padEnd(10)} detected=${r.detected} patterned=${!!r.patterned} clusters=${r.clusters} compact=${r.compact} best=${r.count ?? 0} ${ms}ms`);
}
console.log(`false positives: ${fp}/${total}  (flagged as patterned/ignored: ${patterned})`);

console.log('\n== cloned patches (want: detected=true) ==');
const photos = ['astronaut', 'coffee', 'chelsea', 'rocket', 'camera', 'grace_hopper', 'immunohistochemistry'];
const variants = [
  { label: 'exact', noise: 0, gain: 1 }, { label: 'noise2', noise: 2, gain: 1 },
  { label: 'noise4', noise: 4, gain: 1 }, { label: 'gain0.9', noise: 0, gain: 0.9 },
];
const offsets = [[277, 53], [131, 201], [-203, 97], [89, 143], [301, 211]];
let hit = 0; let n = 0;
const byVariant = {};
for (const name of photos) {
  if (!meta[name]) continue;
  const [w, h] = meta[name];
  const gray = toGray(new Uint8Array(fs.readFileSync(path.join(dir, name + '.rgba'))), w, h);
  for (const v of variants) for (const [dx, dy] of offsets) {
    const size = Math.round(Math.min(w, h) * 0.2);
    const sx = dx >= 0 ? 20 : w - size - 20; const sy = 30;
    if (sx + dx < 0 || sx + dx + size > w || sy + dy + size > h) continue;
    const r = run(clone(gray, w, h, { sx, sy, size, dx, dy, noise: v.noise, gain: v.gain }), w, h);
    n++; byVariant[v.label] ??= [0, 0]; byVariant[v.label][1]++;
    if (r.detected) { hit++; byVariant[v.label][0]++; }
  }
}
console.log(`detected ${hit}/${n}`, Object.entries(byVariant).map(([k, [a, b]]) => `${k}: ${a}/${b}`).join('  '));
