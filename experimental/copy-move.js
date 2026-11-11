// EXPERIMENTAL / NOT SHIPPED. Copy-move (cloned region) detection by block matching.
//
// Measured on 14 public sample photos/textures (scikit-image, matplotlib):
//   * untouched images:   0/14 false positives
//   * pixel-exact clones: detected only when the image is analysed at NATIVE resolution on a 1px grid
//                         (about 0.7-3 s for a 0.26 MP image, too slow for typical photos)
//   * after downscaling, or for any clone with sub-pixel/recompression differences: mostly missed
// A second approach (FFT autocorrelation proposing shifts + local verification) had 4/14 false
// positives (self-similar textures such as grass) and found only 10/28 clones, so it was dropped.
// Conclusion: neither is reliable enough to show users, so the extension does not use this file.
// Reproduce with: python3 tools/export-samples.py DIR && node tools/calibrate-pixels.mjs DIR
// The module-level notes below are kept so the next attempt does not start from zero.

export function boxResize(src, w, h, nw, nh) {
  const out = new Float32Array(nw * nh);
  for (let y = 0; y < nh; y++) {
    const y0 = Math.floor((y * h) / nh);
    const y1 = Math.max(y0 + 1, Math.floor(((y + 1) * h) / nh));
    for (let x = 0; x < nw; x++) {
      const x0 = Math.floor((x * w) / nw);
      const x1 = Math.max(x0 + 1, Math.floor(((x + 1) * w) / nw));
      let t = 0;
      for (let yy = y0; yy < y1; yy++) for (let xx = x0; xx < x1; xx++) t += src[yy * w + xx];
      out[y * nw + x] = t / ((y1 - y0) * (x1 - x0));
    }
  }
  return out;
}
export function toGray(rgba, w, h) {
  const g = new Float32Array(w * h);
  for (let i = 0, p = 0; i < g.length; i++, p += 4) g[i] = 0.299 * rgba[p] + 0.587 * rgba[p + 1] + 0.114 * rgba[p + 2];
  return g;
}

// ------------------------------------------------------------------ 1. cloned regions
// Separable [1 2 1]/4 smoothing. Matching on a lightly blurred copy tolerates sub-pixel shifts and
// recompression noise that break matching on raw pixels.
export function blur(src, w, h, passes) {
  let a = src;
  for (let p = 0; p < passes; p++) {
    const t = new Float32Array(a.length);
    const b = new Float32Array(a.length);
    for (let y = 0; y < h; y++) for (let x = 0; x < w; x++) {
      const i = y * w + x;
      t[i] = (a[i - (x > 0 ? 1 : 0)] + 2 * a[i] + a[i + (x < w - 1 ? 1 : 0)]) / 4;
    }
    for (let y = 0; y < h; y++) for (let x = 0; x < w; x++) {
      const i = y * w + x;
      b[i] = (t[i - (y > 0 ? w : 0)] + 2 * t[i] + t[i + (y < h - 1 ? w : 0)]) / 4;
    }
    a = b;
  }
  return a;
}

const B = 16; // block size
const NF = 16; // 4x4 pooled features per block

export const COPY_MOVE_DEFAULTS = {
  maxSide: 384, step: 1, blur: 0, texture: 5, isotropy: 0.04, match: 3, minShift: 24,
  minExtent: 16, // a clone must span at least this many pixels (beyond one block) in BOTH directions
  minBlocks: 100, minFill: 0.5, window: 12, maxCompact: 3, maxPairs: 250000,
};

export function copyMove(gray, w, h, opts = {}) {
  const o = { ...COPY_MOVE_DEFAULTS, ...opts };
  const S = o.step;
  const nx = Math.floor((w - B) / S) + 1;
  const ny = Math.floor((h - B) / S) + 1;
  if (nx < 6 || ny < 6) return { ran: false };
  const total = nx * ny;
  if (o.blur) gray = blur(gray, w, h, o.blur);

  const ci = Float32Array.from({ length: B }, (_, i) => i - (B - 1) / 2);
  let sxx = 0;
  for (let i = 0; i < B; i++) sxx += ci[i] * ci[i] * B;

  const feats = new Float32Array(total * NF);
  const usable = [];
  const pooled = new Float32Array(NF);
  for (let by = 0; by < ny; by++) {
    for (let bx = 0; bx < nx; bx++) {
      let sum = 0; let sx = 0; let sy = 0;
      for (let j = 0; j < B; j++) {
        const row = (by * S + j) * w + bx * S;
        for (let i = 0; i < B; i++) { const v = gray[row + i]; sum += v; sx += v * ci[i]; sy += v * ci[j]; }
      }
      const mean = sum / (B * B);
      const ax = sx / sxx;
      const ay = sy / sxx;
      pooled.fill(0);
      let e = 0; let gxx = 0; let gyy = 0; let gxy = 0;
      for (let j = 0; j < B; j++) {
        const row = (by * S + j) * w + bx * S;
        for (let i = 0; i < B; i++) {
          const v = gray[row + i];
          const r = v - mean - ax * ci[i] - ay * ci[j];
          e += r * r;
          pooled[(j >> 2) * 4 + (i >> 2)] += r;
          if (i < B - 1 && j < B - 1) {
            const gx = gray[row + i + 1] - v; const gy = gray[row + w + i] - v;
            gxx += gx * gx; gyy += gy * gy; gxy += gx * gy;
          }
        }
      }
      if (Math.sqrt(e / (B * B)) < o.texture) continue; // flat or pure gradient
      // Straight edges match themselves along their own direction; keep only blocks with structure
      // in more than one direction (smaller structure-tensor eigenvalue not negligible).
      const half = (gxx + gyy) / 2;
      const root = Math.sqrt(((gxx - gyy) / 2) ** 2 + gxy * gxy);
      if (half - root < o.isotropy * (half + root)) continue;
      const id = by * nx + bx;
      for (let k = 0; k < NF; k++) feats[id * NF + k] = pooled[k] / 16;
      usable.push(id);
    }
  }

  const n = usable.length;
  const votes = new Map();
  const seen = new Set();
  let pairs = 0;
  const limit = o.match * NF;
  for (let pass = 0; pass < 2; pass++) {
    const wts = Float64Array.from({ length: NF }, (_, k) => (((k + 1) * (pass ? 2246822519 : 2654435761)) >>> 0) / 2147483648 - 1);
    const keys = new Float64Array(total);
    for (const id of usable) { let t = 0; for (let k = 0; k < NF; k++) t += wts[k] * feats[id * NF + k]; keys[id] = t; }
    const order = Uint32Array.from(usable).sort((x, y) => keys[x] - keys[y]);
    for (let p = 0; p < n; p++) {
      for (let q = p + 1; q < Math.min(n, p + 1 + o.window); q++) {
        let a = order[p]; let b = order[q];
        let d = 0;
        for (let k = 0; k < NF && d <= limit; k++) d += Math.abs(feats[a * NF + k] - feats[b * NF + k]);
        if (d > limit) continue;
        const pid = a < b ? a * total + b : b * total + a;
        if (seen.has(pid)) continue;
        seen.add(pid);
        let dx = ((b % nx) - (a % nx)) * S;
        let dy = (Math.floor(b / nx) - Math.floor(a / nx)) * S;
        if (Math.hypot(dx, dy) < o.minShift) continue;
        if (dy < 0 || (dy === 0 && dx < 0)) { const t = a; a = b; b = t; dx = -dx; dy = -dy; }
        if (++pairs > o.maxPairs) return { ran: true, blocks: n, pairs, detected: false, patterned: true };
        const key = dx * 100003 + dy;
        let v = votes.get(key);
        if (!v) { v = { dx, dy, count: 0, minx: 1e9, maxx: -1, miny: 1e9, maxy: -1 }; votes.set(key, v); }
        v.count++;
        const bxa = a % nx; const bya = Math.floor(a / nx);
        if (bxa < v.minx) v.minx = bxa; if (bxa > v.maxx) v.maxx = bxa;
        if (bya < v.miny) v.miny = bya; if (bya > v.maxy) v.maxy = bya;
      }
    }
  }

  // Shifts within a few pixels of each other are the same copy (smooth content matches at
  // neighbouring offsets): merge them, then keep clusters that form a compact 2D blob. A real clone
  // is a filled patch; edge/line self-matches are thin, and wallpaper-like repetition produces many
  // compact clusters at once.
  const clusters = [];
  for (const v of [...votes.values()].sort((a, b) => b.count - a.count)) {
    const c = clusters.find((k) => Math.hypot(k.dx - v.dx, k.dy - v.dy) <= 3);
    if (!c) { clusters.push({ ...v }); continue; }
    c.count += v.count;
    c.minx = Math.min(c.minx, v.minx); c.maxx = Math.max(c.maxx, v.maxx);
    c.miny = Math.min(c.miny, v.miny); c.maxy = Math.max(c.maxy, v.maxy);
  }
  const ext = Math.ceil(o.minExtent / S);
  const compact = clusters.filter((c) => {
    const bw = c.maxx - c.minx + 1; const bh = c.maxy - c.miny + 1;
    c.fill = c.count / (bw * bh);
    return bw >= ext && bh >= ext && c.count >= o.minBlocks && c.fill >= o.minFill;
  }).sort((a, b) => b.count - a.count);
  const result = { ran: true, blocks: n, pairs, clusters: clusters.length, compact: compact.length, detected: false };
  if (o.debug) {
    result.top = clusters.sort((a, b) => b.count - a.count).slice(0, 5).map((c) => ({
      dx: c.dx, dy: c.dy, count: c.count, bw: c.maxx - c.minx + 1, bh: c.maxy - c.miny + 1, fill: +(c.count / ((c.maxx - c.minx + 1) * (c.maxy - c.miny + 1))).toFixed(2),
    }));
  }
  if (!compact.length) return result;
  if (compact.length > o.maxCompact) { result.patterned = true; return result; }
  const best = compact[0];
  const px = (v) => v * S;
  const src = { x0: px(best.minx) / w, y0: px(best.miny) / h, x1: Math.min(1, (px(best.maxx) + B) / w), y1: Math.min(1, (px(best.maxy) + B) / h) };
  Object.assign(result, {
    detected: true, vector: { dx: best.dx, dy: best.dy }, count: best.count, fill: best.fill, source: src,
    target: { x0: src.x0 + best.dx / w, y0: src.y0 + best.dy / h, x1: src.x1 + best.dx / w, y1: src.y1 + best.dy / h },
    areaFraction: (src.x1 - src.x0) * (src.y1 - src.y0),
  });
  return result;
}

