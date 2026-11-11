// Metadata parsing (EXIF, XMP, PNG text, C2PA presence) + provenance signals.
// Parsers never throw: on malformed input they return whatever they parsed so far.
import { latin1, utf8Text, u16, u32, clean } from './bytes.js';

// ------------------------------------------------------------------ TIFF / EXIF
const TAGS_IFD0 = {
  0x010e: 'ImageDescription', 0x010f: 'Make', 0x0110: 'Model', 0x0131: 'Software',
  0x0132: 'DateTime', 0x013b: 'Artist', 0x8298: 'Copyright',
};
const TAGS_EXIF = {
  0x9003: 'DateTimeOriginal', 0xa430: 'CameraOwnerName', 0xa431: 'BodySerialNumber',
  0xa434: 'LensModel', 0xa435: 'LensSerialNumber', 0x927c: 'MakerNote',
};
const TAGS_GPS = {
  1: 'GPSLatitudeRef', 2: 'GPSLatitude', 3: 'GPSLongitudeRef', 4: 'GPSLongitude', 6: 'GPSAltitude',
};
const TYPE_SIZE = { 1: 1, 2: 1, 3: 2, 4: 4, 5: 8, 7: 1, 9: 4, 10: 8 };

function readValue(u8, valPos, type, count, le) {
  const size = (TYPE_SIZE[type] || 0) * count;
  if (!size) return null;
  const pos = size <= 4 ? valPos : u32(u8, valPos, le);
  if (pos < 0 || pos + size > u8.length) return null;
  if (type === 2) return clean(latin1(u8, pos, pos + Math.min(size, 256)).split('\0')[0]);
  if (type === 7 && count > 8) return `${count} bytes`;
  const vals = [];
  for (let i = 0; i < Math.min(count, 8); i++) {
    if (type === 1 || type === 7) vals.push(u8[pos + i]);
    else if (type === 3) vals.push(u16(u8, pos + i * 2, le));
    else if (type === 4) vals.push(u32(u8, pos + i * 4, le));
    else if (type === 9) vals.push(u32(u8, pos + i * 4, le) | 0);
    else if (type === 5) {
      const d = u32(u8, pos + i * 8 + 4, le);
      vals.push(d ? u32(u8, pos + i * 8, le) / d : 0);
    } else if (type === 10) {
      const d = u32(u8, pos + i * 8 + 4, le) | 0;
      vals.push(d ? (u32(u8, pos + i * 8, le) | 0) / d : 0);
    }
  }
  return vals;
}

function readIfd(u8, off, le, names, out, pointers = {}) {
  const n = Math.min(u16(u8, off, le), 500);
  for (let i = 0; i < n; i++) {
    const e = off + 2 + i * 12;
    if (e + 12 > u8.length) break;
    const tag = u16(u8, e, le);
    const type = u16(u8, e + 2, le);
    const count = u32(u8, e + 4, le);
    if (tag === 0x8769) pointers.exif = u32(u8, e + 8, le);
    if (tag === 0x8825) pointers.gps = u32(u8, e + 8, le);
    const name = names[tag];
    if (name) out[name] = readValue(u8, e + 8, type, count, le);
  }
}

const dms = (a) => (Array.isArray(a) && a.length >= 3 ? a[0] + a[1] / 60 + a[2] / 3600 : null);

export function parseTiff(u8) {
  const out = {};
  try {
    const bo = latin1(u8, 0, 2);
    const le = bo === 'II';
    if (!le && bo !== 'MM') return out;
    if (u16(u8, 2, le) !== 42) return out;
    const pointers = {};
    readIfd(u8, u32(u8, 4, le), le, TAGS_IFD0, out, pointers);
    if (pointers.exif) readIfd(u8, pointers.exif, le, TAGS_EXIF, out);
    if (pointers.gps) {
      const g = {};
      readIfd(u8, pointers.gps, le, TAGS_GPS, g);
      const lat = dms(g.GPSLatitude);
      const lon = dms(g.GPSLongitude);
      if (lat !== null && lon !== null && Number.isFinite(lat) && Number.isFinite(lon)
          && !(lat === 0 && lon === 0)) {
        out.gps = {
          lat: (g.GPSLatitudeRef === 'S' ? -1 : 1) * lat,
          lon: (g.GPSLongitudeRef === 'W' ? -1 : 1) * lon,
          alt: Array.isArray(g.GPSAltitude) ? g.GPSAltitude[0] : undefined,
        };
      }
    }
  } catch { /* partial result */ }
  return out;
}

// ------------------------------------------------------------------ JPEG
// EXIF "preview thumbnail": a small JPEG stored in the second IFD (tags 0x0201 offset, 0x0202 length).
// Returns the thumbnail's JPEG bytes or null. `tiff` is the TIFF block (starting at 'II'/'MM').
export function exifThumbnail(tiff) {
  try {
    const bo = latin1(tiff, 0, 2);
    const le = bo === 'II';
    if (!le && bo !== 'MM') return null;
    if (u16(tiff, 2, le) !== 42) return null;
    const ifd0 = u32(tiff, 4, le);
    const n0 = Math.min(u16(tiff, ifd0, le), 500);
    const ifd1 = u32(tiff, ifd0 + 2 + n0 * 12, le);
    if (!ifd1) return null;
    const n1 = Math.min(u16(tiff, ifd1, le), 500);
    let off = null;
    let len = null;
    for (let i = 0; i < n1; i++) {
      const e = ifd1 + 2 + i * 12;
      const tag = u16(tiff, e, le);
      if (tag === 0x0201) off = u32(tiff, e + 8, le);
      else if (tag === 0x0202) len = u32(tiff, e + 8, le);
    }
    if (off === null || len === null || len < 100 || len > 262144 || off + len > tiff.length) return null;
    const t = tiff.subarray(off, off + len);
    return t[0] === 0xff && t[1] === 0xd8 ? t : null;
  } catch {
    return null;
  }
}

export function parseJpegMeta(u8) {
  const r = { exif: {}, xmp: null, c2pa: false, c2paText: '', comments: [], thumbnail: null };
  try {
    let i = 2;
    while (i + 4 <= u8.length) {
      if (u8[i] !== 0xff) break;
      const m = u8[i + 1];
      if (m === 0xff) { i++; continue; }
      if (m === 0xd8 || m === 0x01 || (m >= 0xd0 && m <= 0xd7)) { i += 2; continue; }
      if (m === 0xd9 || m === 0xda) break;
      const len = u16(u8, i + 2);
      if (len < 2) break;
      const s = i + 4;
      const e = Math.min(i + 2 + len, u8.length);
      if (m === 0xe1) {
        if (latin1(u8, s, s + 6) === 'Exif\0\0') {
          Object.assign(r.exif, parseTiff(u8.subarray(s + 6, e)));
          r.thumbnail = r.thumbnail || exifThumbnail(u8.subarray(s + 6, e));
        } else if (latin1(u8, s, s + 28) === 'http://ns.adobe.com/xap/1.0/') {
          r.xmp = utf8Text(u8, s + 29, e).slice(0, 200000);
        }
      } else if (m === 0xeb) {
        const head = latin1(u8, s, Math.min(e, s + 2048));
        if (head.includes('jumb') || head.includes('c2pa')) {
          r.c2pa = true;
          if (r.c2paText.length < 262144) r.c2paText += latin1(u8, s, e);
        }
      } else if (m === 0xfe) {
        r.comments.push(clean(latin1(u8, s, e), 500));
      }
      i += 2 + len;
    }
  } catch { /* partial result */ }
  return r;
}

// ------------------------------------------------------------------ PNG
export function parsePngMeta(u8) {
  const r = { text: {}, exif: {}, xmp: null, c2pa: false, c2paText: '' };
  try {
    let pos = 8;
    let n = 0;
    while (pos + 12 <= u8.length && n++ < 10000) {
      const len = u32(u8, pos);
      const type = latin1(u8, pos + 4, pos + 8);
      const s = pos + 8;
      const e = Math.min(s + len, u8.length);
      const body = u8.subarray(s, e);
      if (type === 'tEXt') {
        const z = body.indexOf(0);
        if (z > 0) r.text[clean(latin1(body, 0, z), 80)] = latin1(body, z + 1).slice(0, 20000);
      } else if (type === 'iTXt') {
        const z = body.indexOf(0);
        if (z > 0 && z + 3 < body.length) {
          const key = clean(latin1(body, 0, z), 80);
          const compressed = body[z + 1] === 1;
          const l = body.indexOf(0, z + 3);
          const t = l === -1 ? -1 : body.indexOf(0, l + 1);
          if (!compressed && t !== -1) {
            const text = utf8Text(body, t + 1).slice(0, 200000);
            if (key === 'XML:com.adobe.xmp') r.xmp = text;
            else r.text[key] = text.slice(0, 20000);
          }
        }
      } else if (type === 'eXIf') {
        Object.assign(r.exif, parseTiff(body));
      } else if (type === 'caBX') {
        r.c2pa = true;
        r.c2paText += latin1(body, 0, 262144);
      }
      if (type === 'IEND') break;
      pos += 12 + len;
    }
  } catch { /* partial result */ }
  return r;
}

// ------------------------------------------------------------------ WebP (RIFF)
export function parseWebpMeta(u8) {
  const r = { exif: {}, xmp: null, c2pa: false, c2paText: '', comments: [], thumbnail: null };
  try {
    const end = Math.min(u8.length, 8 + u32(u8, 4, true));
    let pos = 12;
    let n = 0;
    while (pos + 8 <= end && n++ < 10000) {
      const type = latin1(u8, pos, pos + 4);
      const len = u32(u8, pos + 4, true);
      const s = pos + 8;
      const e = Math.min(s + len, end);
      const body = u8.subarray(s, e);
      if (type === 'EXIF') {
        const t = latin1(body, 0, 6) === 'Exif\0\0' ? body.subarray(6) : body;
        Object.assign(r.exif, parseTiff(t));
        r.thumbnail = r.thumbnail || exifThumbnail(t);
      } else if (type === 'XMP ') {
        r.xmp = utf8Text(body, 0).slice(0, 200000);
      } else if (type === 'C2PA') {
        r.c2pa = true;
        r.c2paText += latin1(body, 0, 262144);
      }
      pos = s + len + (len & 1); // chunks are padded to even length
    }
  } catch { /* partial result */ }
  return r;
}

// ------------------------------------------------------------------ ISO-BMFF (HEIC / AVIF)
const C2PA_UUID = 'd8fec3d61b0e483c92975828877ec481';
function isoBoxes(u8, start, end) {
  const out = [];
  let pos = start;
  while (pos + 8 <= end && out.length < 5000) {
    let size = u32(u8, pos);
    const type = latin1(u8, pos + 4, pos + 8);
    let head = 8;
    if (size === 1) { // 64-bit size: refuse anything that does not fit comfortably in a double
      const hi = u32(u8, pos + 8);
      if (hi > 0xfffff) break;
      size = hi * 4294967296 + u32(u8, pos + 12);
      head = 16;
    } else if (size === 0) size = end - pos;
    if (size < head || pos + size > end) break;
    out.push({ type, start: pos + head, end: pos + size });
    pos += size;
  }
  return out;
}

export function parseIsoMeta(u8) {
  const r = { exif: {}, xmp: null, c2pa: false, c2paText: '', comments: [], thumbnail: null };
  try {
    const top = isoBoxes(u8, 0, u8.length);
    for (const b of top) {
      if (b.type === 'uuid' && b.end - b.start >= 16 && [...u8.subarray(b.start, b.start + 16)].map((x) => x.toString(16).padStart(2, '0')).join('') === C2PA_UUID) {
        r.c2pa = true;
        r.c2paText += latin1(u8, b.start + 16, Math.min(b.end, b.start + 16 + 262144));
      }
    }
    const meta = top.find((b) => b.type === 'meta');
    if (!meta) return r;
    const kids = isoBoxes(u8, meta.start + 4, meta.end); // meta is a "full box": 4 version/flags bytes first
    const iinf = kids.find((b) => b.type === 'iinf');
    const iloc = kids.find((b) => b.type === 'iloc');
    if (!iinf || !iloc) return r;

    // item id -> { type, mime }
    const items = new Map();
    const iv = u8[iinf.start];
    const countSize = iv === 0 ? 2 : 4;
    const entries = isoBoxes(u8, iinf.start + 4 + countSize, iinf.end);
    for (const e of entries) {
      if (e.type !== 'infe') continue;
      const v = u8[e.start];
      if (v < 2) continue;
      let p = e.start + 4;
      const id = v === 2 ? u16(u8, p) : u32(u8, p);
      p += v === 2 ? 2 : 4;
      p += 2; // protection index
      const type = latin1(u8, p, p + 4);
      p += 4;
      let mime = '';
      if (type === 'mime') {
        const z = u8.indexOf(0, p);
        const z2 = z === -1 ? -1 : u8.indexOf(0, z + 1);
        if (z2 !== -1 && z2 < e.end + 1) mime = latin1(u8, z + 1, Math.min(z2, e.end));
      }
      items.set(id, { type, mime });
    }

    const lv = u8[iloc.start];
    const sizes = u8[iloc.start + 4];
    const sizes2 = u8[iloc.start + 5];
    const offSize = sizes >> 4;
    const lenSize = sizes & 15;
    const baseSize = sizes2 >> 4;
    const idxSize = lv === 1 || lv === 2 ? sizes2 & 15 : 0;
    let p = iloc.start + 6;
    const rd = (n) => {
      if (n === 0) return 0;
      if (n !== 4 && n !== 8) throw new RangeError('unsupported field size');
      const v = n === 4 ? u32(u8, p) : u32(u8, p) * 4294967296 + u32(u8, p + 4);
      p += n;
      return v;
    };
    const count = lv < 2 ? (p += 2, u16(u8, p - 2)) : (p += 4, u32(u8, p - 4));
    for (let i = 0; i < count && i < 5000; i++) {
      const id = lv < 2 ? (p += 2, u16(u8, p - 2)) : (p += 4, u32(u8, p - 4));
      let method = 0;
      if (lv === 1 || lv === 2) { method = u16(u8, p) & 15; p += 2; }
      p += 2; // data reference index
      const base = rd(baseSize);
      const extents = u16(u8, p); p += 2;
      let first = null;
      for (let j = 0; j < extents && j < 64; j++) {
        if (idxSize) rd(idxSize);
        const off = rd(offSize);
        const len = rd(lenSize);
        if (j === 0) first = { off: base + off, len };
      }
      const item = items.get(id);
      if (!item || method !== 0 || !first || first.len === 0 || first.len > 4 * 1024 * 1024) continue;
      if (first.off + first.len > u8.length) continue;
      const data = u8.subarray(first.off, first.off + first.len);
      if (item.type === 'Exif' && data.length > 4) {
        const skip = u32(data, 0);
        let t = data.subarray(4 + Math.min(skip, data.length - 4));
        if (latin1(t, 0, 6) === 'Exif\0\0') t = t.subarray(6);
        Object.assign(r.exif, parseTiff(t));
      } else if (item.type === 'mime' && /xmp|rdf\+xml/i.test(item.mime)) {
        r.xmp = utf8Text(data, 0).slice(0, 200000);
      }
    }
  } catch { /* partial result */ }
  return r;
}

// ------------------------------------------------------------------ provenance
const GENERATOR_RE =
  /(midjourney|dall[\s·.\-]{0,3}e\b|stable[\s_-]*diffusion|comfyui|automatic1111|novelai|adobe firefly|\bfirefly\b|openai|invokeai|leonardo\.ai|\bimagen\b|\bgemini\b)/i;
const EDITOR_RE =
  /(photoshop|lightroom|gimp|affinity|canva|picsart|facetune|snapseed|pixelmator|paint\.net|capture one)/i;

const SOURCE_TYPES = {
  trainedalgorithmicmedia: ['ai', 'Labelled AI-generated (IPTC digital source type: trained algorithmic media)'],
  compositewithtrainedalgorithmicmedia: ['ai-partial', 'Labelled as a composite that includes AI-generated elements'],
  algorithmicmedia: ['ai', 'Labelled as algorithmically generated media'],
  compositesynthetic: ['ai-partial', 'Labelled as a composite with synthetic elements'],
  digitalcapture: ['camera', 'Labelled as a digital camera capture'],
  computationalcapture: ['camera', 'Labelled as a computational (phone camera) capture'],
  digitalart: ['info', 'Labelled as digital art'],
};

export function provenance(parsed, c2pa = null) {
  const findings = [];
  const strings = [];
  if (parsed.xmp) strings.push(parsed.xmp);
  if (parsed.c2paText) strings.push(parsed.c2paText);
  const text = parsed.text || {};
  for (const v of Object.values(text)) strings.push(v);

  let ai = null; // 'ai' | 'ai-partial'
  const markAi = (kind, msg) => {
    findings.push({ sev: 'warning', text: msg });
    if (kind === 'ai' || !ai) ai = kind;
  };

  // IPTC / C2PA "digital source type" labels
  const seen = new Set();
  for (const s of strings) {
    for (const m of s.matchAll(/digitalsourcetype\/([A-Za-z]+)/gi)) seen.add(m[1].toLowerCase());
  }
  let camera = false;
  for (const key of seen) {
    const entry = SOURCE_TYPES[key];
    if (!entry) continue;
    if (entry[0] === 'ai' || entry[0] === 'ai-partial') markAi(entry[0], entry[1]);
    else {
      findings.push({ sev: 'info', text: entry[1] });
      if (entry[0] === 'camera') camera = true;
    }
  }

  // Generator fingerprints left in PNG text chunks by common tools
  for (const [k, v] of Object.entries(text)) {
    const kl = k.toLowerCase();
    if (kl === 'parameters' && /steps:\s*\d+/i.test(v)) {
      markAi('ai', 'Contains Stable Diffusion-style generation settings (prompt, steps, sampler)');
    } else if ((kl === 'prompt' || kl === 'workflow') && /class_type|"nodes"/.test(v)) {
      markAi('ai', 'Contains an embedded ComfyUI workflow (AI image generation)');
    } else if (kl === 'sd-metadata' || kl === 'invokeai_metadata' || kl === 'dream') {
      markAi('ai', 'Contains InvokeAI generation metadata');
    } else if (kl === 'comment' && /"steps"\s*:\s*\d+/.test(v) && /"sampler"/.test(v)) {
      markAi('ai', 'Contains NovelAI-style generation settings');
    } else if (kl === 'software' && GENERATOR_RE.test(v)) {
      markAi('ai', `Software field names an AI generator: ${clean(v, 60)}`);
    }
  }

  // Software / creator tool
  const xmpTool = parsed.xmp ? (parsed.xmp.match(/xmp:CreatorTool(?:>|=")([^<"]{1,120})/i) || [])[1] : null;
  const software = [parsed.exif && parsed.exif.Software, xmpTool].filter(Boolean).map((s) => clean(s, 60));
  const editing = [];
  for (const sw of software) {
    if (GENERATOR_RE.test(sw)) markAi('ai', `Software field names an AI generator: ${sw}`);
    else if (EDITOR_RE.test(sw)) editing.push(sw);
  }
  if (parsed.xmp && /stEvt:action/i.test(parsed.xmp) && !editing.length) {
    findings.push({ sev: 'info', text: 'XMP contains an edit history (the file was saved by editing software)' });
  }

  // C2PA Content Credentials
  const verified = !!(c2pa && c2pa.found);
  if (verified) {
    findings.push(...c2pa.findings.map((f) => ({ ...f, c2pa: true })));
    if (c2pa.ai && !ai) ai = 'ai';
  } else if (parsed.c2pa) {
    findings.push({
      sev: 'notice',
      text: 'Contains C2PA Content Credentials (a signed provenance record). This tool detects them but does NOT verify the signature; check the file at contentcredentials.org/verify.',
    });
    const gen = parsed.c2paText.match(GENERATOR_RE);
    if (gen) markAi('ai', `Content Credentials mention an AI generator: ${clean(gen[0], 40)}`);
  }

  const ex = parsed.exif || {};
  if (ex.Make || ex.Model) {
    camera = true;
    findings.push({
      sev: 'info',
      text: `Camera metadata present (${clean([ex.Make, ex.Model].filter(Boolean).join(' '), 60)}). Consistent with a camera photo, but metadata is easy to copy or forge.`,
    });
  }
  for (const sw of editing) findings.push({ sev: 'notice', text: `Saved or edited with: ${sw}` });

  let level = 'unknown';
  let headline = 'No provenance data. This does not mean the image is real or fake.';
  if (verified && c2pa.status === 'invalid') { level = 'alert'; headline = c2pa.headline; }
  else if (ai === 'ai' && verified && c2pa.ai && c2pa.status === 'valid') {
    level = 'warning'; headline = 'Signed Content Credentials say this image is AI-generated';
  }
  else if (ai === 'ai') { level = 'warning'; headline = 'Labelled as AI-generated by its own metadata'; }
  else if (ai === 'ai-partial') { level = 'warning'; headline = 'Labelled as containing AI-generated elements'; }
  else if (verified) { level = c2pa.level; headline = c2pa.headline; }
  else if (parsed.c2pa) { level = 'notice'; headline = 'Has Content Credentials (signature not verified here)'; }
  else if (editing.length) { level = 'notice'; headline = `Edited with ${editing[0]}`; }
  else if (camera) { level = 'notice'; headline = 'Carries camera metadata (can be forged)'; }

  return { findings, level, headline, ai: !!ai, credentials: !!parsed.c2pa || verified, editing };
}
