// JUMBF (ISO 19566-5) box reader. Untrusted input: strict bounds; malformed data throws.
import { latin1, u32 } from './bytes.js';
import { hex } from './der.js';

export function readBox(u8, pos, limit = u8.length) {
  if (pos + 8 > limit) throw new Error('JUMBF truncated');
  const lbox = u32(u8, pos);
  const type = latin1(u8, pos + 4, pos + 8);
  let hdr = 8;
  let end;
  if (lbox === 1) {
    if (pos + 16 > limit) throw new Error('JUMBF truncated');
    if (u32(u8, pos + 8) !== 0) throw new Error('JUMBF box too large');
    end = pos + u32(u8, pos + 12);
    hdr = 16;
  } else if (lbox === 0) {
    end = limit;
  } else {
    end = pos + lbox;
  }
  if (end > limit || end < pos + hdr) throw new Error('JUMBF bad box length');
  return { type, start: pos, hdr, payload: pos + hdr, end };
}

export function readBoxes(u8, start, end) {
  const out = [];
  let p = start;
  while (p < end) {
    if (out.length > 20000) throw new Error('JUMBF too many boxes');
    const b = readBox(u8, p, end);
    out.push(b);
    p = b.end;
  }
  return out;
}

// A superbox ('jumb'): first child is the description box ('jumd'): uuid(16) toggles(1)
// [label\0] [id(4)] [signature(32)]; the remaining children are content boxes.
export function parseSuper(u8, box) {
  if (box.type !== 'jumb') throw new Error('expected JUMBF superbox');
  const kids = readBoxes(u8, box.payload, box.end);
  const d = kids[0];
  if (!d || d.type !== 'jumd') throw new Error('superbox without description');
  const dp = u8.subarray(d.payload, d.end);
  if (dp.length < 17) throw new Error('bad description box');
  const toggles = dp[16];
  let label = '';
  if (toggles & 0x02) {
    const z = dp.indexOf(0, 17);
    if (z === -1) throw new Error('unterminated label');
    label = new TextDecoder('utf-8').decode(dp.subarray(17, z));
  }
  return { box, uuid: hex(dp.subarray(0, 16)), label, children: kids.slice(1) };
}
