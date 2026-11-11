// File-type sniffing by magic bytes, dimensions, and "data hidden after the image ends".
import { u16, u32, startsWith, latin1 } from './bytes.js';

const PNG_SIG = [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a];
const MIME = {
  png: 'image/png', jpeg: 'image/jpeg', gif: 'image/gif', webp: 'image/webp', bmp: 'image/bmp',
  ico: 'image/x-icon', svg: 'image/svg+xml', avif: 'image/avif', heic: 'image/heic',
};
export const mimeFor = (type) => MIME[type] || null;

export function sniffType(u8) {
  if (startsWith(u8, PNG_SIG)) return 'png';
  if (startsWith(u8, [0xff, 0xd8, 0xff])) return 'jpeg';
  const head6 = latin1(u8, 0, 6);
  if (head6 === 'GIF87a' || head6 === 'GIF89a') return 'gif';
  if (latin1(u8, 0, 4) === 'RIFF' && latin1(u8, 8, 12) === 'WEBP') return 'webp';
  if (latin1(u8, 4, 8) === 'ftyp') {
    const brand = latin1(u8, 8, 12);
    if (brand === 'avif' || brand === 'avis') return 'avif';
    if (['heic', 'heix', 'mif1', 'msf1'].includes(brand)) return 'heic';
  }
  if (startsWith(u8, [0x42, 0x4d])) return 'bmp';
  if (startsWith(u8, [0, 0, 1, 0])) return 'ico';
  const text = latin1(u8, 0, 512).trimStart().toLowerCase();
  if (text.startsWith('<svg') || (text.startsWith('<?xml') && text.includes('<svg'))) return 'svg';
  if (['<!doctype html', '<html', '<script', '<head', '<body'].some((s) => text.startsWith(s))) {
    return 'html';
  }
  return 'unknown';
}

// ---------------------------------------------------------------- dimensions
export function dimensions(u8, type) {
  try {
    switch (type) {
      case 'png': return { w: u32(u8, 16), h: u32(u8, 20) };
      case 'gif': return { w: u16(u8, 6, true), h: u16(u8, 8, true) };
      case 'bmp': return { w: Math.abs(u32(u8, 18, true) | 0), h: Math.abs(u32(u8, 22, true) | 0) };
      case 'jpeg': return jpegDims(u8);
      case 'webp': return webpDims(u8);
      default: return null;
    }
  } catch {
    return null;
  }
}

function jpegDims(u8) {
  let i = 2;
  while (i + 4 <= u8.length) {
    if (u8[i] !== 0xff) { i++; continue; }
    const m = u8[i + 1];
    if (m === 0xff) { i++; continue; }
    if (m === 0xd8 || m === 0x01 || (m >= 0xd0 && m <= 0xd7)) { i += 2; continue; }
    if (m === 0xd9 || m === 0xda) break;
    const len = u16(u8, i + 2);
    if (len < 2) break;
    if (m >= 0xc0 && m <= 0xcf && m !== 0xc4 && m !== 0xc8 && m !== 0xcc) {
      return { h: u16(u8, i + 5), w: u16(u8, i + 7) };
    }
    i += 2 + len;
  }
  return null;
}

function webpDims(u8) {
  const fourcc = latin1(u8, 12, 16);
  if (fourcc === 'VP8 ') return { w: u16(u8, 26, true) & 0x3fff, h: u16(u8, 28, true) & 0x3fff };
  if (fourcc === 'VP8L') {
    const b = u32(u8, 21, true);
    return { w: (b & 0x3fff) + 1, h: ((b >> 14) & 0x3fff) + 1 };
  }
  if (fourcc === 'VP8X') {
    return {
      w: (u8[24] | (u8[25] << 8) | (u8[26] << 16)) + 1,
      h: (u8[27] | (u8[28] << 8) | (u8[29] << 16)) + 1,
    };
  }
  return null;
}

// ---------------------------------------------------------------- trailing data
function pngEnd(u8) {
  let pos = 8;
  while (pos + 12 <= u8.length) {
    const len = u32(u8, pos);
    const type = latin1(u8, pos + 4, pos + 8);
    pos += 12 + len;
    if (type === 'IEND') return pos <= u8.length ? pos : null;
  }
  return null;
}

function jpegEnd(u8) {
  let i = 2;
  while (i + 4 <= u8.length) {
    if (u8[i] !== 0xff) return null;
    const m = u8[i + 1];
    if (m === 0xff) { i++; continue; }
    if (m === 0xd8 || m === 0x01 || (m >= 0xd0 && m <= 0xd7)) { i += 2; continue; }
    if (m === 0xd9) return i + 2;
    const len = u16(u8, i + 2);
    if (len < 2) return null;
    if (m === 0xda) {
      // Entropy-coded data: FF D9 can only be the real end-of-image marker.
      for (let j = i + 2 + len; j + 1 < u8.length; j++) {
        if (u8[j] === 0xff && u8[j + 1] === 0xd9) return j + 2;
      }
      return null;
    }
    i += 2 + len;
  }
  return null;
}

function skipSubBlocks(u8, p) {
  while (p < u8.length) {
    const n = u8[p];
    p += 1 + n;
    if (n === 0) return p;
  }
  return u8.length + 1;
}

function gifEnd(u8) {
  let p = 13;
  const flags = u8[10];
  if (flags & 0x80) p += 3 * (1 << ((flags & 7) + 1));
  while (p < u8.length) {
    const b = u8[p];
    if (b === 0x3b) return p + 1;
    if (b === 0x21) {
      p = skipSubBlocks(u8, p + 2);
    } else if (b === 0x2c) {
      const f = u8[p + 9];
      p += 10;
      if (f & 0x80) p += 3 * (1 << ((f & 7) + 1));
      p = skipSubBlocks(u8, p + 1);
    } else {
      return null;
    }
  }
  return null;
}

const SIGNATURES = [
  ['<script', 'HTML/JavaScript', false], ['<?php', 'PHP code', false], ['<html', 'HTML page', false],
  ['PK\x03\x04', 'ZIP archive', false], ['%PDF', 'PDF document', false], ['Rar!', 'RAR archive', false],
  ['MZ', 'Windows executable', true], ['\x7fELF', 'Linux executable', true],
  ['#!/', 'shell script', true],
];

export function trailingData(u8, type) {
  let end = null;
  try {
    if (type === 'png') end = pngEnd(u8);
    else if (type === 'jpeg') end = jpegEnd(u8);
    else if (type === 'gif') end = gifEnd(u8);
  } catch { /* malformed: treat as unknown */ }
  if (end === null || end >= u8.length) return null;
  const rest = latin1(u8, end, Math.min(u8.length, end + 65536));
  const lower = rest.toLowerCase();
  const signatures = [];
  for (const [sig, label, atStart] of SIGNATURES) {
    const hay = sig.startsWith('<') ? lower : rest;
    const idx = hay.indexOf(sig.startsWith('<') ? sig.toLowerCase() : sig);
    if (idx !== -1 && (!atStart || idx === 0)) signatures.push(label);
  }
  return { offset: end, length: u8.length - end, signatures };
}

// ---------------------------------------------------------------- SVG
export function svgInfo(u8) {
  const s = latin1(u8, 0, Math.min(u8.length, 1 << 20)).toLowerCase();
  const active = [];
  if (s.includes('<script')) active.push('<script> element');
  if (/\son[a-z]+\s*=/.test(s)) active.push('event-handler attributes (onload=...)');
  if (s.includes('javascript:')) active.push('javascript: link');
  if (s.includes('<foreignobject')) active.push('<foreignObject> (embedded HTML)');
  const external = /(?:href|src)\s*=\s*["']\s*https?:\/\//.test(s) || /url\(\s*["']?https?:\/\//.test(s);
  return { active, external };
}
