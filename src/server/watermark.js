'use strict';
// Per-recipient text watermark using invisible characters. Identifies WHICH account leaked a
// copy of text served to them. It is trivially stripped by someone who knows to look
// (see docs/VERDICT.md): it catches careless leaks, not careful ones.
const ZERO = '​';
const ONE = '‌';
const MARK = '⁠';

const crc8 = (bytes) => {
  let c = 0;
  for (const b of bytes) {
    c ^= b;
    for (let i = 0; i < 8; i++) c = c & 0x80 ? ((c << 1) ^ 0x07) & 0xff : (c << 1) & 0xff;
  }
  return c;
};

function encode(id) {
  const data = [...Buffer.from(String(id), 'utf8')];
  if (data.length > 255) throw new Error('id too long');
  const frame = [data.length, ...data, crc8(data)];
  let bits = '';
  for (const b of frame) bits += b.toString(2).padStart(8, '0');
  return MARK + [...bits].map((x) => (x === '1' ? ONE : ZERO)).join('') + MARK;
}

function decodeAt(text, start) {
  const end = text.indexOf(MARK, start + 1);
  if (end < 0) return null;
  const bits = [...text.slice(start + 1, end)].map((c) => (c === ONE ? '1' : c === ZERO ? '0' : null));
  if (bits.includes(null) || bits.length % 8 !== 0 || bits.length < 16) return null;
  const bytes = [];
  for (let i = 0; i < bits.length; i += 8) bytes.push(parseInt(bits.slice(i, i + 8).join(''), 2));
  const len = bytes[0];
  if (bytes.length !== len + 2) return null;
  const data = bytes.slice(1, 1 + len);
  if (crc8(data) !== bytes[1 + len]) return null;
  return Buffer.from(data).toString('utf8');
}

// Embeds the mark after every sentence end so copying a fragment still carries it.
function embed(text, id) {
  const mark = encode(id);
  let n = 0;
  const out = text.replace(/([.!?])(\s)/g, (_, p, s) => { n++; return p + mark + s; });
  return n ? out : text + mark;
}

function extract(text) {
  for (let i = text.indexOf(MARK); i >= 0; i = text.indexOf(MARK, i + 1)) {
    const id = decodeAt(text, i);
    if (id !== null) return id;
  }
  return null;
}

const strip = (text) => text.replace(/[​‌⁠]/g, '');

module.exports = { embed, extract, strip };
