'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { inspectPE, inspectELF } = require('../src/binary');
const { scan } = require('../src/scan');

const tmp = () => fs.mkdtempSync(path.join(os.tmpdir(), 'rp-bin-'));
const ids = (r) => r.findings.map((x) => x.id).sort();

function makePE({ dll = 0x8160, security = 0, debug = 0, clr = 0 } = {}) {
  const b = Buffer.alloc(0x400);
  b.write('MZ', 0); b.writeUInt32LE(0x80, 0x3c);
  b.write('PE\0\0', 0x80);
  b.writeUInt16LE(0x8664, 0x84); b.writeUInt16LE(240, 0x80 + 20);
  const opt = 0x80 + 24;
  b.writeUInt16LE(0x20b, opt); b.writeUInt16LE(dll, opt + 70); b.writeUInt32LE(16, opt + 108);
  const dd = (i, size) => { b.writeUInt32LE(size ? 0x1000 : 0, opt + 112 + i * 8); b.writeUInt32LE(size, opt + 112 + i * 8 + 4); };
  dd(4, security); dd(6, debug); dd(14, clr);
  return b;
}

function makeELF({ type = 3, stackFlags = 6, relro = true, bindNow = true, symtab = false } = {}) {
  const b = Buffer.alloc(0x800);
  b.writeUInt32BE(0x7f454c46, 0); b[4] = 2; b[5] = 1;
  b.writeUInt16LE(type, 16); b.writeBigUInt64LE(64n, 32);
  b.writeUInt16LE(56, 54);
  const ph = [];
  if (stackFlags !== null) ph.push({ t: 0x6474e551, flags: stackFlags });
  if (relro) ph.push({ t: 0x6474e552, flags: 4 });
  ph.push({ t: 2, flags: 6, off: 0x200, size: 32 });
  b.writeUInt16LE(ph.length, 56);
  ph.forEach((p, i) => {
    const o = 64 + i * 56;
    b.writeUInt32LE(p.t, o); b.writeUInt32LE(p.flags, o + 4);
    if (p.off) { b.writeBigUInt64LE(BigInt(p.off), o + 8); b.writeBigUInt64LE(BigInt(p.size), o + 32); }
  });
  // .dynamic: optional DT_BIND_NOW then DT_NULL
  if (bindNow) b.writeBigUInt64LE(24n, 0x200);
  if (symtab) { b.writeBigUInt64LE(0x600n, 40); b.writeUInt16LE(64, 58); b.writeUInt16LE(1, 60); b.writeUInt32LE(2, 0x600 + 4); }
  return b;
}

test('PE: well-hardened but unsigned build only flags the signature', () => {
  const d = tmp(); const f = path.join(d, 'a.exe'); fs.writeFileSync(f, makePE({ dll: 0xc160 }));
  assert.deepEqual(ids(inspectPE(f)), ['pe-unsigned']);
});

test('PE: matches the real esbuild win32-x64 profile (0x8160: no CFG, unsigned)', () => {
  const d = tmp(); const f = path.join(d, 'esbuild.exe'); fs.writeFileSync(f, makePE({ dll: 0x8160 }));
  assert.deepEqual(ids(inspectPE(f)), ['pe-no-cfg', 'pe-unsigned']);
});

test('PE: no ASLR/DEP are HIGH; debug dir and managed assembly are flagged; signed passes', () => {
  const d = tmp(); const f = path.join(d, 'b.dll'); fs.writeFileSync(f, makePE({ dll: 0x0, security: 100, debug: 28, clr: 72 }));
  const r = ids(inspectPE(f));
  for (const id of ['pe-no-aslr', 'pe-no-dep', 'pe-debug-info', 'pe-managed']) assert.ok(r.includes(id), id);
  assert.ok(!r.includes('pe-unsigned'));
});

test('ELF: hardened PIE with full RELRO and canary has no findings', () => {
  const d = tmp(); const f = path.join(d, 'good'); fs.writeFileSync(f, makeELF());
  assert.deepEqual(ids(inspectELF(f, { hasMarker: (n) => n === '__stack_chk_fail' })), []);
});

test('ELF: matches the real esbuild linux-x64 profile (static Go: no-pie, no-relro)', () => {
  const d = tmp(); const f = path.join(d, 'esbuild'); fs.writeFileSync(f, makeELF({ type: 2, relro: false, bindNow: false }));
  assert.deepEqual(ids(inspectELF(f, { hasMarker: (n) => n === 'Go build' })), ['elf-no-pie', 'elf-no-relro']);
});

test('ELF: executable stack is HIGH, partial RELRO and symbols and missing canary are flagged', () => {
  const d = tmp(); const f = path.join(d, 'bad'); fs.writeFileSync(f, makeELF({ stackFlags: 7, bindNow: false, symtab: true }));
  const r = ids(inspectELF(f));
  for (const id of ['elf-exec-stack', 'elf-partial-relro', 'elf-symbols', 'elf-no-stack-canary']) assert.ok(r.includes(id), id);
});

test('scanner dispatches PE and ELF by magic bytes, ignoring extension-less non-binaries', () => {
  const d = tmp();
  fs.writeFileSync(path.join(d, 'tool.exe'), makePE({ dll: 0 }));
  fs.writeFileSync(path.join(d, 'daemon'), makeELF({ stackFlags: 7 }));
  fs.writeFileSync(path.join(d, 'LICENSE'), 'MIT license text '.repeat(10));
  const f = scan(d).map((x) => x.id);
  assert.ok(f.includes('pe-no-aslr') && f.includes('elf-exec-stack'));
});

test('truncated or malformed binaries do not crash the scanner', () => {
  const d = tmp();
  fs.writeFileSync(path.join(d, 'broken.exe'), Buffer.from('MZ' + 'x'.repeat(100)));
  fs.writeFileSync(path.join(d, 'broken'), Buffer.concat([Buffer.from([0x7f, 0x45, 0x4c, 0x46, 2, 1]), Buffer.alloc(100)]));
  assert.doesNotThrow(() => scan(d));
});
