'use strict';
// Header-level hardening checks for Windows PE and Linux ELF (64-bit little-endian), zero dependencies.
// Validated against real esbuild linux-x64 / win32-x64 binaries with llvm-objdump as ground truth.
const fs = require('node:fs');

function readAt(fd, pos, len) {
  const b = Buffer.alloc(len);
  const n = fs.readSync(fd, b, 0, len, pos);
  return n === len ? b : b.subarray(0, n);
}
const f = (severity, id, file, message, fix) => ({ severity, id, file, message, fix: fix || '' });

function inspectPE(file) {
  const out = [];
  const fd = fs.openSync(file, 'r');
  try {
    const dos = readAt(fd, 0, 64);
    if (dos.length < 64 || dos.toString('latin1', 0, 2) !== 'MZ') return null;
    const peOff = dos.readUInt32LE(0x3c);
    const hdr = readAt(fd, peOff, 24 + 240);
    if (hdr.length < 24 + 96 || hdr.toString('latin1', 0, 4) !== 'PE\0\0') return null;
    const optSize = hdr.readUInt16LE(20);
    const opt = 24;
    const magic = hdr.readUInt16LE(opt);
    if (magic !== 0x10b && magic !== 0x20b) return null;
    const plus = magic === 0x20b;
    const dll = hdr.readUInt16LE(opt + 70);
    const ddBase = opt + (plus ? 112 : 96);
    const nDirs = hdr.readUInt32LE(opt + (plus ? 108 : 92));
    const dir = (i) => (i < nDirs && ddBase + i * 8 + 8 <= hdr.length && ddBase + i * 8 + 8 <= opt + optSize
      ? { rva: hdr.readUInt32LE(ddBase + i * 8), size: hdr.readUInt32LE(ddBase + i * 8 + 4) } : { rva: 0, size: 0 });

    if (!(dll & 0x40)) out.push(f('high', 'pe-no-aslr', file, 'DYNAMIC_BASE (ASLR) is off: fixed load addresses make exploits and patching easier.', 'Link with /DYNAMICBASE.'));
    if (!(dll & 0x100)) out.push(f('high', 'pe-no-dep', file, 'NX_COMPAT (DEP) is off.', 'Link with /NXCOMPAT.'));
    if (plus && !(dll & 0x20)) out.push(f('low', 'pe-no-highentropy', file, 'HIGH_ENTROPY_VA is off.', 'Link with /HIGHENTROPYVA.'));
    if (!(dll & 0x4000)) out.push(f('low', 'pe-no-cfg', file, 'Control Flow Guard is off.', 'Compile with /guard:cf and link with /GUARD:CF.'));
    if (dir(4).size === 0) out.push(f('medium', 'pe-unsigned', file, 'No Authenticode signature: the binary can be modified and re-distributed without detection.', 'Sign with signtool and a trusted certificate.'));
    if (dir(6).size > 0) out.push(f('medium', 'pe-debug-info', file, 'Debug directory present (PDB path and build info leak).', 'Link with /DEBUG:NONE for release or strip the debug directory.'));
    if (dir(14).size > 0) out.push(f('medium', 'pe-managed', file, 'Managed .NET assembly: decompiles to near-original C# with free tools.', 'Use NativeAOT or a commercial obfuscator, and move secrets/logic server-side.'));
    return { format: 'PE', plus, dllCharacteristics: dll, findings: out };
  } finally {
    fs.closeSync(fd);
  }
}

function inspectELF(file, { hasMarker = () => false } = {}) {
  const out = [];
  const fd = fs.openSync(file, 'r');
  try {
    const h = readAt(fd, 0, 64);
    if (h.length < 64 || h.readUInt32BE(0) !== 0x7f454c46) return null;
    if (h[4] !== 2 || h[5] !== 1) return { format: 'ELF', findings: [f('info', 'elf-unsupported', file, '32-bit or big-endian ELF: hardening checks not implemented.')] };
    const type = h.readUInt16LE(16);
    const phoff = Number(h.readBigUInt64LE(32));
    const shoff = Number(h.readBigUInt64LE(40));
    const phentsize = h.readUInt16LE(54);
    const phnum = h.readUInt16LE(56);
    const shentsize = h.readUInt16LE(58);
    const shnum = h.readUInt16LE(60);
    if (type === 2) out.push(f('medium', 'elf-no-pie', file, 'Not position-independent (ET_EXEC): fixed addresses, no ASLR for the main image.', 'Build with -fPIE -pie (Go: -buildmode=pie).'));

    let stack = null, relro = false, dynamic = null;
    for (let i = 0; i < phnum; i++) {
      const p = readAt(fd, phoff + i * phentsize, 56);
      if (p.length < 56) break;
      const ptype = p.readUInt32LE(0), flags = p.readUInt32LE(4);
      if (ptype === 0x6474e551) stack = flags;
      else if (ptype === 0x6474e552) relro = true;
      else if (ptype === 2) dynamic = { off: Number(p.readBigUInt64LE(8)), size: Number(p.readBigUInt64LE(32)) };
    }
    if (stack === null || stack & 1) out.push(f('high', 'elf-exec-stack', file, 'Executable stack (or no PT_GNU_STACK): injected shellcode on the stack can run.', 'Link with -z noexecstack.'));
    if (!relro) out.push(f('medium', 'elf-no-relro', file, 'No RELRO: the GOT stays writable, easing hijacking.', 'Link with -Wl,-z,relro,-z,now.'));
    else if (dynamic) {
      let now = false;
      const d = readAt(fd, dynamic.off, Math.min(dynamic.size, 64 * 1024));
      for (let o = 0; o + 16 <= d.length; o += 16) {
        const tag = Number(d.readBigUInt64LE(o)), val = Number(d.readBigUInt64LE(o + 8));
        if (tag === 0) break;
        if (tag === 24 || (tag === 30 && val & 8) || (tag === 0x6ffffffb && val & 1)) now = true;
      }
      if (!now) out.push(f('low', 'elf-partial-relro', file, 'Partial RELRO only (lazy binding keeps the GOT writable).', 'Link with -z now.'));
    }
    if (shoff && shnum && shentsize >= 64) {
      for (let i = 0; i < shnum; i++) {
        const s = readAt(fd, shoff + i * shentsize, 8);
        if (s.length === 8 && s.readUInt32LE(4) === 2) {
          out.push(f('medium', 'elf-symbols', file, 'Symbol table (.symtab) present: function names help decompilers.', 'strip --strip-all, or link with -s.'));
          break;
        }
      }
    }
    if (!hasMarker('__stack_chk_fail') && !hasMarker('Go build') && !hasMarker('/rustc/') && !hasMarker('\xff Go buildinf:')) {
      out.push(f('low', 'elf-no-stack-canary', file, 'No stack protector reference found (C/C++ binary).', 'Compile with -fstack-protector-strong.'));
    }
    return { format: 'ELF', type, findings: out };
  } finally {
    fs.closeSync(fd);
  }
}

module.exports = { inspectPE, inspectELF };
