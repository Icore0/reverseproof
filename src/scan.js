'use strict';
// Static auditor: what would a reverse-engineering toolkit (REA, Ghidra, asar extract, strings) get from this artifact?
const fs = require('node:fs');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const { inspectPE, inspectELF } = require('./binary');

const SENTINEL = Buffer.from('dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX');
// Order of the Electron "V1" fuse wire (see @electron/fuses).
const FUSES_V1 = [
  'RunAsNode',
  'EnableCookieEncryption',
  'EnableNodeOptionsEnvironmentVariable',
  'EnableNodeCliInspectArguments',
  'EnableEmbeddedAsarIntegrityValidation',
  'OnlyLoadAppFromAsar',
  'LoadBrowserProcessSpecificV8Snapshot',
  'GrantFileProtocolExtraPrivileges',
];
const FUSE_RULES = {
  RunAsNode: { bad: 'on', sev: 'high', fix: 'Flip RunAsNode off: anyone can run your app as a plain node REPL (ELECTRON_RUN_AS_NODE).' },
  EnableNodeCliInspectArguments: { bad: 'on', sev: 'high', fix: 'Flip off: --inspect lets a debugger attach to the main process.' },
  EnableNodeOptionsEnvironmentVariable: { bad: 'on', sev: 'high', fix: 'Flip off: NODE_OPTIONS can inject code into the app.' },
  OnlyLoadAppFromAsar: { bad: 'off', sev: 'medium', fix: 'Flip on: stops an attacker dropping a loose app/ folder that overrides your code.' },
  EnableEmbeddedAsarIntegrityValidation: { bad: 'off', sev: 'medium', fix: 'Flip on: detects a modified app.asar.' },
  EnableCookieEncryption: { bad: 'off', sev: 'low', fix: 'Flip on: cookies are plaintext on disk otherwise.' },
  GrantFileProtocolExtraPrivileges: { bad: 'on', sev: 'low', fix: 'Flip off unless you load the UI from file://.' },
};

const SECRET_PATTERNS = [
  ['aws-access-key', /\bAKIA[0-9A-Z]{16}\b/],
  // A real PEM block has a base64 body; a bare marker is usually a string inside a crypto library.
  ['private-key', /-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----[A-Za-z0-9+/=\s\\]{60,}-----END/],
  ['github-token', /\bgh[pousr]_[A-Za-z0-9]{36,}\b/],
  ['slack-token', /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/],
  ['stripe-live-key', /\b[sr]k_live_[A-Za-z0-9_]{16,}\b/],
  ['openai-style-key', /\bsk-[A-Za-z0-9_-]{32,}\b/],
  ['google-api-key', /\bAIza[0-9A-Za-z_-]{35}\b/, 'medium'],
  ['generic-secret', /\b(?:api[_-]?key|secret|token|passwd|password)["']?\s*[:=]\s*["'][A-Za-z0-9_\-/+=]{20,}["']/i],
];
const TEXT_EXT = new Set(['.js', '.mjs', '.cjs', '.json', '.html', '.htm', '.yml', '.yaml', '.plist', '.txt', '.ts', '.py', '.rb', '.go', '.swift', '.xml', '.env', '.ini', '.cfg', '.toml', '.map']);

function finding(severity, id, file, message, fix) {
  return { severity, id, file, message, fix: fix || '' };
}

function mask(s) {
  return s.length <= 8 ? '***' : s.slice(0, 6) + '***';
}

// `exists(ref)` tells us whether a referenced sourcemap file is really shipped; a dangling
// `//# sourceMappingURL=` comment leaks nothing.
function scanText(label, text, out, exists = () => false) {
  for (const [name, re, sev] of SECRET_PATTERNS) {
    for (const m of text.matchAll(new RegExp(re.source, re.flags.includes('g') ? re.flags : re.flags + 'g'))) {
      if (/EXAMPLE|XXXX|your[_-]?key/i.test(m[0])) continue; // documented placeholders
      const publicByDesign = name === 'google-api-key';
      out.push(finding(sev || 'high', 'secret:' + name, label, `Looks like ${name}: ${mask(m[0])}${publicByDesign ? ' (Google web keys are public-by-design ONLY if restricted by referrer/bundle id)' : ''}`, 'Remove from the client; proxy the call through your server and rotate the credential.'));
      break;
    }
  }
  const sm = /\/\/[#@]\s*sourceMappingURL=(\S+)/.exec(text.slice(-2048));
  if (sm) {
    if (sm[1].startsWith('data:')) {
      out.push(finding('high', 'sourcemap-inline', label, 'Inline sourcemap embeds your original source in the shipped file.', 'Build with sourcemap: false (or "hidden" and keep the maps private).'));
    } else if (exists(sm[1])) {
      out.push(finding('high', 'sourcemap-shipped', label, `Sourcemap ${sm[1]} is shipped next to the code: original source is recoverable.`, 'Do not publish *.map files.'));
    }
  }
}

function* walk(root, { all = false, maxFiles = 200000 } = {}) {
  const stack = [root];
  let n = 0;
  while (stack.length) {
    const p = stack.pop();
    let st;
    try { st = fs.lstatSync(p); } catch { continue; }
    if (st.isSymbolicLink()) continue;
    if (st.isDirectory()) {
      const base = path.basename(p);
      if (!all && (base === 'node_modules' || base === '.git')) continue;
      let ents;
      try { ents = fs.readdirSync(p); } catch { continue; }
      for (const e of ents) stack.push(path.join(p, e));
    } else if (st.isFile()) {
      if (++n > maxFiles) return;
      yield { p, size: st.size };
    }
  }
}

// Chunked search so we never load a 300 MB framework into memory.
function findInFile(file, needle, { from = 0, chunk = 8 * 1024 * 1024 } = {}) {
  const fd = fs.openSync(file, 'r');
  try {
    const size = fs.fstatSync(fd).size;
    const buf = Buffer.alloc(chunk + needle.length);
    let pos = from;
    while (pos < size) {
      const n = fs.readSync(fd, buf, 0, buf.length, pos);
      if (n <= 0) break;
      const i = buf.subarray(0, n).indexOf(needle);
      if (i >= 0) return pos + i;
      if (pos + n >= size) break;
      pos += n - needle.length + 1;
    }
    return -1;
  } finally {
    fs.closeSync(fd);
  }
}

function readFuses(file) {
  let from = 0;
  for (let tries = 0; tries < 4; tries++) {
    const off = findInFile(file, SENTINEL, { from });
    if (off < 0) return null;
    const fd = fs.openSync(file, 'r');
    try {
      const head = Buffer.alloc(2);
      fs.readSync(fd, head, 0, 2, off + SENTINEL.length);
      const [version, len] = head;
      if (version === 1 && len > 0 && len <= 32) {
        const wire = Buffer.alloc(len);
        fs.readSync(fd, wire, 0, len, off + SENTINEL.length + 2);
        const fuses = {};
        for (let i = 0; i < len; i++) {
          const name = FUSES_V1[i] || `fuse#${i}`;
          fuses[name] = wire[i] === 0x31 ? 'on' : wire[i] === 0x30 ? 'off' : 'removed';
        }
        return { version, fuses };
      }
    } finally {
      fs.closeSync(fd);
    }
    from = off + 1;
  }
  return null;
}

function readAsarFiles(file) {
  const fd = fs.openSync(file, 'r');
  try {
    const sizeBuf = Buffer.alloc(8);
    fs.readSync(fd, sizeBuf, 0, 8, 0);
    const headerSize = sizeBuf.readUInt32LE(4);
    const headerBuf = Buffer.alloc(headerSize);
    fs.readSync(fd, headerBuf, 0, headerSize, 8);
    const jsonLen = headerBuf.readUInt32LE(4);
    const header = JSON.parse(headerBuf.subarray(8, 8 + jsonLen).toString('utf8'));
    const base = 8 + headerSize;
    const files = [];
    (function rec(node, prefix) {
      for (const [name, e] of Object.entries(node.files || {})) {
        const p = prefix ? `${prefix}/${name}` : name;
        if (e.files) rec(e, p);
        else if (!e.unpacked && !e.link) files.push({ p, size: e.size, offset: base + Number(e.offset) });
      }
    })(header, '');
    return { fd, files };
  } catch (err) {
    fs.closeSync(fd);
    throw err;
  }
}

function scanAsar(file, out) {
  let asar;
  try { asar = readAsarFiles(file); } catch (e) {
    out.push(finding('info', 'asar-unreadable', file, 'Could not parse ASAR: ' + e.message));
    return;
  }
  try {
    out.push(finding('info', 'asar-plain', file, `ASAR is a plain archive: ${asar.files.length} files extractable with 'npx asar extract'. It is packaging, not protection.`, 'Compile sensitive JS to bytecode (bytenode) and keep real logic on the server.'));
    const names = new Set(asar.files.map((f) => f.p));
    for (const f of asar.files) {
      const ext = path.extname(f.p).toLowerCase();
      if (ext === '.map') out.push(finding('high', 'sourcemap-file', `${file}!${f.p}`, 'Sourcemap shipped inside ASAR.', 'Exclude *.map from the build.'));
      if (!TEXT_EXT.has(ext) || f.size > 5 * 1024 * 1024 || f.size === 0) continue;
      const buf = Buffer.alloc(f.size);
      fs.readSync(asar.fd, buf, 0, f.size, f.offset);
      const dir = path.posix.dirname(f.p);
      scanText(`${file}!${f.p}`, buf.toString('utf8'), out, (ref) => names.has(path.posix.normalize(dir === '.' ? ref : `${dir}/${ref}`)));
    }
  } finally {
    fs.closeSync(asar.fd);
  }
}

function isMachO(file) {
  try {
    const fd = fs.openSync(file, 'r');
    const b = Buffer.alloc(4);
    fs.readSync(fd, b, 0, 4, 0);
    fs.closeSync(fd);
    const m = b.toString('hex');
    return m === 'cffaedfe' || m === 'cefaedfe' || m === 'bebafeca' || m === 'cafebabe' && fs.statSync(file).size > 4096 && !file.endsWith('.class');
  } catch { return false; }
}

function machoChecks(file, out) {
  if (process.platform !== 'darwin') return;
  // codesign prints its report on stderr, so merge both streams.
  const run = (cmd, args) => {
    const r = spawnSync(cmd, args, { encoding: 'utf8', maxBuffer: 64 * 1024 * 1024, timeout: 30000 });
    return (r.stdout || '') + (r.stderr || '');
  };
  const info = run('codesign', ['-dvv', file]);
  if (/code object is not signed/i.test(info)) {
    out.push(finding('high', 'macho-unsigned', file, 'Binary is not code-signed.', 'Sign and notarize; unsigned binaries can be patched freely.'));
  } else if (!/flags=0x[0-9a-f]+\([^)]*runtime/i.test(info)) {
    out.push(finding('high', 'macho-no-hardened-runtime', file, 'Hardened runtime is OFF: debuggers and dylib injection are not blocked by the OS.', 'codesign --options runtime (see templates/macos/sign-harden.sh).'));
  }
  const ent = run('codesign', ['-d', '--entitlements', ':-', file]);
  for (const k of ['com.apple.security.get-task-allow', 'com.apple.security.cs.disable-library-validation', 'com.apple.security.cs.allow-dyld-environment-variables', 'com.apple.security.cs.debugger']) {
    const re = new RegExp(`<key>${k.replace(/\./g, '\\.')}</key>\\s*<true/>`);
    if (re.test(ent)) out.push(finding('high', 'macho-entitlement', file, `Entitlement ${k} is enabled (weakens anti-attach / anti-injection).`, 'Remove it from the release entitlements.'));
  }
  const nm = run('nm', ['-a', file]);
  const syms = nm.split('\n').filter((l) => l.trim() && !/no symbols/i.test(l)).length;
  if (syms > 200) out.push(finding('medium', 'macho-symbols', file, `${syms} symbol-table entries present (function names help decompilers).`, 'Strip: strip -x, STRIP_STYLE=all, DEPLOYMENT_POSTPROCESSING=YES.'));
}

// What `strings` would show: printable runs >= 8 chars, scanned with the same secret patterns.
function binarySecrets(file, out) {
  const size = fs.statSync(file).size;
  if (size > 200 * 1024 * 1024) return;
  const buf = fs.readFileSync(file);
  const runs = [];
  let start = -1;
  for (let i = 0; i <= buf.length; i++) {
    const printable = i < buf.length && buf[i] >= 0x20 && buf[i] < 0x7f;
    if (printable && start < 0) start = i;
    else if (!printable && start >= 0) {
      if (i - start >= 8) runs.push(buf.toString('latin1', start, i));
      start = -1;
    }
  }
  const tmp = [];
  scanText(file, runs.join('\n'), tmp);
  for (const f of tmp) if (f.id.startsWith('secret:')) out.push({ ...f, id: 'binary-' + f.id, message: f.message + ' (visible with plain `strings`)' });
}

function langMarkers(file, out) {
  const size = fs.statSync(file).size;
  if (size > 400 * 1024 * 1024) return;
  if (findInFile(file, Buffer.from('\xff Go buildinf:', 'latin1')) >= 0) {
    out.push(finding('medium', 'go-buildinfo', file, 'Go build info present (module paths, dependency versions, build flags readable).', 'go build -trimpath -ldflags="-s -w"; consider garble.'));
  }
  if (findInFile(file, Buffer.from('.dep-v0')) >= 0) {
    out.push(finding('medium', 'rust-auditable', file, 'cargo-auditable dependency list embedded in binary.', 'Do not build release artifacts with cargo auditable if the dependency list is sensitive.'));
  }
  if (findInFile(file, Buffer.from('/rustc/')) >= 0) {
    out.push(finding('low', 'rust-paths', file, 'Rust compiler paths embedded (reveals toolchain and panic locations).', 'strip = true, panic = "abort", build with --remap-path-prefix.'));
  }
}

function scan(target, opts = {}) {
  const out = [];
  const root = path.resolve(target);
  if (!fs.existsSync(root)) throw new Error('No such path: ' + root);
  const stat = fs.statSync(root);
  const files = stat.isDirectory() ? [...walk(root, opts)] : [{ p: root, size: stat.size }];
  const machos = [];

  for (const { p, size } of files) {
    const ext = path.extname(p).toLowerCase();
    const base = path.basename(p);
    if (ext === '.map') out.push(finding('high', 'sourcemap-file', p, 'Sourcemap file shipped.', 'Do not publish *.map files.'));
    if (base === 'app.asar') scanAsar(p, out);
    else if (size < 5 * 1024 * 1024 && size > 0 && (TEXT_EXT.has(ext) || base.startsWith('.env'))) {
      try { scanText(p, fs.readFileSync(p, 'utf8'), out, (ref) => fs.existsSync(path.join(path.dirname(p), ref))); } catch { /* unreadable */ }
    }
    if (size > (opts.minBinarySize ?? 20 * 1024 * 1024) && (ext === '' || ['.exe', '.dll', '.so', '.dylib'].includes(ext))) {
      const f = readFuses(p);
      if (f) {
        out.push(finding('info', 'electron-fuses', p, 'Electron fuses: ' + Object.entries(f.fuses).map(([k, v]) => `${k}=${v}`).join(', ')));
        for (const [name, state] of Object.entries(f.fuses)) {
          const r = FUSE_RULES[name];
          if (r && state === r.bad) out.push(finding(r.sev, 'electron-fuse:' + name, p, `${name} is ${state}.`, r.fix));
        }
      }
    }
    // Only the app's own top-level plist, and only if it actually ships an app.asar.
    if ((ext === '' || ['.exe', '.dll', '.sys', '.node', '.so'].includes(ext)) && size >= 64 && size < 500 * 1024 * 1024) {
      let magic = '';
      try { const fd = fs.openSync(p, 'r'); const b = Buffer.alloc(4); fs.readSync(fd, b, 0, 4, 0); fs.closeSync(fd); magic = b.toString('hex'); } catch { /* unreadable */ }
      try {
        if (magic.startsWith('4d5a')) out.push(...(inspectPE(p)?.findings || []));
        else if (magic === '7f454c46') out.push(...(inspectELF(p, { hasMarker: (n) => findInFile(p, Buffer.from(n, 'latin1')) >= 0 })?.findings || []));
      } catch { /* truncated or malformed binary */ }
    }
    if (base === 'Info.plist' && /\.app\/Contents\/Info\.plist$/.test(p) && fs.existsSync(path.join(path.dirname(p), 'Resources', 'app.asar'))) {
      if (!fs.readFileSync(p, 'utf8').includes('ElectronAsarIntegrity')) {
        out.push(finding('medium', 'asar-integrity-missing', p, 'Info.plist has no ElectronAsarIntegrity entry: app.asar can be swapped undetected.', 'Package with @electron/packager / electron-builder ASAR integrity enabled.'));
      }
    }
    const underMacOS = p.includes('.app/Contents/MacOS/');
    if ((underMacOS || (!stat.isDirectory() && isMachO(p))) && isMachO(p)) machos.push(p);
  }
  for (const m of machos) {
    machoChecks(m, out);
    binarySecrets(m, out);
    langMarkers(m, out);
  }
  const order = { high: 0, medium: 1, low: 2, info: 3 };
  out.sort((a, b) => order[a.severity] - order[b.severity]);
  return out;
}

module.exports = { scan, readFuses, scanText, readAsarFiles, FUSES_V1 };
