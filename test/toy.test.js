'use strict';
// Empirical test of the repo's central claim: client-side tricks raise the cost, they do not make
// secrets unrecoverable. Builds one toy program several ways and attacks each with real tools.
// macOS (arm64) + clang + lldb only; skipped elsewhere.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const { scan } = require('../src/scan');

const has = (cmd) => spawnSync('which', [cmd]).status === 0;
const runnable = process.platform === 'darwin' && process.arch === 'arm64' && has('cc') && has('strip') && has('nm');
const lldbOk = runnable && has('lldb') && !process.env.CI; // debugger attach is usually blocked on CI runners
const opts = { skip: !runnable && 'needs macOS arm64 + clang' };

const SRC = path.join(__dirname, '..', 'examples', 'toy', 'toy.c');
const SECRET = 'sk_live_TOYSECRET_DO_NOT_USE_1234567890';
const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'rp-toy-'));
const xorBlob = [...Buffer.from(SECRET)].map((b) => b ^ 0x5a).join(',');

function build(name, flags, { strip = false } = {}) {
  const out = path.join(dir, name);
  const r = spawnSync('cc', ['-O2', ...flags, '-o', out, SRC], { encoding: 'utf8' });
  assert.equal(r.status, 0, r.stderr);
  if (strip) assert.equal(spawnSync('strip', [out]).status, 0);
  return out;
}

// --- attacker tooling -------------------------------------------------------------------
const bytes = (f) => fs.readFileSync(f);
const strings = (f) => bytes(f).toString('latin1');
const symbols = (f) => spawnSync('nm', ['-a', f], { encoding: 'utf8' }).stdout;
// Known-prefix crib: try every single-byte XOR key against the bytes, looking for 'sk_live_'.
function xorCrib(f) {
  const buf = bytes(f);
  const needle = Buffer.from('sk_live_');
  for (let k = 1; k < 256; k++) {
    const enc = Buffer.from(needle.map((b) => b ^ k));
    const i = buf.indexOf(enc);
    if (i >= 0) return Buffer.from(buf.subarray(i, i + SECRET.length).map((b) => b ^ k)).toString();
  }
  return null;
}
// Attacker script: stop at the first printf (after the app decoded its secret into a stack buffer)
// and search the caller's stack for the plaintext. Optionally skip the ptrace(PT_DENY_ATTACH) call.
const FOUND = /data found at location/;
function lldbDump(f, { bypassPtrace = false } = {}) {
  const script = [
    ...(bypassPtrace ? ['breakpoint set -n ptrace', 'run', 'thread return 0', 'breakpoint set -n printf', 'continue'] : ['breakpoint set -n printf', 'run']),
    'memory find -s "sk_live" -- $sp `$sp+4096`',
    'kill',
    'quit',
  ];
  const file = path.join(dir, 'cmds.txt');
  fs.writeFileSync(file, script.join('\n'));
  const r = spawnSync('lldb', ['-b', '-s', file, f], { encoding: 'utf8', timeout: 60000 });
  return r.stdout + r.stderr;
}

test('A. plain build: strings, symbols and the scanner all see everything', opts, () => {
  const bin = build('plain', []);
  assert.ok(strings(bin).includes(SECRET));
  assert.ok(strings(bin).includes('LICENSE-ABCD-1234'));
  assert.match(symbols(bin), /_check_license/);
  assert.ok(scan(bin).some((f) => f.id === 'binary-secret:stripe-live-key'));
});

test('B. stripped: function names go away, but the secret string is still there', opts, () => {
  const bin = build('stripped', [], { strip: true });
  assert.doesNotMatch(symbols(bin), /_check_license/);
  assert.ok(strings(bin).includes(SECRET), 'stripping does not hide data');
});

test('C. XOR-obfuscated + stripped: beats `strings`, loses to a 1-line crib', opts, () => {
  const bin = build('xor', ['-DXOR_KEY=0x5A', `-DXOR_BLOB=${xorBlob}`], { strip: true });
  assert.ok(!strings(bin).includes('sk_live_'), '`strings` finds nothing');
  assert.ok(!scan(bin).some((f) => f.id.startsWith('binary-secret')), 'static string scan finds nothing');
  assert.equal(xorCrib(bin), SECRET, 'single-byte XOR crib recovers it instantly');
});

test('D. XOR build is recovered from process memory by a debugger', { skip: opts.skip || (!lldbOk && 'needs lldb (skipped on CI)') }, () => {
  const bin = build('xor-dbg', ['-DXOR_KEY=0x5A', `-DXOR_BLOB=${xorBlob}`], { strip: true });
  assert.match(lldbDump(bin), FOUND);
});

test('E. PT_DENY_ATTACH stops the plain debugger run...', { skip: opts.skip || (!lldbOk && 'needs lldb (skipped on CI)') }, () => {
  const bin = build('deny', ['-DDENY_ATTACH', '-DXOR_KEY=0x5A', `-DXOR_BLOB=${xorBlob}`], { strip: true });
  const out = lldbDump(bin);
  assert.doesNotMatch(out, FOUND);
  assert.match(out, /exited with status = 45/);
});

test('F. ...but skipping the ptrace call defeats it (anti-debug is a speed bump)', { skip: opts.skip || (!lldbOk && 'needs lldb (skipped on CI)') }, () => {
  const bin = path.join(dir, 'deny');
  assert.match(lldbDump(bin, { bypassPtrace: true }), FOUND);
});
