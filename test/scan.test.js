'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { scan, readFuses, readAsarFiles } = require('../src/scan');

const tmp = () => fs.mkdtempSync(path.join(os.tmpdir(), 'rp-'));
const ids = (f) => f.map((x) => x.id);

// Build a minimal valid ASAR (same on-disk format Electron reads).
function makeAsar(file, files) {
  const header = { files: {} };
  let offset = 0;
  const bodies = [];
  for (const [name, content] of Object.entries(files)) {
    const buf = Buffer.from(content);
    header.files[name] = { size: buf.length, offset: String(offset) };
    offset += buf.length;
    bodies.push(buf);
  }
  const json = Buffer.from(JSON.stringify(header));
  const padded = Math.ceil(json.length / 4) * 4;
  const headerBuf = Buffer.alloc(8 + padded);
  headerBuf.writeUInt32LE(4 + padded, 0); // pickle payload size
  headerBuf.writeUInt32LE(json.length, 4);
  json.copy(headerBuf, 8);
  const top = Buffer.alloc(8);
  top.writeUInt32LE(4, 0);
  top.writeUInt32LE(headerBuf.length, 4);
  fs.writeFileSync(file, Buffer.concat([top, headerBuf, ...bodies]));
}

// Fake Electron binary with a fuse wire: sentinel, version 1, length, states.
function makeFuseBinary(file, states) {
  const wire = Buffer.from(states);
  fs.writeFileSync(file, Buffer.concat([Buffer.alloc(1000, 7), Buffer.from('dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX'), Buffer.from([1, wire.length]), wire, Buffer.alloc(500, 9)]));
}

test('flags AWS/Stripe-style secrets but ignores documented placeholders', () => {
  const d = tmp();
  fs.writeFileSync(path.join(d, 'a.js'), 'const k = "sk_live_' + 'A1b2C3d4E5f6G7h8I9j0K1l2";');
  fs.writeFileSync(path.join(d, 'b.js'), 'const aws = "AKIAIOSFODNN7EXAMPLE";');
  const f = scan(d);
  assert.ok(ids(f).includes('secret:stripe-live-key'));
  assert.ok(!ids(f).includes('secret:aws-access-key'), 'EXAMPLE key must not be flagged');
});

test('bare PEM marker in a library string is not a leak; a real PEM block is', () => {
  const d = tmp();
  fs.writeFileSync(path.join(d, 'lib.js'), 'if (s.startsWith("-----BEGIN PRIVATE KEY-----")) parse(s)');
  assert.ok(!ids(scan(d)).includes('secret:private-key'));
  fs.writeFileSync(path.join(d, 'k.js'), '-----BEGIN PRIVATE KEY-----\n' + 'A'.repeat(120) + '\n-----END PRIVATE KEY-----');
  assert.ok(ids(scan(d)).includes('secret:private-key'));
});

test('sourcemaps: dangling comment is ignored, shipped .map and inline map are high', () => {
  const d = tmp();
  fs.writeFileSync(path.join(d, 'dangling.js'), 'x()\n//# sourceMappingURL=nope.js.map');
  assert.ok(!ids(scan(d)).some((i) => i.startsWith('sourcemap-') && i !== 'sourcemap-file'));
  fs.writeFileSync(path.join(d, 'app.js'), 'x()\n//# sourceMappingURL=app.js.map');
  fs.writeFileSync(path.join(d, 'app.js.map'), '{}');
  const f = ids(scan(d));
  assert.ok(f.includes('sourcemap-shipped') && f.includes('sourcemap-file'));
  fs.writeFileSync(path.join(d, 'inline.js'), 'x()\n//# sourceMappingURL=data:application/json;base64,e30=');
  assert.ok(ids(scan(d)).includes('sourcemap-inline'));
});

test('reads Electron fuses and flags dangerous ones', () => {
  const d = tmp();
  const bin = path.join(d, 'Electron Framework');
  // RunAsNode=on, Cookie=on, NodeOptions=off, CliInspect=on, AsarIntegrity=off, OnlyLoadFromAsar=on, V8Snap=off, FileProto=off
  makeFuseBinary(bin, '11010 1 00'.replace(/ /g, '').split('').map((c) => c.charCodeAt(0)));
  const fuses = readFuses(bin).fuses;
  assert.equal(fuses.RunAsNode, 'on');
  assert.equal(fuses.EnableNodeOptionsEnvironmentVariable, 'off');
  assert.equal(fuses.EnableNodeCliInspectArguments, 'on');
  const f = scan(d, { minBinarySize: 0 });
  assert.ok(ids(f).includes('electron-fuse:RunAsNode'));
  assert.ok(ids(f).includes('electron-fuse:EnableNodeCliInspectArguments'));
  assert.ok(ids(f).includes('electron-fuse:EnableEmbeddedAsarIntegrityValidation'));
  assert.ok(!ids(f).includes('electron-fuse:OnlyLoadAppFromAsar'), 'on is the good state');
});

test('ASAR: parses real format, finds secrets and shipped maps inside it', () => {
  const d = tmp();
  const asar = path.join(d, 'app.asar');
  makeAsar(asar, { 'main.js': 'const t="ghp_' + 'a'.repeat(36) + '";', 'main.js.map': '{}' });
  assert.equal(readAsarFiles(asar).files.length, 2);
  const f = ids(scan(d));
  assert.ok(f.includes('secret:github-token'));
  assert.ok(f.includes('sourcemap-file'));
  assert.ok(f.includes('asar-plain'));
});

test('clean directory yields no high findings', () => {
  const d = tmp();
  fs.writeFileSync(path.join(d, 'index.js'), 'console.log("hello")');
  assert.deepEqual(scan(d).filter((x) => x.severity === 'high'), []);
});
