'use strict';
// What do JS obfuscation and V8 bytecode (bytenode) actually protect? Measured, not assumed.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

let JSO, bytenode;
try { JSO = require('javascript-obfuscator'); bytenode = require('bytenode'); } catch { /* deps not installed */ }
const opts = { skip: !JSO && 'run `npm install` in experiments/js first' };

const SECRET = 'sk_live_JSEXPERIMENT_SECRET_12345678';
const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'rp-js-'));
const load = (n) => JSON.parse(fs.readFileSync(path.join(__dirname, '..', '..', 'templates', 'js', n), 'utf8'));
const cfg = load('obfuscator.heavy.json');
const light = load('obfuscator.light.json');
const src = (f) => fs.readFileSync(path.join(__dirname, f), 'utf8');
const out = (name, content) => { const p = path.join(dir, name); fs.writeFileSync(p, content); return p; };
const visible = (file) => fs.readFileSync(file).toString('latin1').includes('JSEXPERIMENT');

function build() {
  const plain = out('plain.js', src('app.js'));
  const obf = out('obf.js', JSO.obfuscate(src('app.js'), cfg).getObfuscatedCode());
  const jscSrc = out('bc.js', src('app.js'));
  const jsc = path.join(dir, 'bc.jsc');
  bytenode.compileFile({ filename: jscSrc, output: jsc });
  return { plain, obf, jsc };
}

// Attacker's dynamic step: preload a hook, run the artifact, read what it sent.
function hookRun(args) {
  const log = path.join(dir, 'hook-' + Math.random().toString(36).slice(2) + '.log');
  const r = spawnSync(process.execPath, ['-r', path.join(__dirname, 'hook.js'), ...args], { env: { ...process.env, HOOK_OUT: log }, encoding: 'utf8', timeout: 60000 });
  return { ok: r.status === 0, leaked: fs.existsSync(log) ? fs.readFileSync(log, 'utf8') : '', err: r.stderr };
}

test('plain: secret visible statically and dynamically (baseline)', opts, () => {
  const { plain } = build();
  assert.ok(visible(plain));
  assert.ok(hookRun([plain]).leaked.includes(SECRET));
});

test('obfuscated (heavy and light profiles): static grep fails, runtime hook still gets the secret', opts, () => {
  const { obf } = build();
  const lightObf = out('obf-light.js', JSO.obfuscate(src('app.js'), light).getObfuscatedCode());
  for (const f of [obf, lightObf]) {
    assert.ok(!visible(f), 'secret is not a visible literal');
    const r = hookRun([f]);
    assert.ok(r.ok, r.err);
    assert.ok(r.leaked.includes(SECRET), 'obfuscation does not stop observing the call');
  }
});

test('bytenode bytecode: what is visible statically, and does a runtime hook win?', opts, () => {
  const { jsc } = build();
  const staticallyVisible = visible(jsc);
  console.log(`  [bytenode] secret literal visible in .jsc via strings/grep: ${staticallyVisible}`);
  const r = hookRun(['-e', `require('bytenode'); require(${JSON.stringify(jsc)})`]);
  assert.ok(r.ok, r.err);
  assert.ok(r.leaked.includes(SECRET), 'bytecode does not stop observing the call');
});

test('cost: slowdown of each profile on a CPU-bound workload (informational)', opts, () => {
  const bench = src('bench.js');
  const plain = out('bench-plain.js', bench);
  const obf = out('bench-obf.js', JSO.obfuscate(bench, cfg).getObfuscatedCode());
  const lt = out('bench-light.js', JSO.obfuscate(bench, light).getObfuscatedCode());
  const time = (f) => { const t = process.hrtime.bigint(); const r = spawnSync(process.execPath, [f]); assert.equal(r.status, 0, String(r.stderr)); return Number(process.hrtime.bigint() - t) / 1e6; };
  time(plain); // warm
  const a = Math.min(time(plain), time(plain));
  const b = Math.min(time(obf), time(obf));
  const c = Math.min(time(lt), time(lt));
  console.log(`  [cost] plain ${a.toFixed(0)}ms | heavy ${b.toFixed(0)}ms (x${(b / a).toFixed(1)}) | light ${c.toFixed(0)}ms (x${(c / a).toFixed(1)})`);
  assert.ok(b > c, 'heavy profile costs more than light');
});
