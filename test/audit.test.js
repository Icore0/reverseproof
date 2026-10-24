'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const { audit } = require('../src/audit');

const tmp = () => fs.mkdtempSync(path.join(os.tmpdir(), 'rp-audit-'));
const ids = (f) => f.map((x) => x.id);
const git = (d, ...a) => { const r = spawnSync('git', ['-c', 'user.name=t', '-c', 'user.email=t@t', ...a], { cwd: d, encoding: 'utf8' }); assert.equal(r.status, 0, r.stderr); };

test('flags missing lockfile, unpinned deps and pipe-to-shell scripts', () => {
  const d = tmp();
  fs.writeFileSync(path.join(d, 'package.json'), JSON.stringify({ dependencies: { a: '*', b: 'github:x/y', c: '1.2.3' }, scripts: { install: 'curl https://x.sh | sh' } }));
  const r = audit(d);
  assert.ok(ids(r).includes('no-lockfile'));
  assert.equal(r.filter((x) => x.id === 'unpinned-dependency').length, 2);
  assert.ok(ids(r).includes('pipe-to-shell'));
  fs.writeFileSync(path.join(d, 'package-lock.json'), '{}');
  assert.ok(!ids(audit(d)).includes('no-lockfile'));
});

test('workflows: unpinned actions, default permissions, pwn-request and script injection', () => {
  const d = tmp();
  fs.mkdirSync(path.join(d, '.github', 'workflows'), { recursive: true });
  const sha = 'a'.repeat(40);
  fs.writeFileSync(path.join(d, '.github', 'workflows', 'bad.yml'), `on: pull_request_target
jobs:
  x:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: \${{ github.event.pull_request.head.sha }}
      - uses: thirdparty/tool@main
      - uses: pinned/tool@${sha}
      - run: echo "\${{ github.event.pull_request.title }}"
`);
  const r = audit(d);
  const got = ids(r);
  for (const id of ['pwn-request', 'script-injection', 'workflow-default-permissions']) assert.ok(got.includes(id), id);
  const pins = r.filter((x) => x.id === 'action-not-pinned');
  assert.equal(pins.length, 2);
  assert.ok(pins.some((x) => x.severity === 'medium' && x.message.includes('thirdparty/tool')));
  assert.ok(!pins.some((x) => x.message.includes('pinned/tool')));
});

test('a clean pinned workflow with permissions passes', () => {
  const d = tmp();
  fs.mkdirSync(path.join(d, '.github', 'workflows'), { recursive: true });
  fs.writeFileSync(path.join(d, '.github', 'workflows', 'ok.yml'), `on: push\npermissions:\n  contents: read\njobs:\n  x:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@${'b'.repeat(40)}\n      - run: npm test\n`);
  const got = ids(audit(d));
  assert.ok(!got.some((i) => ['action-not-pinned', 'workflow-default-permissions', 'pwn-request', 'script-injection'].includes(i)));
});

test('git: tracked .env and a secret deleted in a later commit are both caught', () => {
  const d = tmp();
  git(d, 'init', '-q', '-b', 'main');
  fs.writeFileSync(path.join(d, 'config.js'), 'module.exports = { stripe: "sk_live_' + 'A1b2C3d4E5f6G7h8I9j0K1l2" };\n');
  fs.writeFileSync(path.join(d, '.env'), 'X=1\n');
  git(d, 'add', '-A'); git(d, 'commit', '-q', '-m', 'oops');
  fs.writeFileSync(path.join(d, 'config.js'), 'module.exports = { stripe: process.env.STRIPE };\n');
  git(d, 'commit', '-q', '-am', 'remove secret');
  const r = audit(d);
  assert.ok(ids(r).includes('tracked-secret-file'));
  const h = r.find((x) => x.id === 'history-secret:stripe-live-key');
  assert.ok(h, 'secret removed from HEAD must still be found in history');
  assert.match(h.message, /NOT enough/);
});

test('hygiene: missing gitignore / SECURITY.md / dependabot are low severity only', () => {
  const r = audit(tmp());
  assert.deepEqual(ids(r).sort(), ['no-dependency-updates', 'no-gitignore', 'no-security-policy']);
  assert.ok(r.every((x) => x.severity === 'low'));
});

test('.reverseproofignore removes fixture paths, including from git history findings', () => {
  const { applyIgnore } = require('../src/audit');
  const d = tmp();
  git(d, 'init', '-q', '-b', 'main');
  fs.mkdirSync(path.join(d, 'test'));
  fs.writeFileSync(path.join(d, 'test', 'fixture.js'), 'const k = "sk_live_' + 'A1b2C3d4E5f6G7h8I9j0K1l2";\n');
  fs.writeFileSync(path.join(d, 'real.js'), 'const k = "sk_live_' + 'Z9y8X7w6V5u4T3s2R1q0P9o8";\n');
  git(d, 'add', '-A'); git(d, 'commit', '-q', '-m', 'x');
  fs.writeFileSync(path.join(d, '.reverseproofignore'), '# fixtures\ntest/\n');
  const files = applyIgnore(audit(d), d).filter((x) => x.id === 'history-secret:stripe-live-key').map((x) => x.file);
  assert.deepEqual(files, ['real.js'], 'only the real file remains');
});
