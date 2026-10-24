'use strict';
// Repo / supply-chain hygiene: the ways real companies get breached without anyone reverse-engineering a thing.
const fs = require('node:fs');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const { scanText } = require('./scan');

const f = (severity, id, file, message, fix) => ({ severity, id, file, message, fix: fix || '' });
const git = (cwd, args, max = 64 * 1024 * 1024) => spawnSync('git', args, { cwd, encoding: 'utf8', maxBuffer: max });

function auditPackageJson(root, out) {
  const p = path.join(root, 'package.json');
  if (!fs.existsSync(p)) return;
  let pkg;
  try { pkg = JSON.parse(fs.readFileSync(p, 'utf8')); } catch { return; }
  const hasLock = ['package-lock.json', 'yarn.lock', 'pnpm-lock.yaml', 'bun.lockb', 'bun.lock'].some((n) => fs.existsSync(path.join(root, n)));
  const deps = { ...pkg.dependencies, ...pkg.devDependencies, ...pkg.optionalDependencies };
  if (Object.keys(deps).length && !hasLock) out.push(f('medium', 'no-lockfile', p, 'Dependencies without a lockfile: every install can pull different (possibly malicious) versions.', 'Commit package-lock.json / yarn.lock / pnpm-lock.yaml and install with npm ci.'));
  for (const [name, v] of Object.entries(deps)) {
    if (/^(\*|latest|x|)$/.test(v) || /^(git\+|https?:|github:|git:)/.test(v)) out.push(f('medium', 'unpinned-dependency', p, `${name}@"${v}" is not a pinned registry version.`, 'Pin to an exact version (or a commit SHA for git deps) and review updates.'));
  }
  for (const [s, cmd] of Object.entries(pkg.scripts || {})) {
    if (/(curl|wget)[^|;&]*\|\s*(sudo\s+)?(ba|z)?sh\b/.test(cmd)) out.push(f('high', 'pipe-to-shell', p, `Script "${s}" pipes a download into a shell.`, 'Download, verify a checksum, then run.'));
  }
}

function auditWorkflows(root, out) {
  const dir = path.join(root, '.github', 'workflows');
  if (!fs.existsSync(dir)) return;
  for (const name of fs.readdirSync(dir).filter((n) => /\.ya?ml$/.test(n))) {
    const file = path.join(dir, name);
    const t = fs.readFileSync(file, 'utf8');
    for (const m of t.matchAll(/^\s*-?\s*uses:\s*([^\s#]+)@([^\s#]+)/gm)) {
      const [, action, ref] = m;
      if (action.startsWith('./') || action.startsWith('docker://') || /^[0-9a-f]{40}$/.test(ref)) continue;
      const firstParty = /^actions\//.test(action);
      out.push(f(firstParty ? 'low' : 'medium', 'action-not-pinned', file, `${action}@${ref} is a movable tag/branch, not a commit SHA.`, 'Pin to the full 40-char commit SHA (a compromised tag then cannot change what you run).'));
    }
    if (!/^permissions:/m.test(t)) out.push(f('medium', 'workflow-default-permissions', file, 'No top-level `permissions:` block: the token may default to broad write access.', 'Add `permissions: { contents: read }` and widen per job only where needed.'));
    if (/pull_request_target/.test(t) && /ref:\s*\$\{\{\s*github\.event\.pull_request\.head/.test(t)) out.push(f('high', 'pwn-request', file, 'pull_request_target checks out untrusted PR code with a privileged token.', 'Use pull_request, or never run PR code in a pull_request_target job.'));
    if (/\$\{\{\s*github\.event\.(?:issue|pull_request|comment|review|head_commit|pages)[\w.\[\]*]*\.(?:title|body|message|name|label|ref|email)\s*\}\}/.test(t)) out.push(f('high', 'script-injection', file, 'Attacker-controlled text (title/body/branch name) is interpolated into a workflow expression.', 'Pass it through an env var and quote it in the shell instead of interpolating `${{ }}` into `run:`.'));
  }
}

function auditGit(root, out, { history = 300 } = {}) {
  if (git(root, ['rev-parse', '--git-dir']).status !== 0) return;
  const tracked = git(root, ['ls-files']).stdout.split('\n').filter(Boolean);
  for (const t of tracked) {
    const b = path.basename(t);
    if (/^\.env(\..+)?$/.test(b) && !/\.(example|sample|template)$/.test(b)) out.push(f('high', 'tracked-secret-file', t, '.env file is committed.', 'git rm --cached it, add to .gitignore, and rotate everything it contained.'));
    if (/\.(pem|p12|pfx|keystore|jks)$/.test(b) || /^id_(rsa|ed25519|ecdsa)$/.test(b)) out.push(f('high', 'tracked-secret-file', t, 'Private key/keystore is committed.', 'Remove it, rotate the key, and purge history if it was ever pushed.'));
  }
  const log = git(root, ['log', '-p', '--all', '--no-color', '-U0', '-n', String(history)]);
  if (log.status !== 0) return;
  const seen = new Set();
  for (const chunk of log.stdout.split(/^commit /m).slice(1)) {
    const sha = chunk.slice(0, 40);
    const perFile = new Map();
    let cur = '(unknown)';
    for (const line of chunk.split('\n')) {
      const m = /^diff --git a\/.* b\/(.*)$/.exec(line);
      if (m) { cur = m[1]; continue; }
      if (line.startsWith('+') && !line.startsWith('+++')) perFile.set(cur, (perFile.get(cur) || '') + line.slice(1) + '\n');
    }
    for (const [file, added] of perFile) {
      const tmp = [];
      scanText(file, added, tmp);
      for (const x of tmp.filter((y) => y.id.startsWith('secret:') && y.severity === 'high')) {
        const key = file + x.id + x.message;
        if (seen.has(key)) continue;
        seen.add(key);
        out.push({ ...x, id: 'history-' + x.id, file, message: x.message + ` (in git history, commit ${sha.slice(0, 8)}: deleting the file is NOT enough)`, fix: 'Rotate the credential first; then purge history (git filter-repo) if the repo was ever shared.' });
      }
    }
  }
}

function auditHygiene(root, out) {
  if (!fs.existsSync(path.join(root, '.gitignore'))) out.push(f('low', 'no-gitignore', root, 'No .gitignore: secrets and build output are easy to commit by accident.'));
  if (!['SECURITY.md', '.github/SECURITY.md', 'docs/SECURITY.md'].some((n) => fs.existsSync(path.join(root, n)))) out.push(f('low', 'no-security-policy', root, 'No SECURITY.md: researchers have no private way to report a vulnerability.', 'Add a SECURITY.md with a reporting address.'));
  if (!['.github/dependabot.yml', '.github/dependabot.yaml', 'renovate.json', '.renovaterc', '.github/renovate.json'].some((n) => fs.existsSync(path.join(root, n)))) out.push(f('low', 'no-dependency-updates', root, 'No Dependabot/Renovate config: vulnerable dependencies go unnoticed.'));
}

function audit(target, opts = {}) {
  const root = path.resolve(target);
  if (!fs.existsSync(root)) throw new Error('No such path: ' + root);
  const out = [];
  auditPackageJson(root, out);
  auditWorkflows(root, out);
  auditGit(root, out, opts);
  auditHygiene(root, out);
  const order = { high: 0, medium: 1, low: 2, info: 3 };
  return out.sort((a, b) => order[a.severity] - order[b.severity]);
}

// `.reverseproofignore` in the scanned root: one path prefix per line (# comments allowed).
// Use it for intentional fixtures; every ignored path should be one you can justify in review.
function applyIgnore(findings, root) {
  const file = path.join(path.resolve(root), '.reverseproofignore');
  if (!fs.existsSync(file)) return findings;
  const prefixes = fs.readFileSync(file, 'utf8').split('\n').map((l) => l.trim()).filter((l) => l && !l.startsWith('#'));
  const rel = (p) => (path.isAbsolute(p) ? path.relative(path.resolve(root), p) : p).split(path.sep).join('/');
  return findings.filter((x) => !prefixes.some((pre) => rel(x.file.split('!')[0]).startsWith(pre)));
}

module.exports = { audit, applyIgnore };
