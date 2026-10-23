'use strict';
// What remains once the logic lives on the server: black-box extraction through the API.
// Measures how fast an attacker with a valid account can clone a hidden linear scoring model,
// with and without the guards. Deterministic (seeded PRNG).
const test = require('node:test');
const assert = require('node:assert/strict');
const { QuotaGuard, quantize } = require('../src/server/guard');

const W = [3.7, -1.2, 0.8, 2.5, -4.1]; // the "product secret" that never leaves the server
const model = (x) => x.reduce((s, v, i) => s + v * W[i], 0);

function prng(seed) {
  let a = seed;
  return () => {
    a |= 0; a = (a + 0x6d2b79f5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

// Least squares via normal equations + Gaussian elimination.
function fit(X, y) {
  const n = X[0].length;
  const A = Array.from({ length: n }, () => new Array(n + 1).fill(0));
  X.forEach((row, k) => {
    for (let i = 0; i < n; i++) {
      for (let j = 0; j < n; j++) A[i][j] += row[i] * row[j];
      A[i][n] += row[i] * y[k];
    }
  });
  for (let c = 0; c < n; c++) {
    let p = c;
    for (let r = c + 1; r < n; r++) if (Math.abs(A[r][c]) > Math.abs(A[p][c])) p = r;
    [A[c], A[p]] = [A[p], A[c]];
    for (let r = 0; r < n; r++) {
      if (r === c) continue;
      const f = A[r][c] / A[c][c];
      for (let k = c; k <= n; k++) A[r][k] -= f * A[c][k];
    }
  }
  return A.map((row, i) => row[n] / row[i]);
}

// Attacker keeps querying `oracle` (returns null when blocked) up to `budget` times, then fits a clone.
function attack(oracle, budget, seed = 1) {
  const rnd = prng(seed);
  const X = [];
  const y = [];
  for (let i = 0; i < budget; i++) {
    const x = W.map(() => rnd());
    const out = oracle(x);
    if (out === null) break;
    X.push(x); y.push(out);
  }
  if (X.length < W.length) return { queries: X.length, err: Infinity };
  const w = fit(X, y);
  return { queries: X.length, err: Math.max(...w.map((v, i) => Math.abs(v - W[i]))) };
}

test('open API, full precision: clone is EXACT after 5 queries', () => {
  const r = attack(model, 5);
  assert.equal(r.queries, 5);
  assert.ok(r.err < 1e-9, `err=${r.err}`);
});

test('coarse outputs alone do not save you: averaging many queries still recovers it', () => {
  const r = attack((x) => quantize(model(x), 5), 5000);
  console.log(`  [quantize only, 5000 queries] max weight error = ${r.err.toFixed(3)}`);
  assert.ok(r.err < 0.5, `err=${r.err}`); // weights are 0.8..4.1, so this is a ~10% accurate clone
});

test('quota + coarse outputs: one account is capped at 50 queries and the clone is >2x less accurate', () => {
  const guard = new QuotaGuard({ perTokenMax: 50, perUserMax: 50 });
  const oracle = (x) => (guard.consume({ jti: 't1', sub: 'attacker' }).ok ? quantize(model(x), 5) : null);
  const r = attack(oracle, 5000);
  console.log(`  [quota 50 + quantize, 1 account] queries=${r.queries} max weight error = ${r.err.toFixed(3)}`);
  const unrestricted = attack((x) => quantize(model(x), 5), 5000);
  assert.equal(r.queries, 50);
  assert.ok(r.err > 2 * unrestricted.err, `err=${r.err} vs ${unrestricted.err}`);
});

test('HONEST LIMIT: many accounts defeat quotas, so identity cost is the real defence', () => {
  const guard = new QuotaGuard({ perTokenMax: 50, perUserMax: 50 });
  let acct = 0;
  let used = 0;
  const oracle = (x) => {
    if (used % 50 === 0) acct++; // attacker registers a fresh account every 50 queries
    used++;
    return guard.consume({ jti: 't' + acct, sub: 'sybil' + acct }).ok ? quantize(model(x), 5) : null;
  };
  const r = attack(oracle, 5000);
  console.log(`  [quota 50 + quantize, 100 fake accounts] queries=${r.queries} max weight error = ${r.err.toFixed(3)}`);
  assert.equal(r.queries, 5000);
  assert.ok(r.err < 0.5, 'sybil accounts recover the model: require paid/attested identities');
});
