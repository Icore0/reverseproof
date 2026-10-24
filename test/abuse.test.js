'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { scoreIdentity, sybilClusters } = require('../src/server/abuse');

function prng(seed) { let a = seed; return () => { a |= 0; a = (a + 0x6d2b79f5) | 0; let t = Math.imul(a ^ (a >>> 15), 1 | a); t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t; return ((t ^ (t >>> 14)) >>> 0) / 4294967296; }; }

// A person: bursty think-times (log-normal-ish), revisits pages, jumps between ids.
function human(n, seed = 1) {
  const r = prng(seed); let t = 0; const ev = [];
  for (let i = 0; i < n; i++) { t += 800 + Math.exp(r() * 9) ; ev.push({ t, path: '/item/' + Math.floor(r() * 12), id: Math.floor(r() * 5000) }); }
  return ev;
}
const crawler = (n) => Array.from({ length: n }, (_, i) => ({ t: i * 100, path: '/item/' + (1000 + i), id: 1000 + i }));
// A smarter bot: random delays, shuffled ids, revisits some pages.
function stealth(n, seed = 7) {
  const r = prng(seed); let t = 0;
  return Array.from({ length: n }, () => { t += 600 + r() * 9000 * r() * 3; return { t, path: '/item/' + Math.floor(r() * 40), id: Math.floor(r() * 100000) }; });
}

test('human browsing is allowed', () => {
  const r = scoreIdentity(human(60));
  assert.equal(r.action, 'allow', JSON.stringify(r));
});

test('sequential, machine-regular crawler is blocked with reasons', () => {
  const r = scoreIdentity(crawler(300));
  assert.equal(r.action, 'block');
  assert.ok(r.reasons.some((x) => /sequential id/.test(x)) && r.reasons.some((x) => /machine-regular/.test(x)));
});

test('too little data never blocks', () => {
  assert.equal(scoreIdentity(crawler(5)).action, 'allow');
});

test('HONEST LIMIT: a stealthy bot with random timing and ids evades per-identity scoring', () => {
  const r = scoreIdentity(stealth(200));
  assert.equal(r.action, 'allow', JSON.stringify(r));
});

test('Sybil farm: many accounts on one expensive-to-rotate fingerprint are clustered', () => {
  const accounts = [
    ...Array.from({ length: 12 }, (_, i) => ({ id: 'bot' + i, fingerprint: 'dev-X' })),
    { id: 'alice', fingerprint: 'dev-A' }, { id: 'bob', fingerprint: 'dev-B' }, { id: 'carol', fingerprint: 'dev-B' },
    { id: 'nofp', fingerprint: null },
  ];
  const c = sybilClusters(accounts, { maxPerFingerprint: 3 });
  assert.equal(c.length, 1);
  assert.equal(c[0].fingerprint, 'dev-X');
  assert.equal(c[0].count, 12);
});
