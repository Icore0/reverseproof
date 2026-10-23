'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { issueToken, verifyToken, signRequest, verifyRequest, NonceGuard } = require('../src/server/token');
const { makeCanary, isCanary, canaryGuard } = require('../src/server/canary');
const wm = require('../src/server/watermark');

const secret = 'server-only-secret';

test('token: valid, expired, tampered, wrong device', () => {
  const now = 1_000_000;
  const { token } = issueToken({ secret, sub: 'u1', device: 'dev1', ttlSec: 60, now });
  assert.equal(verifyToken({ secret, token, device: 'dev1', now: now + 1000 }).ok, true);
  assert.equal(verifyToken({ secret, token, device: 'dev1', now: now + 61_000 }).reason, 'expired');
  assert.equal(verifyToken({ secret, token, device: 'other', now }).reason, 'device-mismatch');
  const bad = token.slice(0, -2) + (token.endsWith('A') ? 'BB' : 'AA');
  assert.equal(verifyToken({ secret, token: bad, device: 'dev1', now }).reason, 'bad-signature');
  assert.equal(verifyToken({ secret: 'other', token, device: 'dev1', now }).reason, 'bad-signature');
});

test('request signing: valid once, replay rejected, tamper rejected, stale rejected', () => {
  const now = 5_000_000;
  const { token, sessionKey } = issueToken({ secret, sub: 'u1', device: 'd', now });
  const guard = new NonceGuard({ windowSec: 30 });
  const req = { method: 'POST', path: '/v1/score', body: '{"a":1}', ts: now, nonce: 'n1' };
  const sig = signRequest({ sessionKey, ...req });
  const base = { secret, token, device: 'd', guard, now, ...req, sig };
  assert.equal(verifyRequest(base).ok, true);
  assert.equal(verifyRequest(base).reason, 'replay');
  assert.equal(verifyRequest({ ...base, nonce: 'n2' }).reason, 'bad-request-signature');
  assert.equal(verifyRequest({ ...base, body: '{"a":2}', nonce: 'n1' }).reason, 'bad-request-signature');
  const old = { ...req, ts: now - 120_000, nonce: 'n3' };
  assert.equal(verifyRequest({ ...base, ...old, sig: signRequest({ sessionKey, ...old }) }).reason, 'stale');
});

test('a forged session key (client clone guessing) cannot sign requests', () => {
  const now = 9_000_000;
  const { token } = issueToken({ secret, sub: 'u1', device: 'd', now });
  const req = { method: 'GET', path: '/x', ts: now, nonce: 'z' };
  const sig = signRequest({ sessionKey: 'guess', ...req });
  assert.equal(verifyRequest({ secret, token, device: 'd', guard: new NonceGuard(), now, ...req, sig }).reason, 'bad-request-signature');
});

test('canary: recognised statelessly, random lookalikes are not', () => {
  const c = makeCanary({ secret });
  assert.equal(isCanary({ secret, value: c }), true);
  assert.equal(isCanary({ secret: 'other', value: c }), false);
  assert.equal(isCanary({ secret, value: 'sk_live_' + 'a'.repeat(32) }), false);
  assert.equal(isCanary({ secret, value: c.slice(0, -1) + (c.endsWith('a') ? 'b' : 'a') }), false);
});

test('canary middleware trips on headers/body and passes clean requests', () => {
  const c = makeCanary({ secret });
  const trips = [];
  const mw = canaryGuard({ secret, onTrip: (t) => trips.push(t) });
  let nexted = 0;
  const res = { setHeader() {}, end(b) { this.body = b; } };
  mw({ headers: { authorization: 'Bearer ' + c }, query: {}, body: null, ip: '1.2.3.4', path: '/p' }, res, () => nexted++);
  assert.equal(trips.length, 1);
  assert.equal(nexted, 0);
  assert.equal(res.body, '{"data":[]}');
  mw({ headers: { authorization: 'Bearer real' }, query: {}, body: {}, ip: 'x', path: '/p' }, res, () => nexted++);
  assert.equal(nexted, 1);
  assert.equal(trips.length, 1);
});

test('watermark: round-trips, survives fragment copy, defeated by strip (documented limit)', () => {
  const text = 'First sentence here. Second sentence there! Third one follows? Done.';
  const marked = wm.embed(text, 'user-4821');
  assert.equal(wm.extract(marked), 'user-4821');
  assert.equal(wm.strip(marked), text);
  const fragment = marked.slice(marked.indexOf('Second'));
  assert.equal(wm.extract(fragment), 'user-4821');
  assert.equal(wm.extract(wm.strip(marked)), null); // honest limit: one regex removes it
  assert.equal(wm.extract('plain text'), null);
});
