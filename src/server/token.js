'use strict';
// Short-lived server-issued tokens + per-session request signing + replay guard.
// A clone of your client cannot mint tokens; an extracted token dies in minutes;
// a captured request cannot be replayed.
const crypto = require('node:crypto');

const b64u = (b) => Buffer.from(b).toString('base64url');
const hmac = (key, data) => crypto.createHmac('sha256', key).update(data).digest();
const sha256 = (d) => crypto.createHash('sha256').update(d).digest('hex');
const eq = (a, b) => {
  a = Buffer.from(String(a));
  b = Buffer.from(String(b));
  return a.length === b.length && crypto.timingSafeEqual(a, b);
};

// `device` MUST come from your attestation result (App Attest / Play Integrity / Turnstile),
// not from a value the client simply asserts.
function issueToken({ secret, sub, device, ttlSec = 300, now = Date.now() }) {
  const jti = crypto.randomBytes(12).toString('base64url');
  const body = b64u(JSON.stringify({ sub, dev: device, exp: Math.floor(now / 1000) + ttlSec, jti }));
  return {
    token: `${body}.${b64u(hmac(secret, body))}`,
    jti,
    sessionKey: b64u(hmac(secret, 'sk:' + jti)), // sent to the client once, over TLS
  };
}

function verifyToken({ secret, token, device, now = Date.now() }) {
  const [body, sig] = String(token).split('.');
  if (!body || !sig) return { ok: false, reason: 'malformed' };
  if (!eq(b64u(hmac(secret, body)), sig)) return { ok: false, reason: 'bad-signature' };
  let claims;
  try { claims = JSON.parse(Buffer.from(body, 'base64url').toString()); } catch { return { ok: false, reason: 'malformed' }; }
  if (claims.exp * 1000 <= now) return { ok: false, reason: 'expired' };
  if (claims.dev !== device) return { ok: false, reason: 'device-mismatch' };
  return { ok: true, claims };
}

function signRequest({ sessionKey, method, path, body = '', ts, nonce }) {
  const canonical = [method.toUpperCase(), path, sha256(body), ts, nonce].join('\n');
  return b64u(hmac(sessionKey, canonical));
}

class NonceGuard {
  constructor({ windowSec = 30 } = {}) {
    this.windowMs = windowSec * 1000;
    this.seen = new Map();
  }
  check({ ts, nonce, now = Date.now() }) {
    for (const [n, t] of this.seen) if (now - t > this.windowMs) this.seen.delete(n);
    if (Math.abs(now - ts) > this.windowMs) return { ok: false, reason: 'stale' };
    if (this.seen.has(nonce)) return { ok: false, reason: 'replay' };
    this.seen.set(nonce, now);
    return { ok: true };
  }
}

function verifyRequest({ secret, token, device, method, path, body = '', ts, nonce, sig, guard, now = Date.now() }) {
  const t = verifyToken({ secret, token, device, now });
  if (!t.ok) return t;
  const sessionKey = b64u(hmac(secret, 'sk:' + t.claims.jti));
  const expect = signRequest({ sessionKey, method, path, body, ts, nonce });
  if (!eq(expect, sig)) return { ok: false, reason: 'bad-request-signature' };
  const g = guard.check({ ts, nonce, now });
  if (!g.ok) return g;
  return { ok: true, claims: t.claims };
}

module.exports = { issueToken, verifyToken, signRequest, verifyRequest, NonceGuard };
