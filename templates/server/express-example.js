// Wiring example (not a framework): npm i express. Run: node templates/server/express-example.js
const express = require('express');
const { issueToken, verifyRequest, NonceGuard } = require('../../src/server/token');
const { makeCanary, canaryGuard } = require('../../src/server/canary');

const SECRET = process.env.RP_SECRET;             // server-only; never ships in a client
if (!SECRET) throw new Error('set RP_SECRET');
const guard = new NonceGuard({ windowSec: 30 });
const app = express();
app.use(express.json());

// 1. Honeytoken: embed makeCanary({secret: SECRET}) in your client bundle/config as a fake API key.
app.use(canaryGuard({ secret: SECRET, onTrip: (t) => console.warn('CANARY TRIPPED', t.ip, t.path) }));

// 2. Login: issue a short-lived token. `device` must come from attestation (App Attest/Play Integrity/Turnstile).
app.post('/login', (req, res) => {
  const device = req.body.attestedDeviceId; // replace with real attestation verification
  const { token, sessionKey } = issueToken({ secret: SECRET, sub: req.body.user, device, ttlSec: 300 });
  res.json({ token, sessionKey });
});

// 3. Every call is signed with the session key, with a fresh nonce and timestamp.
app.post('/v1/score', (req, res) => {
  const r = verifyRequest({
    secret: SECRET, guard, token: req.get('x-token'), device: req.get('x-device'),
    method: req.method, path: req.path, body: JSON.stringify(req.body), // use the RAW body bytes in production
    ts: Number(req.get('x-ts')), nonce: req.get('x-nonce'), sig: req.get('x-sig'),
  });
  if (!r.ok) return res.status(401).json({ error: r.reason });
  res.json({ score: 42 }); // the valuable logic lives HERE, not in the client
});

if (require.main === module) app.listen(3000);
module.exports = app;
