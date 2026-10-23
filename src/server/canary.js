'use strict';
// Honeytokens: fake credentials that look real, are embedded in client code/data, and are
// recognised statelessly (HMAC tag) when anyone presents them to your API. A hit means the
// artifact was extracted and someone is using what they found.
const crypto = require('node:crypto');

const TAG_LEN = 8;
const tagOf = (secret, rnd) => crypto.createHmac('sha256', secret).update('canary:' + rnd).digest('base64url').slice(0, TAG_LEN);

function makeCanary({ secret, prefix = 'sk_live_' }) {
  const rnd = crypto.randomBytes(18).toString('base64url'); // 24 chars
  return prefix + rnd + tagOf(secret, rnd);
}

function isCanary({ secret, value, prefix = 'sk_live_' }) {
  if (typeof value !== 'string' || !value.startsWith(prefix)) return false;
  const rest = value.slice(prefix.length);
  if (rest.length !== 24 + TAG_LEN) return false;
  const rnd = rest.slice(0, 24);
  const tag = rest.slice(24);
  const want = tagOf(secret, rnd);
  return tag.length === want.length && crypto.timingSafeEqual(Buffer.from(tag), Buffer.from(want));
}

// Express/Connect-style middleware: looks in headers, query and string body fields.
function canaryGuard({ secret, prefix = 'sk_live_', onTrip }) {
  const re = new RegExp(prefix.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '[A-Za-z0-9_-]{' + (24 + TAG_LEN) + '}', 'g');
  return (req, res, next) => {
    const hay = JSON.stringify([req.headers, req.query, req.body]) || '';
    for (const m of hay.matchAll(re)) {
      if (isCanary({ secret, value: m[0], prefix })) {
        onTrip({ value: m[0], ip: req.ip, path: req.path, headers: req.headers });
        res.statusCode = 200; // do not tip them off: answer plausibly, flag the source out of band
        res.setHeader('content-type', 'application/json');
        return res.end('{"data":[]}');
      }
    }
    next();
  };
}

module.exports = { makeCanary, isCanary, canaryGuard };
