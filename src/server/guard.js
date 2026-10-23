'use strict';
// Defences against black-box extraction: an attacker who owns a valid account can still query
// your API and fit a clone of the hidden function. Quotas and output coarsening raise that cost.
class QuotaGuard {
  constructor({ perTokenMax = 50, perUserMax = 500, windowSec = 86400 } = {}) {
    this.perTokenMax = perTokenMax;
    this.perUserMax = perUserMax;
    this.windowMs = windowSec * 1000;
    this.tokens = new Map();
    this.users = new Map();
  }
  consume({ jti, sub, now = Date.now() }) {
    const t = (this.tokens.get(jti) || 0) + 1;
    const u = this.users.get(sub);
    const user = u && now - u.start < this.windowMs ? u : { start: now, n: 0 };
    user.n += 1;
    this.tokens.set(jti, t);
    this.users.set(sub, user);
    if (t > this.perTokenMax) return { ok: false, reason: 'token-quota' };
    if (user.n > this.perUserMax) return { ok: false, reason: 'user-quota' };
    return { ok: true };
  }
}

// Return only as much precision as the product needs: less signal per query for the attacker.
const quantize = (x, step) => Math.round(x / step) * step;

module.exports = { QuotaGuard, quantize };
