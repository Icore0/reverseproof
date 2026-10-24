'use strict';
// Behavioural scoring for one identity's recent requests, plus Sybil clustering across identities.
// Heuristic by design: tune thresholds on your own traffic, and treat 'challenge' as the default response,
// not 'block'. Attackers who rotate identities AND randomise behaviour will slip through (see docs/VERDICT.md).

const mean = (a) => a.reduce((s, v) => s + v, 0) / a.length;
const sd = (a) => { const m = mean(a); return Math.sqrt(mean(a.map((v) => (v - m) ** 2))); };

// events: [{ t: ms, path: '/item/123', id?: number }]
function scoreIdentity(events, { minEvents = 20 } = {}) {
  const reasons = [];
  let score = 0;
  if (events.length < minEvents) return { score: 0, action: 'allow', reasons: ['too few events to judge'] };
  const ev = [...events].sort((a, b) => a.t - b.t);
  const gaps = ev.slice(1).map((e, i) => e.t - ev[i].t);
  const spanMin = Math.max((ev[ev.length - 1].t - ev[0].t) / 60000, 1 / 60);
  const perMin = ev.length / spanMin;

  if (perMin > 120) { score += 25; reasons.push(`very high rate: ${perMin.toFixed(0)}/min`); }
  else if (perMin > 40) { score += 10; reasons.push(`high rate: ${perMin.toFixed(0)}/min`); }

  const m = mean(gaps);
  const cv = m > 0 ? sd(gaps) / m : 0;
  if (cv < 0.25) { score += 30; reasons.push(`machine-regular timing (CV ${cv.toFixed(2)}; humans are bursty, CV > 0.7)`); }

  const fast = gaps.filter((g) => g < 50).length / gaps.length;
  if (fast > 0.5) { score += 15; reasons.push(`${(fast * 100).toFixed(0)}% of requests under 50 ms apart (no think time)`); }

  const ids = ev.filter((e) => Number.isFinite(e.id)).map((e) => e.id);
  if (ids.length >= minEvents) {
    const seq = ids.slice(1).filter((v, i) => Math.abs(v - ids[i]) === 1).length / (ids.length - 1);
    if (seq > 0.8) { score += 30; reasons.push(`sequential id enumeration (${(seq * 100).toFixed(0)}% of steps are +/-1)`); }
  }

  const distinct = new Set(ev.map((e) => e.path)).size / ev.length;
  if (distinct > 0.95 && ev.length >= 50) { score += 15; reasons.push('almost never revisits a resource (crawling pattern)'); }

  score = Math.min(score, 100);
  return { score, action: score >= 70 ? 'block' : score >= 30 ? 'challenge' : 'allow', reasons };
}

// accounts: [{ id, fingerprint }]. Fingerprint = whatever is expensive to rotate for you
// (attested device id, payment instrument, phone number hash). Many accounts per fingerprint = Sybil farm.
function sybilClusters(accounts, { maxPerFingerprint = 3 } = {}) {
  const by = new Map();
  for (const a of accounts) {
    if (!a.fingerprint) continue;
    if (!by.has(a.fingerprint)) by.set(a.fingerprint, []);
    by.get(a.fingerprint).push(a.id);
  }
  return [...by.entries()].filter(([, ids]) => ids.length > maxPerFingerprint).map(([fingerprint, ids]) => ({ fingerprint, accounts: ids, count: ids.length }));
}

module.exports = { scoreIdentity, sybilClusters };
