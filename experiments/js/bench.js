let s = 0;
for (let i = 0; i < 3e6; i++) { s = (s + Math.imul(i, 31) ^ (i >>> 3)) | 0; }
const rows = Array.from({ length: 2e5 }, (_, i) => ({ k: 'k' + i, v: i % 97 }));
const m = new Map(rows.map((r) => [r.k, r.v]));
let t = 0; for (const [, v] of m) t += v;
console.log(s, t);
