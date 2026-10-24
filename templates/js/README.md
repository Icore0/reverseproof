# JS hardening notes (every claim here is measured: `cd experiments/js && npm install && npm test`)

Profiles for `npx javascript-obfuscator dist --config <file>`:
- `obfuscator.light.json`: string-array encoding only. Hides string literals from grep/`strings`.
- `obfuscator.heavy.json`: adds control-flow flattening + dead code. Hides more structure, **costs far more CPU**.

Measured once on one Apple-silicon machine (a mixed arithmetic + string-constant workload; your numbers will differ, run the experiment): heavy ~52x slower, light ~12x slower (cost is dominated by
string lookups in hot loops). Apply to cold, sensitive modules only. Never to hot paths.

What it does and does not do:
- Obfuscation hides literals from `grep`. A runtime hook (`fetch`, `http.request`, a debugger) still reads the secret as it is used. Tested.
- **Bytecode (bytenode) does NOT hide strings.** String literals sit in the `.jsc` in plaintext. Tested. It makes logic harder to read,
  not secrets harder to find. Combine with moving the secret server-side, not with hope.
- Never ship `.map` files. `npx reverseproof scan dist` checks.
- Keep `seed` random per build so release-to-release diffs stay noisy.
