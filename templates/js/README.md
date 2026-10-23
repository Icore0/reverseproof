# JS obfuscation notes
Use with `npx javascript-obfuscator dist --config templates/js/obfuscator.config.json`.
- Apply to the few modules that matter, not the whole bundle: control-flow flattening costs 15-100%+ runtime.
- `seed: 0` = random per build. Keep it random so release-to-release diffs are noisy.
- Never ship `.map` files. Verify: `npx reverseproof scan dist`.
- For Electron main-process code, prefer bytecode: `npx bytenode -c main.js` and load the `.jsc` from a tiny stub.
- Obfuscated JS is still JS: it runs in a runtime the attacker controls. It slows reading, it does not prevent it.
