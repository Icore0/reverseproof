# Contributing

- `npm test` must pass. Zero runtime dependencies is a goal; avoid adding any.
- **Claims need tests.** If you add a protection, add an attack that tries to defeat it and record the result in
  `docs/VERDICT.md`, including when the attack wins. A protection without a measured attack does not get merged.
- Scanner checks must not produce noise on clean projects. Add a false-positive test with every new pattern.
- Gaps that would be most valuable: Windows signing/PE checks, Linux ELF hardening (RELRO/PIE), Android/iOS packages,
  Tauri/Flutter/React Native bundles, a Windows/Linux version of the debugger experiment.
