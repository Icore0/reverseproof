# Honest claims guide (for README, posts, talks, sales)

A false claim about security tools gets screenshotted and disproved. This repo's edge is that it shows its own failures.

## Never say
- "prevents / stops / blocks reverse engineering"
- "immune", "unbreakable", "uncrackable", "100% secure", "military-grade"
- "protects your source code" (it hardens artifacts; it cannot stop a determined local attacker)
- "makes your app safe" (it covers a slice of one threat; see THREAT-MODEL.md)

## Safe to say (each is backed by a test in this repo)
- "Finds the leaks that make your app easy to reverse-engineer: sourcemaps, secrets, weak Electron/macOS/Windows/Linux hardening."
- "Finds secrets that were deleted but still live in your git history."
- "Audits your CI for unpinned actions, workflow injection and unlocked dependencies."
- "Makes a stolen client worthless by moving logic server-side, with short-lived tokens, signed requests, replay protection, canaries."
- "Measured: obfuscation hides strings from `grep` but not from a runtime hook; bytecode doesn't hide strings; anti-debug is one breakpoint from bypass."
- "Zero dependencies. Tested on Linux and macOS in CI."

## Required caveats when you describe it
- Early version; not independently audited.
- Client-side protections raise cost, they do not stop a skilled attacker.
- Real protection is architectural: do not ship secrets, keep valuable logic on the server.

## If someone shows it failing
Add their case as a test and a line in VERDICT.md, credit them, and say so publicly. That is the brand.
