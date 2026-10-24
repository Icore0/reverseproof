# Launch post draft (edit freely; keep the claims as written)

**I attacked my own "anti-reverse-engineering" tool. Here's what survived.**

I tried to build something that stops people reverse-engineering apps. Then I attacked it with real tools. The honest result:

- Stripping symbols hides function names, not data. The secret was still readable.
- Encoding a secret beat `strings`, and lost to a one-line crack.
- A debugger pulled the decoded secret out of memory.
- macOS anti-debug blocked the debugger, until I skipped one function call.
- JS obfuscation hid the secret from `grep`, but a 4-line runtime hook still read it. "Bytecode" didn't even hide the strings.

So nothing on the user's machine is unbreakable. What *does* work: don't ship the valuable part. Keep logic and secrets on your server, and make a stolen client worthless.

**reverseproof** is the toolkit I ended up with:
- `scan`: finds what a reverse engineer gets for free (sourcemaps, secrets, weak hardening) in Electron, macOS, Windows and Linux builds.
- `audit`: finds repo and CI mistakes, including secrets you deleted but that still live in git history.
- Server pieces: short-lived tokens, replay protection, canary keys, scraping detection.
- Every claim is backed by an experiment you can rerun. Zero dependencies.

It's early (v0.1), not independently audited, and it won't replace a pentest. If you can break one of its claims, open an issue: I'll add your attack as a test and credit you.

Repo: https://github.com/Icore0/reverseproof
