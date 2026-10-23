# Verdict: does this stop reverse engineering?

**No. Nothing client-side can, and this repo does not pretend otherwise.**
What it does is move the work from "free and instant" to "needs a skilled human and time", and it gives you
tripwires and a server-side design that makes a stolen client worthless. Every claim below is backed by a test you can run (`npm test`).

## What the tests actually showed (`test/toy.test.js`, macOS arm64, clang + lldb)

One toy program holds a licence check and an API key. Built five ways, attacked with real tools:

| Build | `strings` | symbols (`nm`) | single-byte-XOR crib | debugger (lldb) |
|---|---|---|---|---|
| A. plain | secret + licence visible | `check_license` visible | n/a | n/a |
| B. stripped | **secret still visible** | names gone | n/a | n/a |
| C. XOR-encoded + stripped | **nothing found** | gone | **recovered instantly** | n/a |
| D. same as C | nothing | gone | recovered | **recovered from memory** |
| E. + `PT_DENY_ATTACH` | nothing | gone | recovered | **blocked** (process exits 45) |
| F. same as E | nothing | gone | recovered | **recovered** (attacker skips the `ptrace` call) |

Lessons, each one measured:
1. **Stripping hides names, not data.** Secrets in a binary stay readable (B).
2. **Encoding beats `strings` and loses to anyone who looks.** A known-prefix crib breaks it in one pass (C). Also: my first XOR build was *silently undone by the compiler*, which constant-folded the decoder back to plaintext until the blob was marked `volatile`. Naive obfuscation is fragile even against your own toolchain.
3. **A secret that is used must exist in memory.** A debugger gets it at the moment of use (D).
4. **Anti-debug stops the casual attempt and costs the determined one a single breakpoint** (E, F). Frida/hooking frameworks do the same without a debugger.

## What it does and does not do against a toolkit like REA

Not tested directly: REA's decompiler back-ends (Ghidra/Hopper/IDA) are not installed in the test environment. The tests use their *inputs*: `strings`, `nm`, a debugger, a crib. A decompiler adds readable pseudocode; it does not change the memory/instrumentation results above.

| Attacker capability | With this repo's hardening | Honest effect |
|---|---|---|
| Unpack ASAR / read JS | bytecode + obfuscation + no sourcemaps | slower; not stopped |
| Attach to Electron main process | fuses off (`--inspect`, `RunAsNode`, `NODE_OPTIONS`) | **actually closed** for the stock route |
| Native decompile | stripped, hardened runtime | readable pseudocode, no names |
| Dynamic instrumentation | hardened runtime + library validation | blocks injection into *your signed* binary; a user who re-signs a modified copy still can |
| Capture traffic | pinning + short-lived tokens + nonce signing | replay and cloning of the API are blocked; **the client's own calls remain observable** |
| Extract a baked-in secret | n/a | **always possible** (see C, D, F). Do not bake in secrets. |

So: it will not make a tool like REA "trash". The tool still opens your artifact. The difference is what it finds:
a signed UI shell with no secrets, whose network calls are bound to short-lived attested tokens, with logic that lives on your server.

## The layer that actually works
Move value server-side (`src/server/token.js`, `templates/server/express-example.js`). Reverse engineering the client then yields an
API schema, not your product. Everything else in this repo exists to protect the part you could not move.

### What survives even a server-side design: black-box extraction (`test/extraction.test.js`)
If the logic is on your server, reading the client reveals nothing about it. The attacker's remaining move is to query your API from a valid account and fit a clone. Measured on a hidden 5-weight scoring model:

| API behaviour | Attacker result |
|---|---|
| open, full-precision outputs | **exact clone after 5 queries** |
| outputs coarsened (step 5), no limits | weights within 0.35 after 5,000 queries (~10% accurate) |
| + 50-query quota per account | capped at 50 queries; clone error 0.74 (**>2x worse**) |
| attacker opens 100 fake accounts | back to 0.35: quotas fall to Sybil accounts |

Takeaway: expose the least precision the product needs, cap queries per identity, and make identities expensive (attestation, payment, phone/ID verification). That is a real defence for logic, but it is a cost wall, not a proof.

## Things this repo's modules cannot do (read before relying on them)
- **Token/nonce signing** proves a request came from a client holding a *current session key*. A user running the genuine client holds one. Without real device attestation (App Attest / Play Integrity / Turnstile) a patient attacker automating the real client still gets through. Add attestation + server-side behavioural limits.
- **Canaries** only detect an attacker who *uses* what they found against your server.
- **Watermark** (`watermark.js`) is an invisible-character mark; one regex strips it (there is a test asserting exactly that). It catches careless leaks.
- **Scanner** is heuristic. On vendored libraries it flags test keys (e.g. an SSH library's built-in probe key); triage findings, don't trust them blindly. It covers Electron fuses/ASAR, sourcemaps, secrets in text and binaries, macOS signing/entitlements/symbols, Go/Rust metadata. It does not analyse obfuscation quality, Windows/Linux signing, or Android/iOS packages.
- **Not covered:** hardware attacks, a malicious OS, a user with unlimited time. Offline software with no server has a hard ceiling.

## Recommended order of effort
1. Remove every embedded secret; move valuable logic server-side.
2. Short-lived attested tokens, nonce-signed requests, server rate limits.
3. Ship a hardened, signed, notarized build (templates/); no sourcemaps; fuses off.
4. Run `reverseproof scan` on every release in CI.
5. Add canaries; log and alert on trips.
6. Only then consider obfuscation for the few modules that must stay on the client.
