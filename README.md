# reverseproof

Raise the cost of reverse-engineering your app, and make a stolen client worthless.
Zero dependencies. Node ≥ 20. Honest about limits: read [docs/VERDICT.md](docs/VERDICT.md) first.

> **It will not make reverse engineering impossible, and no tool can.** It audits what you ship, closes the cheap doors, and gives you server-side pieces that make extraction pointless.

## What's inside

| Part | What it does | Tested by |
|---|---|---|
| `reverseproof scan <app\|dir\|binary>` | Finds what a reverse engineer gets for free: shipped/inline sourcemaps, secrets in text/ASAR/binaries, Electron fuse state, missing ASAR integrity, macOS hardened-runtime / dangerous entitlements / symbols, Go & Rust metadata. Exits 1 on high findings (use in CI). | `test/scan.test.js`, real Electron apps |
| `src/server/token.js` | Short-lived tokens, per-session request signing, replay guard. A cloned client can't mint tokens; a captured request can't be replayed. | `test/server.test.js` |
| `src/server/canary.js` | Stateless honeytokens + middleware: fake keys in your client; any use trips an alert. | `test/server.test.js` |
| `src/server/watermark.js` | Per-recipient invisible text mark to trace leaks (weak by design, documented). | `test/server.test.js` |
| `templates/` | Electron fuse flipper (afterPack), JS obfuscator config, Rust/Go release builds, macOS sign + hardened runtime + empty entitlements, nginx sourcemap block, Express wiring example. | syntax-checked |
| `examples/toy` + `test/toy.test.js` | A toy app built 5 ways and attacked with `strings`, `nm`, an XOR crib and lldb. The evidence behind the verdict. | `test/toy.test.js` |

## Use

```bash
npx reverseproof scan "/path/to/YourApp.app"     # or a dist/ folder, or a single binary
npx reverseproof scan dist --json                # for CI; exit code 1 if any HIGH
npm test                                         # unit tests + the attack experiments (macOS arm64 for the toy tests)
```

Server side:

```js
const { issueToken, verifyRequest, NonceGuard } = require('reverseproof/src/server/token');
const { makeCanary, canaryGuard } = require('reverseproof/src/server/canary');
```
See `templates/server/express-example.js`.

## The strategy in six lines
1. **Don't ship secrets; move valuable logic to your server.** (The only layer that truly works.)
2. Short-lived, attested tokens + nonce-signed requests + server-side rate limits.
3. Hardened, signed, notarized builds; Electron fuses off; no sourcemaps; stripped symbols.
4. Scan every release: `reverseproof scan` in CI.
5. Plant canaries; alert on use.
6. Obfuscate only the few client modules that must stay, and treat it as a speed bump.

## Limits (see the verdict for evidence)
Anything running on a user's device can eventually be read. Debuggers recover decoded secrets from memory; anti-debug is one breakpoint away from bypass; watermarks strip with one regex. Offline apps have a hard ceiling.

## License
MIT
