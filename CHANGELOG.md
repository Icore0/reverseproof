# Changelog
## 0.1.0
- `scan`: Electron fuses/ASAR, sourcemaps, secrets (text + binaries), macOS signing/entitlements/symbols, Windows PE, Linux ELF, Go/Rust metadata.
- `audit`: lockfiles, pinned deps/actions, workflow injection, committed secrets, secrets in git history, hygiene files.
- Server modules: tokens + request signing, canaries, watermark, quotas, abuse scoring.
- Experiments: native toy (strings/nm/crib/lldb), JS obfuscation + bytenode, API extraction.
- Corrected during testing: bytecode does not hide strings; heavy obfuscation is very slow; benchmark timing is machine-dependent.
