# Security policy

reverseproof is a defensive tool. It makes reverse engineering more expensive; it does not make it impossible
(see [docs/VERDICT.md](docs/VERDICT.md)). Please do not describe it, or let users believe it is, a guarantee.

**Report a vulnerability** (e.g. a flaw in `src/server/*` that weakens token/nonce/canary checks, or a scanner
bug that reads files unsafely) via GitHub's private "Report a vulnerability" button on the Security tab.
Do not open a public issue for those.

**False negatives/positives in the scanner** are normal bugs: open an issue with the (sanitised) artifact type and finding id.
