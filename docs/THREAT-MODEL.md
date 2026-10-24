# Threat model template (do this before buying or building any protection)

Reverse engineering the client is one threat among many. Fill this in for your product; the table at the end maps each
row to what this repo covers and, just as important, what it does not.

## 1. What is valuable? (rank, max 5)
Algorithms / models / prompts, customer data, credentials, pricing logic, licence enforcement, the brand, uptime.

## 2. Who attacks it, and what do they want?
| Attacker | Wants | Typical skill/budget |
|---|---|---|
| Curious user / tinkerer | free features, cheats | low, hours |
| Competitor | your algorithm, your data, a clone | medium, weeks, can pay for accounts |
| Scraper / data broker | your dataset via the API | automation, proxies, thousands of accounts |
| Cracker / pirate | licence bypass, redistribution | medium, patient |
| Criminal | credentials, customer data, ransom | high, targeted phishing and supply chain |
| Insider / ex-employee | everything they had access to | has legitimate access |
| Nation-state | a specific target | very high |

## 3. Where can each valuable asset be reached?
Client binary · network traffic · your API (black-box queries) · your servers/cloud · CI/CD and dependencies · employees' laptops and accounts · third-party vendors.

## 4. Decide per asset: remove, move, protect, or accept
- **Remove**: do not store/ship it at all.
- **Move**: put it on the server (the only strong answer for client-side secrets and logic).
- **Protect**: add cost and detection (this repo's layers).
- **Accept**: write down the residual risk and who signed off.

## 5. Coverage map

| Threat | In this repo | Not covered (you need other controls) |
|---|---|---|
| Client static analysis (strings, sourcemaps, symbols) | `scan` for Electron/JS, macOS Mach-O, Windows PE, Linux ELF, Go/Rust metadata | quality of obfuscation; Android/iOS packages |
| Client dynamic analysis (debugger, hooks) | measured: delays only (see VERDICT) | nothing stops a determined attacker on their own machine |
| Secrets in code/history | `scan`, `audit` (text, binaries, git history) | secrets managers, rotation policy |
| API cloning / extraction | tokens, nonce signing, quotas, coarsening, `abuse.js` | strong identity (attestation, payment, ID), legal terms |
| Scraping / enumeration | `abuse.js` behavioural scoring, Sybil clustering | residential-proxy fleets with human-like timing evade it (tested) |
| CI/CD and supply chain | `audit`: lockfiles, pinned actions, workflow injection, pwn-requests | build provenance (SLSA), signed releases, dependency review |
| Server / cloud compromise | none | IAM, network segmentation, patching, WAF, EDR |
| Phishing / account takeover | none | MFA/passkeys, device trust, security training |
| Insider threat | none (canaries help detect misuse of leaked data) | least privilege, access logging, offboarding |
| Third-party vendors | none | contracts, SOC 2 reviews, minimal data sharing |
| Unknown vulnerabilities | none | pentests, bug bounty, code review |

## 6. Review
Re-run when you add a feature, a vendor, or a data type; after every incident; at least yearly.
