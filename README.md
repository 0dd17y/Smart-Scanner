# Smart Scan

An authorized web-portal security scanner with a live, animated SOC-console UI.
You enter a target URL, pick an intensity, and a local Node backend runs real checks
against the site while the browser streams verbose, color-coded output with a radar
sweep, matrix background, per-phase cards, a progress ring, and a final A–F grade.

It also includes an interactive version of the OWASP-based *Bug Bounty Checklist*
(`Checklist.pdf`) for the items that require manual human testing.

> ⚠️ **Authorization notice.** Only scan systems you own or are explicitly authorized
> to test — e.g. your own UAT/staging portals. Aggressive mode performs brute-force,
> content fuzzing and a bounded rate-limit stress test that can disrupt a running app.
> Do not point this at production or third-party sites.

## Requirements

- Node.js 18+ (uses built-in `fetch`, `https`, `tls`).

## Install & run

```bash
npm install
npm start
# open http://localhost:3000
```

## Try it safely (no external target needed)

A deliberately-insecure local app is bundled for demos/verification:

```bash
npm run test-target      # starts http://localhost:4000 (INSECURE on purpose)
```

Then in the UI, tick the authorization box and scan `http://localhost:4000` at
**Aggressive** intensity. You should see real findings stream in: missing security
headers, exposed `/.env`, insecure/low-entropy session cookie, reflected XSS,
error-based SQL injection, SSTI, open redirect, default credentials accepted, no
brute-force protection, and no rate limiting — ending with grade **F**.

## Intensity levels

| Level | What runs |
|-------|-----------|
| **Passive** | Headers, TLS/cert, cookies, exposed files, CORS, methods, fingerprint. No injection. |
| **Active** (default) | Everything in Passive **plus** non-destructive injection probes (XSS, SQLi error/boolean, SSTI, open redirect, LFI, command-injection, CRLF, NoSQL) into discovered parameters. |
| **Aggressive** | Everything in Active **plus** ~50 additional active checks across five modules (below), credential brute-force / default-creds, ffuf-style content discovery, and a bounded anti-automation / rate-limit stress test. Requires an extra confirmation. |

Aggressive options (attempt caps, wordlist size, request volume, IDOR id-tests,
large-body size) are set in the UI and are always finite — no unbounded loops or floods.

### Aggressive check modules (50 in-band checks)

All detection is **in-band** (error signatures, response diffs, timing, reflected
internal data) — no out-of-band callback server is needed.

- **Advanced Injection** (`injectionAdvanced.js`) — XXE, multi-engine SSTI, LDAP, XPath,
  SSRF, prototype pollution, host-header injection, request smuggling (heuristic), cache
  poisoning, SSI, EL/OGNL, XSLT, CSV/formula, NoSQL operators, GraphQL introspection,
  deserialization markers, mass assignment, HPP, blind time-based command injection.
- **Authentication Attacks** (`authAttacks.js`) — JWT `alg`/weak-secret/`kid`, password
  spraying, credential stuffing, username enumeration, session fixation, token-entropy
  sampling, lockout bypass, reset-token predictability, OAuth `redirect_uri`, OTP
  rate-limit, remember-me weakness, verb-based auth bypass, missing re-auth.
- **Access Control / IDOR** (`accessControl.js`) — IDOR, forced browsing, vertical
  priv-esc, HTTP method tampering (incl. PUT upload), path-ACL bypass, deep traversal,
  CORS credentialed exploitation.
- **Infrastructure & Exposure** (`infraAttacks.js`) — actuator/debug endpoints, cloud
  metadata reachability, subdomain takeover, VCS repo dump, backup-archive brute, vhost
  bypass.
- **Advanced DoS (bounded)** (`dosAdvanced.js`) — request body-size limit, ReDoS /
  algorithmic complexity.

Wordlists for these live in `server/scanner/wordlists/` (`jwt-secrets.txt`,
`usernames.txt`, `passwords.txt`) and are editable.

## How it works

- `server/index.js` — Express app; serves the UI and the SSE scan stream
  (`GET /api/scan/stream`), the checklist (`GET /api/checklist`), and an HTML report
  (`POST /api/report`).
- `server/scanner/orchestrator.js` — runs the scan phases in order and streams events.
- `server/scanner/httpClient.js` — Node `https`/`tls` client with concurrency + total
  request caps, raw header/cookie access, and certificate inspection.
- `server/scanner/crawler.js` — bounded same-origin crawl that discovers parameters and
  forms to feed the injection / auth / brute-force phases.
- `server/scanner/modules/*.js` — one module per check category.
- `server/scanner/wordlists/` — `dirs.txt` and `creds.txt` (edit to suit your UAT env).
- `public/` — the animated single-page console (`animations.js` is hand-rolled canvas).

## Reports

After a scan, use **Download HTML report** or **Download JSON** in the summary bar.
Findings include severity, evidence, remediation, and an OWASP reference.

## Safety design

- Requires an explicit "I am authorized" confirmation before any scan.
- Same-origin scoping for active probes; global concurrency/rate caps.
- Non-destructive probes; aggressive checks are opt-in, capped, and clearly labelled.
- Detections guard against reflection-only false positives (e.g. command injection and
  CRLF require evidence of execution / a genuinely split header, not mere reflection).

Built for authorized testing of your own web portals.
