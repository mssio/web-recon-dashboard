# Web Recon Dashboard

A small web app that runs a set of **non-intrusive security checks** against a domain you own (or have permission to test) and shows the result as a scored, visual report: DNS, HTTP security headers, TLS certificate, HTTPS redirect, `robots.txt`/`sitemap.xml`, technology and vendor fingerprinting, and an optional open-port check.

It is stateless (no database, no accounts), has a single API endpoint, and ships as one Docker container.

> **Use it only on domains you own or have explicit permission to test.** See [Responsible use](#responsible-use).

---

## Quick start

### With Docker (recommended)

```bash
docker build -t web-recon-dashboard .
docker run --rm -p 3000:3000 web-recon-dashboard
```

Open <http://localhost:3000>, type a domain, press **Scan**.

### Without Docker

Requires Node.js 20 or newer (the app relies on the built-in `fetch` and `AbortSignal.timeout`).

```bash
npm install
npm start
```

### Configuration

| Variable | Default | Purpose |
|---|---|---|
| `PORT` | `3000` | Port the server listens on. |
| `ALLOW_PRIVATE_TARGETS` | unset | Set to `1` to let the **port probe** target private, loopback or reserved addresses (e.g. a lab machine). Off by default. |

```bash
docker run --rm -p 3000:3000 -e ALLOW_PRIVATE_TARGETS=1 web-recon-dashboard
```

---

## How it works

```
 Browser (public/)                          Express server (server.js)
 ┌──────────────────────┐  POST /scan       ┌─────────────────────────────────────┐
 │ index.html           │  {domain,         │ 1. validate + normalise the domain  │
 │ app.js  ─────────────┼──authorized}────► │ 2. runAllChecks(domain, options)    │
 │ style.css            │                   │      │                              │
 │ Chart.js (CDN)       │ ◄──── JSON ────── │      ├─ checkDns          (dns)     │
 │                      │  {domain, score,  │      ├─ fetchHome ─┬─ checkHeaders  │
 │ gauge · radar chart  │   checks[]}       │      │  (one GET)  └─ detectTech    │
 │ finding cards        │                   │      ├─ checkTls          (tls)     │
 └──────────────────────┘                   │      ├─ checkHttpsRedirect         │
                                            │      ├─ checkRobotsSitemap         │
                                            │      └─ checkPorts   (net, opt-in) │
                                            │ 3. score the scored checks          │
                                            └─────────────────────────────────────┘
```

### Request flow

1. The browser sends `POST /scan` with the domain and whether the user ticked the authorization box.
2. The server **normalises** the input (trims, lowercases, strips `http(s)://` and any path) and **validates** it (non-empty, no whitespace, contains a dot).
3. All checks run **concurrently** with `Promise.all`. The homepage is fetched **once** and shared by the header check and the technology fingerprint.
4. Each check is wrapped so that a failure or crash in one becomes a `fail` result for that check instead of breaking the scan.
5. The server computes the score and returns one JSON report. The page renders it; nothing is stored.

### The checks

Every check returns `{ name, status, message, details }`.

| Check | What it does | Status rules |
|---|---|---|
| **DNS Resolution** | Looks up A, AAAA and MX records in parallel with a bounded resolver. | `fail` no A/AAAA record · `warn` resolves but no MX · `pass` otherwise |
| **HTTP Security Headers** | Inspects the homepage response for `Content-Security-Policy`, `Strict-Transport-Security`, `X-Frame-Options`, `X-Content-Type-Options`. Also reports Referrer-Policy, Permissions-Policy and the cross-origin headers, and lists **findings**: short HSTS max-age, CSP with `unsafe-inline`/`unsafe-eval`/wildcards, version-revealing `Server` / `X-Powered-By`, `Access-Control-Allow-Origin: *`, cookies missing `Secure` / `HttpOnly` / `SameSite`. | `pass` all 4 present · `warn` 1–3 · `fail` none or request failed. Findings are informational and do not change the status. |
| **TLS Certificate** | Opens a TLS connection to port 443 and reads the certificate: issuer, validity dates, days left. | `fail` expired, untrusted or unreachable · `warn` under 30 days left · `pass` otherwise |
| **HTTPS Redirect** | Requests `http://domain/` without following redirects. | `pass` redirects to `https://` · `warn` redirects elsewhere or serves content over HTTP · `fail` request failed |
| **robots.txt / sitemap.xml** | Requests both files over HTTPS. | `pass` both found · `warn` one · `fail` neither |
| **Technology Stack** | Passive fingerprint from the homepage's headers, cookies and HTML: web server, CDN/hosting vendor, CMS, frontend framework, JS libraries, language/runtime, analytics, captcha/payments. Makes **no extra requests**. | Always `info` (not scored) |
| **Open Ports & Services** | TCP connect test against 22 well-known ports (21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 465, 587, 993, 995, 1433, 3306, 3389, 5432, 6379, 8080, 8443, 27017). Sends no data and reads no banners. Service names are inferred from the port number, not verified. | `fail` a sensitive service (FTP, Telnet, SMB, SQL Server, MySQL, RDP, PostgreSQL, Redis, MongoDB) is reachable · `warn` nothing answered · `pass` otherwise · `skip` when not authorized or the target is private |

### Scoring

- `pass` = 1 point, `warn` = 0.5, `fail` = 0.
- Score = points ÷ number of **scored** checks × 100, rounded.
- `info` and `skip` results are displayed but excluded from the score and from the radar chart.
- Gauge colour and verdict: **80+ Strong**, **50–79 Needs work**, **below 50 At risk**.

### Timeouts

| Operation | Limit |
|---|---|
| HTTP requests (headers, redirect, robots, sitemap) | 5 s |
| TLS handshake | 5 s |
| Each DNS query | 2 s, 1 try |
| Each port connection | 1.5 s (ports are tried in parallel) |
| Homepage body read for fingerprinting | first 200,000 characters only |

---

## API

### `POST /scan`

Request body (JSON):

```json
{ "domain": "example.com", "authorized": false }
```

- `domain` — required. Scheme, path and case are normalised away (`https://EXAMPLE.com/a` → `example.com`).
- `authorized` — optional. Must be exactly `true` to run the active port probe; anything else skips it.

Response `200`:

```json
{
  "domain": "example.com",
  "score": 50,
  "checks": [
    {
      "name": "TLS Certificate",
      "status": "pass",
      "message": "Valid, expires in 77 days",
      "details": { "issuer": "...", "validFrom": "...", "validTo": "...", "daysLeft": 77 }
    }
  ]
}
```

`status` is one of `pass`, `warn`, `fail`, `info`, `skip`. `details` is a flat object whose values are strings, numbers, booleans or arrays of strings.

Errors: `400 {"error":"domain is required"}`, `400 {"error":"invalid domain"}`, `500 {"error":"scan failed"}`.

```bash
curl -s -X POST http://localhost:3000/scan \
  -H 'Content-Type: application/json' \
  -d '{"domain":"example.com"}'
```

Everything else is served as static files from `public/`.

---

## Tech stack

| Layer | Technology | Why |
|---|---|---|
| Runtime | **Node.js 20** | Built-in `fetch`, `AbortSignal.timeout`, `dns`, `tls` and `net` cover every check; no scanner libraries needed. |
| Backend | **Express 4** | The only runtime dependency; serves static files and one JSON endpoint. |
| Frontend | **Vanilla HTML, CSS and JavaScript** | No build step, no framework. |
| Charts | **Chart.js 4.4.1** (loaded from cdnjs) | Radar chart of the scored checks. The browser needs internet access to load it; without it the page works and just omits the chart. |
| Graphics | Inline SVG, CSS animations | Logo, score gauge and scanning animation. Animations respect `prefers-reduced-motion`. |
| Packaging | **Docker** (`node:20-alpine`) | One container, `npm ci --omit=dev`. |

Node's standard library does the heavy lifting: `dns.Resolver` (DNS), `tls.connect` (certificate), `net.connect` (port probe), global `fetch` (HTTP checks).

---

## Project structure

```
.
├── server.js        Express app: static files, POST /scan, input normalisation + validation
├── checks.js        DNS, headers, TLS, redirect, robots/sitemap checks; runAllChecks + scoring
├── fingerprint.js   Passive technology / vendor detection (signature table)
├── ports.js         Opt-in TCP connect probe with safety guardrails
├── public/
│   ├── index.html   Page structure (hero, form, overview, findings grid)
│   ├── app.js       Form handling, scanning state, gauge, radar chart, card rendering
│   ├── style.css    Layout (1 / 2 / 3 column grid), theme, animations
│   └── logo.svg     Logo and favicon
├── Dockerfile
├── docs/superpowers/  Original design spec and implementation plan (see note below)
└── package.json
```

### Front-end layout

The report is a full-width dashboard: an **overview row** (score gauge beside the radar chart, plus counts of passed / warning / failed / informational / skipped checks) followed by a **findings grid** that is 1 column on phones, 2 from 760 px and 3 from 1180 px. The page uses semantic headings and landmarks, a skip link, visible focus rings, 48 px touch targets, and announces the scan result to screen readers.

---

## Security notes

- **No HTML injection from scanned sites.** Everything a target returns (header values, cookie names, banners) is rendered with `textContent` / `createElement`, never `innerHTML`.
- **Port probe guardrails.** It is opt-in (the `authorized` flag must be exactly `true`), refuses private / loopback / link-local / reserved addresses unless `ALLOW_PRIVATE_TARGETS=1`, and connects to the already-resolved IP so the address cannot change between lookup and connection.
- **Server-side requests.** The HTTP, TLS and DNS checks make outbound requests to whatever hostname is submitted. That is fine for a single-user local tool; if you ever expose this publicly, add authentication, rate limiting, and a private-range block that covers *all* checks, not only the port probe.

## Responsible use

Only scan systems you own or are explicitly authorized to test. The checks are deliberately light (read-only requests and plain connection attempts, no exploitation, no credential guessing, no banner grabbing), but unauthorized scanning can still be illegal or violate a provider's terms.

---

## Limitations

- Fingerprinting is signature-based and best-effort; it can miss or misattribute technologies, especially behind a CDN or on JavaScript-rendered sites (it reads the initial HTML only).
- Only IPv4 addresses are probed for ports, and only the first A record is used.
- Domain normalisation does not strip ports or query strings (`example.com:8443` is passed through as written).
- Only the homepage is analysed, and only the first redirect hop of the HTTP→HTTPS check.
- Scan progress messages in the UI are cosmetic; the backend returns a single response when all checks finish.

## Testing

There is no automated test suite; this started as a time-boxed hackathon project and was verified manually. A quick smoke test against a running container:

```bash
curl -s localhost:3000/ | grep "Web Recon Dashboard"
curl -s -X POST localhost:3000/scan -H 'Content-Type: application/json' -d '{"domain":"example.com"}'
curl -s -X POST localhost:3000/scan -H 'Content-Type: application/json' -d '{"domain":"not a domain"}'   # {"error":"invalid domain"}
```

## Design documents

`docs/superpowers/specs/` and `docs/superpowers/plans/` hold the original design spec and implementation plan. They describe the first version (five checks, plain card list); the project has since grown, so **this README is the source of truth** for current behaviour.
