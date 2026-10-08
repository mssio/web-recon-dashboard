# Web Recon Dashboard — Design Spec

**Date:** 2026-10-08
**Status:** Draft — pending review
**Time budget:** ~1 hour (hackathon)

## Purpose

A simple, self-authorized web security recon tool: the user enters a domain
they own or have explicit permission to test, and the tool runs a handful of
non-intrusive, read-only checks (DNS, HTTP headers, TLS, HTTPS redirect,
robots.txt/sitemap) and renders a scored report in the browser. No
exploitation, no scanning beyond standard web requests — purely informational
recon against a target the user controls.

**Audience:** hackathon demo judges + the user, run locally.

**Success criteria:**
- User can enter a domain, click "Scan", and see a scored report within a
  few seconds.
- Report clearly shows pass/warn/fail per check with a short human-readable
  explanation.
- Runs via Docker on the user's machine with one `docker run` command.

## Non-goals (explicit scope cuts)

- No authentication/login
- No scan history or persistence (no database)
- No port scanning, subdomain enumeration, or active exploitation
- No PDF/report export
- No rate limiting or multi-user concerns
- No automated test suite (manual smoke test only, given the time budget)

## Architecture

Two pieces, no database:

```
                 ┌─────────────────────┐
  Browser        │   Express server     │
  (index.html +  │   server.js          │
  app.js)  ───────►  POST /scan          │
            JSON  │   { domain }         │
  ◄───────────────│                      │
  report JSON     │  runs checks:        │
                   │  - DNS               │
                   │  - HTTP headers      │
                   │  - TLS cert          │
                   │  - HTTPS redirect    │
                   │  - robots/sitemap    │
                   └─────────────────────┘
```

- **`server.js`** — Express app. Serves static files from `public/`. Single
  endpoint `POST /scan` accepting `{ "domain": "example.com" }`, returns a
  JSON report (see Data Model below).
- **`public/index.html`** — single page: domain input, "Scan" button,
  results container. No framework, no build step.
- **`public/app.js`** — vanilla JS: on submit, `fetch('/scan', ...)`, renders
  returned JSON into styled cards with pass/warn/fail badges and an overall
  score.
- **`public/style.css`** — basic styling for cards/badges/score.
- **`Dockerfile`** — `node:20-alpine` base, installs prod deps, runs
  `node server.js`, exposes port 3000.

Stateless request/response — no persistence between scans.

## Checks (5 total)

Each check is an independent async function that takes a domain and returns
`{ name, status: "pass"|"warn"|"fail", message }`. A failure in one check
never aborts the others — each is wrapped in its own try/catch.

1. **DNS resolution** — resolve A/AAAA and MX/NS records (Node `dns.promises`).
   - pass: A/AAAA records found
   - warn: resolves but no MX records (informational, not necessarily bad)
   - fail: NXDOMAIN / no records resolve

2. **HTTP security headers** — `fetch https://<domain>/`, inspect response
   headers: `Content-Security-Policy`, `Strict-Transport-Security`,
   `X-Frame-Options`, `X-Content-Type-Options`.
   - pass: all 4 present
   - warn: 1–3 present
   - fail: none present, or request fails

3. **TLS certificate** — `tls.connect({host, port:443, servername:host})`,
   inspect `getPeerCertificate()` validity dates.
   - pass: valid, >30 days to expiry
   - warn: valid, <30 days to expiry
   - fail: expired, self-signed/invalid, or connection fails

4. **HTTPS redirect** — `fetch http://<domain>/` (plain HTTP, no redirect
   follow), check if response is a 3xx redirecting to `https://`.
   - pass: HTTP redirects to HTTPS
   - warn: HTTP serves content directly without redirect (not necessarily
     unreachable, just not enforcing HTTPS)
   - fail: HTTP request fails entirely (host unreachable on port 80)

5. **robots.txt / sitemap.xml presence** — `fetch https://<domain>/robots.txt`
   and `/sitemap.xml`.
   - pass: both present (200)
   - warn: one present
   - fail: neither present (404/error on both)

## Data Model

Request:
```json
{ "domain": "example.com" }
```

Response:
```json
{
  "domain": "example.com",
  "score": 80,
  "checks": [
    { "name": "DNS Resolution", "status": "pass", "message": "A record found: 93.184.216.34" },
    { "name": "HTTP Security Headers", "status": "warn", "message": "2 of 4 recommended headers present" },
    { "name": "TLS Certificate", "status": "pass", "message": "Valid, expires in 62 days" },
    { "name": "HTTPS Redirect", "status": "pass", "message": "HTTP redirects to HTTPS" },
    { "name": "robots.txt / sitemap.xml", "status": "warn", "message": "robots.txt found, sitemap.xml missing" }
  ]
}
```

Score formula: pass = 1 point, warn = 0.5 point, fail = 0 points, out of 5
checks, scaled to 100 (e.g., 4 points / 5 = 80).

## Error Handling

- Missing/empty `domain` in request body → `400 { error: "domain is required" }`.
- Domain fails basic format validation (no spaces, has at least one `.`) →
  `400 { error: "invalid domain" }`.
- Each individual check catches its own errors internally and reports
  `status: "fail"` with a descriptive message (e.g., "could not connect")
  rather than throwing — the `/scan` endpoint always returns 200 with a full
  report as long as the domain itself is well-formed.
- Frontend shows a simple error banner if the `/scan` request itself fails
  (network error, 400, 500).

## Docker

```dockerfile
FROM node:20-alpine
WORKDIR /app
COPY package*.json ./
RUN npm ci --omit=dev
COPY . .
EXPOSE 3000
CMD ["node", "server.js"]
```

Run with:
```
docker build -t web-recon-dashboard .
docker run -p 3000:3000 web-recon-dashboard
```

No `docker-compose.yml` needed for a single-container app with no dependent
services — plain `docker run` is simpler given the time budget.

## Testing

Given the 1-hour budget: manual smoke test only.
- Scan a real domain (e.g., `anthropic.com`) and confirm all 5 checks render
  with sensible statuses.
- Scan an invalid domain and confirm the 400 error path shows a clear error
  in the UI.
- Scan a domain with no HTTPS to confirm checks degrade gracefully
  (warn/fail, not a crash).

No automated test suite — explicitly out of scope per the time budget.

## File Structure

```
hackathon/
├── server.js
├── package.json
├── Dockerfile
├── .dockerignore
├── docs/superpowers/specs/2026-10-08-web-recon-dashboard-design.md
└── public/
    ├── index.html
    ├── app.js
    └── style.css
```
