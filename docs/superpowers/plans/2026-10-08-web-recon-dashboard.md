# Web Recon Dashboard Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a one-page web dashboard that scans a domain the user owns/controls and renders a scored, non-intrusive security recon report (DNS, HTTP headers, TLS, HTTPS redirect, robots/sitemap), running in Docker.

**Architecture:** Express backend (`server.js` + `checks.js`) serving a static vanilla-JS frontend (`public/`), stateless, no database. A single `POST /scan` endpoint runs 5 independent checks concurrently and returns one JSON report.

**Tech Stack:** Node.js 20, Express 4, vanilla HTML/CSS/JS (no build step), Docker (`node:20-alpine`).

**Spec:** `docs/superpowers/specs/2026-10-08-web-recon-dashboard-design.md`

## Global Constraints

- No database — fully stateless request/response (per spec Architecture).
- No authentication, no scan history/persistence (per spec Non-goals).
- No automated test suite — spec explicitly scopes this out given the 1-hour
  budget. Every task below replaces "write a failing test" with "write a
  manual verification step" (curl command or browser check) instead. This
  is an intentional, spec-approved deviation from this skill's default TDD
  step shape.
- Single container via plain `docker run` — no `docker-compose.yml` (per
  spec Docker section).
- Base image: `node:20-alpine` (per spec Docker section).
- Frontend has no build step — plain `<script>`/`<link>` tags, no bundler
  (per spec Architecture).
- Score formula: pass = 1 point, warn = 0.5 point, fail = 0 points, summed
  over 5 checks, scaled to 100 (per spec Data Model).

## Review Focus

- User enters a domain with a scheme prefix (`https://example.com`) — the
  app should strip it and scan the bare host, not fail or double-prefix it
  in later fetch calls. Covered in Task 3/4.
- User enters a domain with a path or trailing slash (`example.com/foo`) —
  the app should scan the bare host, not pass a path into DNS/TLS calls.
  Covered in Task 3/4.
- Domain does not exist (NXDOMAIN) — all 5 checks must degrade to
  `fail`/descriptive-message independently, never throw an unhandled
  rejection that crashes the request. Covered in Task 4.
- Host is slow or unresponsive — without a timeout, a hung TCP/TLS
  connection could block `/scan` indefinitely. Each network check gets a
  bounded timeout (5s) so the endpoint always responds. Covered in Task 4.
- Domain entered in mixed case (`EXAMPLE.com`) — should be normalized to
  lowercase before use so DNS/TLS/display are consistent. Covered in
  Task 3.

---

### Task 1: Project Scaffold

**Files:**
- Create: `package.json`
- Create: `.gitignore`

**Interfaces:**
- Produces: an `express` dependency installed and available to `require('express')` in later tasks.

- [ ] **Step 1: Write `package.json`**

```json
{
  "name": "web-recon-dashboard",
  "version": "1.0.0",
  "description": "Simple web security recon dashboard for domains you own or control",
  "main": "server.js",
  "scripts": {
    "start": "node server.js"
  },
  "dependencies": {
    "express": "^4.19.2"
  }
}
```

- [ ] **Step 2: Install dependencies**

Run: `npm install`
Expected: `node_modules/` created, `package-lock.json` created, no errors.

- [ ] **Step 3: Write `.gitignore`**

```
node_modules/
*.log
```

- [ ] **Step 4: Commit**

```bash
git add package.json package-lock.json .gitignore
git commit -m "Scaffold project: package.json and express dependency

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>"
```

---

### Task 2: Static File Server Skeleton

**Files:**
- Create: `server.js`
- Create: `public/index.html`

**Interfaces:**
- Consumes: `express` from `package.json` (Task 1).
- Produces: an HTTP server listening on `process.env.PORT || 3000`, serving `public/` as static files. Later tasks modify `server.js` to add routes.

- [ ] **Step 1: Write `server.js`**

```js
const express = require('express');
const path = require('path');

const app = express();
app.use(express.static(path.join(__dirname, 'public')));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Web Recon Dashboard listening on port ${PORT}`);
});
```

- [ ] **Step 2: Write placeholder `public/index.html`**

```html
<!DOCTYPE html>
<html>
<head><title>Web Recon Dashboard</title></head>
<body>
  <h1>Web Recon Dashboard</h1>
  <p>Coming soon.</p>
</body>
</html>
```

- [ ] **Step 3: Manually verify the server starts and serves the page**

Run: `node server.js` (in one terminal), then in another: `curl -s http://localhost:3000/`
Expected: the curl output contains `<h1>Web Recon Dashboard</h1>`. Stop the server with Ctrl+C after confirming.

- [ ] **Step 4: Commit**

```bash
git add server.js public/index.html
git commit -m "Add static file server skeleton

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>"
```

---

### Task 3: Domain Validation + `/scan` Stub Endpoint

**Files:**
- Modify: `server.js`

**Interfaces:**
- Produces: `normalizeDomain(input: string) => string` and `isValidDomain(domain: string) => boolean`, both used by Task 4's final `/scan` handler.
- Produces: `POST /scan` route that validates input and currently returns a stub `{ domain, score: 0, checks: [] }` — Task 4 replaces the stub body with real checks.

- [ ] **Step 1: Modify `server.js` to add JSON body parsing, normalization, validation, and the stub route**

```js
const express = require('express');
const path = require('path');

const app = express();
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

function normalizeDomain(input) {
  let value = String(input).trim().toLowerCase();
  value = value.replace(/^https?:\/\//, '');
  value = value.split('/')[0];
  return value;
}

function isValidDomain(domain) {
  if (typeof domain !== 'string') return false;
  if (domain.length === 0) return false;
  if (/\s/.test(domain)) return false;
  if (!domain.includes('.')) return false;
  return true;
}

app.post('/scan', (req, res) => {
  const { domain } = req.body || {};
  if (!domain) {
    return res.status(400).json({ error: 'domain is required' });
  }
  const normalized = normalizeDomain(domain);
  if (!isValidDomain(normalized)) {
    return res.status(400).json({ error: 'invalid domain' });
  }
  res.json({ domain: normalized, score: 0, checks: [] });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Web Recon Dashboard listening on port ${PORT}`);
});
```

- [ ] **Step 2: Manually verify validation and normalization**

Run: `node server.js` (in one terminal), then in another terminal run these three checks:

```bash
curl -s -X POST http://localhost:3000/scan -H 'Content-Type: application/json' -d '{"domain":""}'
curl -s -X POST http://localhost:3000/scan -H 'Content-Type: application/json' -d '{"domain":"https://EXAMPLE.com/some/path"}'
curl -s -X POST http://localhost:3000/scan -H 'Content-Type: application/json' -d '{}'
```

Expected:
- First call: `{"error":"domain is required"}` (empty string is falsy, so it hits the "required" check before normalization runs).
- Second call: `{"domain":"example.com","score":0,"checks":[]}` — confirms scheme, path, and case are stripped.
- Third call: `{"error":"domain is required"}`.

Stop the server with Ctrl+C after confirming.

- [ ] **Step 3: Commit**

```bash
git add server.js
git commit -m "Add domain validation, normalization, and /scan stub endpoint

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>"
```

---

### Task 4: Implement Recon Checks Module

**Files:**
- Create: `checks.js`
- Modify: `server.js:` the `/scan` handler (replace the stub body)

**Interfaces:**
- Consumes: `normalizeDomain`/`isValidDomain` from `server.js` (Task 3) — unchanged, still live there.
- Produces: `runAllChecks(domain: string) => Promise<{ domain: string, score: number, checks: Array<{name: string, status: 'pass'|'warn'|'fail', message: string}> }>`, exported from `checks.js`, consumed by `server.js`'s `/scan` route.

- [ ] **Step 1: Write `checks.js`**

```js
const dns = require('dns').promises;
const tls = require('tls');

async function checkDns(domain) {
  try {
    let aRecords = [];
    try {
      aRecords = await dns.resolve4(domain);
    } catch (_) {}
    let aaaaRecords = [];
    try {
      aaaaRecords = await dns.resolve6(domain);
    } catch (_) {}
    if (aRecords.length === 0 && aaaaRecords.length === 0) {
      return { name: 'DNS Resolution', status: 'fail', message: `Could not resolve any A/AAAA records for ${domain}` };
    }
    let mxRecords = [];
    try {
      mxRecords = await dns.resolveMx(domain);
    } catch (_) {}
    const firstAddr = aRecords[0] || aaaaRecords[0];
    if (mxRecords.length === 0) {
      return { name: 'DNS Resolution', status: 'warn', message: `A record found: ${firstAddr}, but no MX records` };
    }
    return { name: 'DNS Resolution', status: 'pass', message: `A record found: ${firstAddr}` };
  } catch (err) {
    return { name: 'DNS Resolution', status: 'fail', message: `DNS lookup failed: ${err.message}` };
  }
}

async function checkHeaders(domain) {
  const required = ['content-security-policy', 'strict-transport-security', 'x-frame-options', 'x-content-type-options'];
  try {
    const res = await fetch(`https://${domain}/`, { redirect: 'follow', signal: AbortSignal.timeout(5000) });
    const present = required.filter((h) => res.headers.has(h));
    if (present.length === required.length) {
      return { name: 'HTTP Security Headers', status: 'pass', message: 'All 4 recommended headers present' };
    }
    if (present.length === 0) {
      return { name: 'HTTP Security Headers', status: 'fail', message: 'None of the 4 recommended headers present' };
    }
    return { name: 'HTTP Security Headers', status: 'warn', message: `${present.length} of 4 recommended headers present` };
  } catch (err) {
    return { name: 'HTTP Security Headers', status: 'fail', message: `Could not fetch https://${domain}/: ${err.message}` };
  }
}

function checkTls(domain) {
  return new Promise((resolve) => {
    const socket = tls.connect({ host: domain, port: 443, servername: domain, timeout: 5000 }, () => {
      const cert = socket.getPeerCertificate();
      socket.end();
      if (!cert || !cert.valid_to) {
        resolve({ name: 'TLS Certificate', status: 'fail', message: 'Could not read certificate' });
        return;
      }
      const expiry = new Date(cert.valid_to);
      const daysLeft = Math.floor((expiry.getTime() - Date.now()) / (1000 * 60 * 60 * 24));
      if (daysLeft < 0) {
        resolve({ name: 'TLS Certificate', status: 'fail', message: `Certificate expired ${-daysLeft} days ago` });
      } else if (daysLeft < 30) {
        resolve({ name: 'TLS Certificate', status: 'warn', message: `Valid, expires in ${daysLeft} days` });
      } else {
        resolve({ name: 'TLS Certificate', status: 'pass', message: `Valid, expires in ${daysLeft} days` });
      }
    });
    socket.on('error', (err) => {
      resolve({ name: 'TLS Certificate', status: 'fail', message: `TLS connection failed: ${err.message}` });
    });
    socket.on('timeout', () => {
      socket.destroy();
      resolve({ name: 'TLS Certificate', status: 'fail', message: 'TLS connection timed out' });
    });
  });
}

async function checkHttpsRedirect(domain) {
  try {
    const res = await fetch(`http://${domain}/`, { redirect: 'manual', signal: AbortSignal.timeout(5000) });
    if (res.status >= 300 && res.status < 400) {
      const location = res.headers.get('location') || '';
      if (location.startsWith('https://')) {
        return { name: 'HTTPS Redirect', status: 'pass', message: 'HTTP redirects to HTTPS' };
      }
      return { name: 'HTTPS Redirect', status: 'warn', message: `HTTP redirects, but not to HTTPS (${location})` };
    }
    return { name: 'HTTPS Redirect', status: 'warn', message: 'HTTP serves content directly without redirecting to HTTPS' };
  } catch (err) {
    return { name: 'HTTPS Redirect', status: 'fail', message: `HTTP request failed: ${err.message}` };
  }
}

async function checkRobotsSitemap(domain) {
  const checkUrl = async (urlPath) => {
    try {
      const res = await fetch(`https://${domain}${urlPath}`, { signal: AbortSignal.timeout(5000) });
      return res.ok;
    } catch (_) {
      return false;
    }
  };
  const [hasRobots, hasSitemap] = await Promise.all([checkUrl('/robots.txt'), checkUrl('/sitemap.xml')]);
  if (hasRobots && hasSitemap) {
    return { name: 'robots.txt / sitemap.xml', status: 'pass', message: 'Both robots.txt and sitemap.xml found' };
  }
  if (hasRobots || hasSitemap) {
    const which = hasRobots ? 'robots.txt' : 'sitemap.xml';
    const missing = hasRobots ? 'sitemap.xml' : 'robots.txt';
    return { name: 'robots.txt / sitemap.xml', status: 'warn', message: `${which} found, ${missing} missing` };
  }
  return { name: 'robots.txt / sitemap.xml', status: 'fail', message: 'Neither robots.txt nor sitemap.xml found' };
}

async function runAllChecks(domain) {
  const results = await Promise.all([
    checkDns(domain),
    checkHeaders(domain),
    checkTls(domain),
    checkHttpsRedirect(domain),
    checkRobotsSitemap(domain),
  ]);
  const points = results.reduce((sum, r) => {
    if (r.status === 'pass') return sum + 1;
    if (r.status === 'warn') return sum + 0.5;
    return sum;
  }, 0);
  const score = Math.round((points / results.length) * 100);
  return { domain, score, checks: results };
}

module.exports = { checkDns, checkHeaders, checkTls, checkHttpsRedirect, checkRobotsSitemap, runAllChecks };
```

- [ ] **Step 2: Modify `server.js` to replace the stub `/scan` body**

Replace the stub line `res.json({ domain: normalized, score: 0, checks: [] });` with a real call. The route becomes:

```js
const { runAllChecks } = require('./checks');

// ... (keep normalizeDomain, isValidDomain as-is) ...

app.post('/scan', async (req, res) => {
  const { domain } = req.body || {};
  if (!domain) {
    return res.status(400).json({ error: 'domain is required' });
  }
  const normalized = normalizeDomain(domain);
  if (!isValidDomain(normalized)) {
    return res.status(400).json({ error: 'invalid domain' });
  }
  const report = await runAllChecks(normalized);
  res.json(report);
});
```

(Add the `require('./checks')` line near the top with the other `require`s, and change the route handler to `async` as shown.)

- [ ] **Step 3: Manually verify against a real domain**

Run: `node server.js`, then: `curl -s -X POST http://localhost:3000/scan -H 'Content-Type: application/json' -d '{"domain":"example.com"}' | node -e "console.log(JSON.stringify(JSON.parse(require('fs').readFileSync(0)), null, 2))"`

Expected: a JSON report with `domain: "example.com"`, a numeric `score`, and a `checks` array of exactly 5 entries, each with `name`, `status` (one of `pass`/`warn`/`fail`), and `message`.

- [ ] **Step 4: Manually verify graceful handling of a nonexistent domain**

Run: `curl -s -X POST http://localhost:3000/scan -H 'Content-Type: application/json' -d '{"domain":"this-domain-definitely-does-not-exist-12345.com"}'`

Expected: HTTP 200 (not a 500/crash) with a `checks` array where every entry has `status: "fail"` and a descriptive message. The server process must still be running and responsive afterward (check with a second curl to `/scan` with `example.com`). Stop the server with Ctrl+C after confirming.

- [ ] **Step 5: Commit**

```bash
git add checks.js server.js
git commit -m "Implement 5 recon checks and wire into /scan endpoint

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>"
```

---

### Task 5: Frontend Dashboard UI

**Files:**
- Modify: `public/index.html` (replace placeholder)
- Create: `public/app.js`
- Create: `public/style.css`

**Interfaces:**
- Consumes: `POST /scan` returning `{ domain, score, checks: [{name, status, message}] }` (Task 4).

- [ ] **Step 1: Replace `public/index.html`**

```html
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <title>Web Recon Dashboard</title>
  <link rel="stylesheet" href="style.css" />
</head>
<body>
  <main>
    <h1>Web Recon Dashboard</h1>
    <p class="subtitle">Scan a domain you own or have permission to test.</p>
    <form id="scan-form">
      <input type="text" id="domain-input" placeholder="example.com" required />
      <button type="submit">Scan</button>
    </form>
    <div id="error-banner" class="error-banner hidden"></div>
    <div id="score-display" class="score-display hidden"></div>
    <div id="results"></div>
  </main>
  <script src="app.js"></script>
</body>
</html>
```

- [ ] **Step 2: Write `public/app.js`**

```js
const form = document.getElementById('scan-form');
const domainInput = document.getElementById('domain-input');
const errorBanner = document.getElementById('error-banner');
const scoreDisplay = document.getElementById('score-display');
const results = document.getElementById('results');

form.addEventListener('submit', async (e) => {
  e.preventDefault();
  errorBanner.classList.add('hidden');
  scoreDisplay.classList.add('hidden');
  results.innerHTML = '';

  const domain = domainInput.value.trim();

  try {
    const res = await fetch('/scan', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ domain }),
    });
    const data = await res.json();

    if (!res.ok) {
      showError(data.error || 'Scan failed');
      return;
    }

    renderReport(data);
  } catch (err) {
    showError('Network error: ' + err.message);
  }
});

function showError(message) {
  errorBanner.textContent = message;
  errorBanner.classList.remove('hidden');
}

function renderReport(report) {
  scoreDisplay.textContent = `Score: ${report.score}/100`;
  scoreDisplay.classList.remove('hidden');

  results.innerHTML = '';
  report.checks.forEach((check) => {
    const card = document.createElement('div');
    card.className = `card ${check.status}`;
    card.innerHTML = `
      <div class="card-header">
        <span class="badge ${check.status}">${check.status.toUpperCase()}</span>
        <span class="card-title">${check.name}</span>
      </div>
      <p class="card-message">${check.message}</p>
    `;
    results.appendChild(card);
  });
}
```

- [ ] **Step 3: Write `public/style.css`**

```css
body {
  font-family: system-ui, sans-serif;
  background: #0f172a;
  color: #e2e8f0;
  margin: 0;
  padding: 2rem;
}
main { max-width: 600px; margin: 0 auto; }
h1 { margin-bottom: 0.25rem; }
.subtitle { color: #94a3b8; margin-top: 0; margin-bottom: 1.5rem; }
#scan-form { display: flex; gap: 0.5rem; margin-bottom: 1rem; }
#domain-input {
  flex: 1;
  padding: 0.6rem;
  border-radius: 6px;
  border: 1px solid #334155;
  background: #1e293b;
  color: #e2e8f0;
}
button {
  padding: 0.6rem 1.2rem;
  border-radius: 6px;
  border: none;
  background: #3b82f6;
  color: white;
  cursor: pointer;
  font-weight: 600;
}
button:hover { background: #2563eb; }
.error-banner {
  background: #7f1d1d;
  color: #fecaca;
  padding: 0.75rem;
  border-radius: 6px;
  margin-bottom: 1rem;
}
.score-display { font-size: 1.5rem; font-weight: 700; margin-bottom: 1rem; }
.hidden { display: none; }
.card {
  background: #1e293b;
  border-radius: 8px;
  padding: 1rem;
  margin-bottom: 0.75rem;
  border-left: 4px solid #334155;
}
.card.pass { border-left-color: #22c55e; }
.card.warn { border-left-color: #eab308; }
.card.fail { border-left-color: #ef4444; }
.card-header { display: flex; align-items: center; gap: 0.5rem; margin-bottom: 0.4rem; }
.card-title { font-weight: 600; }
.badge { font-size: 0.7rem; font-weight: 700; padding: 0.2rem 0.5rem; border-radius: 4px; }
.badge.pass { background: #166534; color: #bbf7d0; }
.badge.warn { background: #854d0e; color: #fef08a; }
.badge.fail { background: #991b1b; color: #fecaca; }
.card-message { margin: 0; color: #cbd5e1; font-size: 0.9rem; }
```

- [ ] **Step 4: Manually verify in a browser**

Run: `node server.js`, then open `http://localhost:3000/` in a browser. Type `example.com` into the input, click "Scan". Expected: within a few seconds, the score displays and 5 cards render, each with a colored left border and badge matching its status (green/pass, yellow/warn, red/fail). Then type `not a domain` (with spaces) and click Scan — expected: the red error banner shows `invalid domain` and no cards render. Stop the server with Ctrl+C after confirming.

- [ ] **Step 5: Commit**

```bash
git add public/index.html public/app.js public/style.css
git commit -m "Build frontend dashboard UI for scan results

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>"
```

---

### Task 6: Dockerize and Verify

**Files:**
- Create: `Dockerfile`
- Create: `.dockerignore`

**Interfaces:**
- Consumes: `package.json`, `server.js`, `checks.js`, `public/` (all prior tasks) — no code changes, packaging only.

- [ ] **Step 1: Write `Dockerfile`**

```dockerfile
FROM node:20-alpine
WORKDIR /app
COPY package*.json ./
RUN npm ci --omit=dev
COPY . .
EXPOSE 3000
CMD ["node", "server.js"]
```

- [ ] **Step 2: Write `.dockerignore`**

```
node_modules
.git
docs
*.md
```

- [ ] **Step 3: Build the image**

Run: `docker build -t web-recon-dashboard .`
Expected: build completes with no errors, ends with `naming to docker.io/library/web-recon-dashboard`.

- [ ] **Step 4: Run the container and verify end-to-end**

Run: `docker run -p 3000:3000 web-recon-dashboard` (in one terminal), then in another:

```bash
curl -s http://localhost:3000/ | grep "Web Recon Dashboard"
curl -s -X POST http://localhost:3000/scan -H 'Content-Type: application/json' -d '{"domain":"example.com"}'
```

Expected: first command prints a matching line from `index.html`; second command returns a full JSON report with 5 checks, same shape as Task 4 Step 3. Stop the container with Ctrl+C after confirming.

- [ ] **Step 5: Commit**

```bash
git add Dockerfile .dockerignore
git commit -m "Add Dockerfile for containerized deployment

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>"
```
