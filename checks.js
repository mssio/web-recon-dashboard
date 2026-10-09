const dns = require('dns').promises;
const tls = require('tls');
const { detectTech } = require('./fingerprint');
const { checkPorts } = require('./ports');

async function checkDns(domain) {
  try {
    const resolver = new dns.Resolver({ timeout: 2000, tries: 1 });
    const [aResult, aaaaResult, mxResult] = await Promise.allSettled([
      resolver.resolve4(domain),
      resolver.resolve6(domain),
      resolver.resolveMx(domain),
    ]);
    const aRecords = aResult.status === 'fulfilled' ? aResult.value : [];
    const aaaaRecords = aaaaResult.status === 'fulfilled' ? aaaaResult.value : [];
    const mxRecords = mxResult.status === 'fulfilled' ? mxResult.value : [];
    const details = {
      aRecords,
      aaaaRecords,
      mxRecords: mxRecords.map((mx) => (
        mx.exchange && mx.exchange !== '.'
          ? `${mx.exchange} (priority ${mx.priority})`
          : 'null MX (domain accepts no mail)'
      )),
    };
    if (aRecords.length === 0 && aaaaRecords.length === 0) {
      return { name: 'DNS Resolution', status: 'fail', message: `Could not resolve any A/AAAA records for ${domain}`, details };
    }
    const firstAddr = aRecords[0] || aaaaRecords[0];
    if (mxRecords.length === 0) {
      return { name: 'DNS Resolution', status: 'warn', message: `A record found: ${firstAddr}, but no MX records`, details };
    }
    return { name: 'DNS Resolution', status: 'pass', message: `A record found: ${firstAddr}`, details };
  } catch (err) {
    return { name: 'DNS Resolution', status: 'fail', message: `DNS lookup failed: ${err.message}`, details: {} };
  }
}

const RECOMMENDED_HEADERS = ['content-security-policy', 'strict-transport-security', 'x-frame-options', 'x-content-type-options'];
const OTHER_SECURITY_HEADERS = [
  'referrer-policy',
  'permissions-policy',
  'cross-origin-opener-policy',
  'cross-origin-resource-policy',
  'cross-origin-embedder-policy',
];
const MAX_BODY_CHARS = 200000;

function truncate(value, max = 140) {
  return value.length > max ? `${value.slice(0, max)}…` : value;
}

// Read at most MAX_BODY_CHARS of the response body, then release the socket.
async function readLimited(res) {
  const reader = res.body && res.body.getReader();
  if (!reader) return '';
  const decoder = new TextDecoder();
  let out = '';
  try {
    while (out.length < MAX_BODY_CHARS) {
      const { done, value } = await reader.read();
      if (done) break;
      out += decoder.decode(value, { stream: true });
    }
  } catch (_) {
    // A truncated or aborted body is fine; we only fingerprint what we got.
  }
  reader.cancel().catch(() => {});
  return out.slice(0, MAX_BODY_CHARS);
}

// One homepage request, shared by the header check and the tech fingerprint.
async function fetchHome(domain) {
  try {
    const res = await fetch(`https://${domain}/`, { redirect: 'follow', signal: AbortSignal.timeout(5000) });
    const setCookies = typeof res.headers.getSetCookie === 'function' ? res.headers.getSetCookie() : [];
    const body = await readLimited(res);
    return { ok: true, domain, status: res.status, url: res.url, headers: res.headers, setCookies, body };
  } catch (err) {
    return { ok: false, domain, error: err.message };
  }
}

function headerFindings(headers, setCookies) {
  const findings = [];

  const hsts = headers.get('strict-transport-security');
  if (hsts) {
    const maxAge = /max-age=(\d+)/i.exec(hsts);
    if (!maxAge || Number(maxAge[1]) < 15552000) findings.push('HSTS max-age is shorter than 6 months');
    if (!/includeSubDomains/i.test(hsts)) findings.push('HSTS does not cover subdomains (no includeSubDomains)');
  }

  const csp = headers.get('content-security-policy');
  if (csp) {
    if (/'unsafe-inline'/i.test(csp)) findings.push("CSP allows 'unsafe-inline'");
    if (/'unsafe-eval'/i.test(csp)) findings.push("CSP allows 'unsafe-eval'");
    if (/(^|[\s;])\*([\s;]|$)/.test(csp)) findings.push('CSP uses a wildcard (*) source');
  }

  const xcto = headers.get('x-content-type-options');
  if (xcto && xcto.trim().toLowerCase() !== 'nosniff') findings.push('X-Content-Type-Options should be "nosniff"');

  const xfo = headers.get('x-frame-options');
  if (xfo && !/^(deny|sameorigin)$/i.test(xfo.trim())) findings.push(`X-Frame-Options has a non-standard value: ${truncate(xfo, 60)}`);

  const server = headers.get('server');
  if (server && /\d+\.\d+/.test(server)) findings.push(`Server header discloses a version: ${truncate(server, 80)}`);
  const poweredBy = headers.get('x-powered-by');
  if (poweredBy) findings.push(`X-Powered-By discloses the stack: ${truncate(poweredBy, 80)}`);

  if (headers.get('access-control-allow-origin') === '*') findings.push('CORS allows any origin (Access-Control-Allow-Origin: *)');

  setCookies.forEach((cookie) => {
    const cookieName = cookie.split('=')[0].trim();
    const lacking = [];
    if (!/;\s*secure/i.test(cookie)) lacking.push('Secure');
    if (!/;\s*httponly/i.test(cookie)) lacking.push('HttpOnly');
    if (!/;\s*samesite/i.test(cookie)) lacking.push('SameSite');
    if (lacking.length > 0) findings.push(`Cookie "${truncate(cookieName, 40)}" is missing: ${lacking.join(', ')}`);
  });

  return findings;
}

function checkHeaders(home) {
  const name = 'HTTP Security Headers';
  if (!home.ok) {
    return { name, status: 'fail', message: `Could not fetch https://${home.domain}/: ${home.error}`, details: {} };
  }

  const present = RECOMMENDED_HEADERS.filter((h) => home.headers.has(h));
  const missing = RECOMMENDED_HEADERS.filter((h) => !home.headers.has(h));
  const otherPresent = OTHER_SECURITY_HEADERS.filter((h) => home.headers.has(h));

  const details = {
    statusCode: home.status,
    finalUrl: home.url,
    present: present.map((h) => `${h}: ${truncate(home.headers.get(h))}`),
    missing,
    otherSecurityHeaders: otherPresent.map((h) => `${h}: ${truncate(home.headers.get(h))}`),
    notFound: OTHER_SECURITY_HEADERS.filter((h) => !home.headers.has(h)),
    findings: headerFindings(home.headers, home.setCookies),
  };

  if (present.length === RECOMMENDED_HEADERS.length) {
    return { name, status: 'pass', message: 'All 4 recommended headers present', details };
  }
  if (present.length === 0) {
    return { name, status: 'fail', message: 'None of the 4 recommended headers present', details };
  }
  return { name, status: 'warn', message: `${present.length} of 4 recommended headers present`, details };
}

function checkTls(domain) {
  return new Promise((resolve) => {
    const socket = tls.connect({ host: domain, port: 443, servername: domain, timeout: 5000 }, () => {
      const cert = socket.getPeerCertificate();
      socket.end();
      if (!cert || !cert.valid_to) {
        resolve({ name: 'TLS Certificate', status: 'fail', message: 'Could not read certificate', details: {} });
        return;
      }
      const expiry = new Date(cert.valid_to);
      const daysLeft = Math.floor((expiry.getTime() - Date.now()) / (1000 * 60 * 60 * 24));
      const details = {
        issuer: cert.issuer ? (cert.issuer.O || cert.issuer.CN || JSON.stringify(cert.issuer)) : 'unknown',
        validFrom: cert.valid_from || 'unknown',
        validTo: cert.valid_to || 'unknown',
        daysLeft,
      };
      if (daysLeft < 0) {
        resolve({ name: 'TLS Certificate', status: 'fail', message: `Certificate expired ${-daysLeft} days ago`, details });
      } else if (daysLeft < 30) {
        resolve({ name: 'TLS Certificate', status: 'warn', message: `Valid, expires in ${daysLeft} days`, details });
      } else {
        resolve({ name: 'TLS Certificate', status: 'pass', message: `Valid, expires in ${daysLeft} days`, details });
      }
    });
    socket.on('error', (err) => {
      resolve({ name: 'TLS Certificate', status: 'fail', message: `TLS connection failed: ${err.message}`, details: {} });
    });
    socket.on('timeout', () => {
      socket.destroy();
      resolve({ name: 'TLS Certificate', status: 'fail', message: 'TLS connection timed out', details: {} });
    });
  });
}

async function checkHttpsRedirect(domain) {
  try {
    const res = await fetch(`http://${domain}/`, { redirect: 'manual', signal: AbortSignal.timeout(5000) });
    const details = { statusCode: res.status, location: res.headers.get('location') || '' };
    if (res.status >= 300 && res.status < 400) {
      const location = details.location;
      if (location.startsWith('https://')) {
        return { name: 'HTTPS Redirect', status: 'pass', message: 'HTTP redirects to HTTPS', details };
      }
      return { name: 'HTTPS Redirect', status: 'warn', message: `HTTP redirects, but not to HTTPS (${location})`, details };
    }
    return { name: 'HTTPS Redirect', status: 'warn', message: 'HTTP serves content directly without redirecting to HTTPS', details };
  } catch (err) {
    return { name: 'HTTPS Redirect', status: 'fail', message: `HTTP request failed: ${err.message}`, details: {} };
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
  const details = { robotsFound: hasRobots, sitemapFound: hasSitemap };
  if (hasRobots && hasSitemap) {
    return { name: 'robots.txt / sitemap.xml', status: 'pass', message: 'Both robots.txt and sitemap.xml found', details };
  }
  if (hasRobots || hasSitemap) {
    const which = hasRobots ? 'robots.txt' : 'sitemap.xml';
    const missing = hasRobots ? 'sitemap.xml' : 'robots.txt';
    return { name: 'robots.txt / sitemap.xml', status: 'warn', message: `${which} found, ${missing} missing`, details };
  }
  return { name: 'robots.txt / sitemap.xml', status: 'fail', message: 'Neither robots.txt nor sitemap.xml found', details };
}

const SCORED = { pass: 1, warn: 0.5, fail: 0 };

// A check must never take the whole scan down: turn any throw into a result.
async function safely(name, fn) {
  try {
    return await fn();
  } catch (err) {
    return { name, status: 'fail', message: `Check crashed: ${err.message}`, details: {} };
  }
}

async function runAllChecks(domain, { authorized = false } = {}) {
  const home = fetchHome(domain);
  const results = await Promise.all([
    safely('DNS Resolution', () => checkDns(domain)),
    safely('HTTP Security Headers', async () => checkHeaders(await home)),
    safely('TLS Certificate', () => checkTls(domain)),
    safely('HTTPS Redirect', () => checkHttpsRedirect(domain)),
    safely('robots.txt / sitemap.xml', () => checkRobotsSitemap(domain)),
    safely('Technology Stack', async () => detectTech(await home)),
    safely('Open Ports & Services', () => checkPorts(domain, { authorized })),
  ]);

  // Only pass/warn/fail checks are scored; 'info' and 'skip' are shown but not counted.
  const scored = results.filter((r) => r.status in SCORED);
  const points = scored.reduce((sum, r) => sum + SCORED[r.status], 0);
  const score = scored.length === 0 ? 0 : Math.round((points / scored.length) * 100);
  return { domain, score, checks: results };
}

module.exports = { checkDns, fetchHome, checkHeaders, checkTls, checkHttpsRedirect, checkRobotsSitemap, runAllChecks };
