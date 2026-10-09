const dns = require('dns').promises;
const tls = require('tls');

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

async function checkHeaders(domain) {
  const required = ['content-security-policy', 'strict-transport-security', 'x-frame-options', 'x-content-type-options'];
  try {
    const res = await fetch(`https://${domain}/`, { redirect: 'follow', signal: AbortSignal.timeout(5000) });
    const present = required.filter((h) => res.headers.has(h));
    const missing = required.filter((h) => !res.headers.has(h));
    const details = { present, missing };
    if (present.length === required.length) {
      return { name: 'HTTP Security Headers', status: 'pass', message: 'All 4 recommended headers present', details };
    }
    if (present.length === 0) {
      return { name: 'HTTP Security Headers', status: 'fail', message: 'None of the 4 recommended headers present', details };
    }
    return { name: 'HTTP Security Headers', status: 'warn', message: `${present.length} of 4 recommended headers present`, details };
  } catch (err) {
    return { name: 'HTTP Security Headers', status: 'fail', message: `Could not fetch https://${domain}/: ${err.message}`, details: {} };
  }
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
