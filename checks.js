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
