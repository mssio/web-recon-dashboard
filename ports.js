// Exposure check: a plain TCP connect test against a short, fixed list of
// well-known ports. It only learns whether a port accepts a connection.
// It sends no data, grabs no banners and attempts no logins or exploits.
//
// It is an active check, so the caller must pass { authorized: true }, and
// by default it refuses private / loopback / link-local targets so the
// server cannot be used to probe its own internal network.
// Set ALLOW_PRIVATE_TARGETS=1 to allow those (e.g. for a lab).

const net = require('net');
const dns = require('dns').promises;

const NAME = 'Open Ports & Services';

// sensitive: services that normally should not be reachable from the internet.
const PORTS = [
  { port: 21, service: 'FTP', sensitive: true },
  { port: 22, service: 'SSH' },
  { port: 23, service: 'Telnet', sensitive: true },
  { port: 25, service: 'SMTP' },
  { port: 53, service: 'DNS' },
  { port: 80, service: 'HTTP' },
  { port: 110, service: 'POP3' },
  { port: 143, service: 'IMAP' },
  { port: 443, service: 'HTTPS' },
  { port: 445, service: 'SMB', sensitive: true },
  { port: 465, service: 'SMTPS' },
  { port: 587, service: 'SMTP submission' },
  { port: 993, service: 'IMAPS' },
  { port: 995, service: 'POP3S' },
  { port: 1433, service: 'Microsoft SQL Server', sensitive: true },
  { port: 3306, service: 'MySQL / MariaDB', sensitive: true },
  { port: 3389, service: 'RDP', sensitive: true },
  { port: 5432, service: 'PostgreSQL', sensitive: true },
  { port: 6379, service: 'Redis', sensitive: true },
  { port: 8080, service: 'HTTP (alternate)' },
  { port: 8443, service: 'HTTPS (alternate)' },
  { port: 27017, service: 'MongoDB', sensitive: true },
];

function isPrivateIPv4(ip) {
  const [a, b] = ip.split('.').map(Number);
  return a === 0 || a === 10 || a === 127
    || (a === 100 && b >= 64 && b <= 127)
    || (a === 169 && b === 254)
    || (a === 172 && b >= 16 && b <= 31)
    || (a === 192 && b === 168)
    || a >= 224;
}

function probe(host, port, timeoutMs = 1500) {
  return new Promise((resolve) => {
    const socket = net.connect({ host, port });
    let finished = false;
    const finish = (open) => {
      if (finished) return;
      finished = true;
      socket.destroy();
      resolve(open);
    };
    socket.setTimeout(timeoutMs);
    socket.once('connect', () => finish(true));
    socket.once('timeout', () => finish(false));
    socket.once('error', () => finish(false));
  });
}

function skipped(message) {
  return { name: NAME, status: 'skip', message, details: {} };
}

async function checkPorts(domain, { authorized = false } = {}) {
  if (!authorized) {
    return skipped('Skipped: tick the authorization box to run the port probe against a domain you own or may test.');
  }
  try {
    let ip = domain;
    if (!net.isIPv4(domain)) {
      const resolver = new dns.Resolver({ timeout: 2000, tries: 1 });
      const addresses = await resolver.resolve4(domain).catch(() => []);
      if (addresses.length === 0) {
        return skipped('Skipped: the domain has no IPv4 address to probe.');
      }
      ip = addresses[0];
    }
    if (isPrivateIPv4(ip) && process.env.ALLOW_PRIVATE_TARGETS !== '1') {
      return skipped(`Skipped: ${ip} is a private, loopback or reserved address (set ALLOW_PRIVATE_TARGETS=1 to allow).`);
    }

    // Connect to the resolved IP directly so the target cannot change between lookup and probe.
    const outcomes = await Promise.all(PORTS.map((p) => probe(ip, p.port)));
    const open = PORTS.filter((_, i) => outcomes[i]);
    const sensitive = open.filter((p) => p.sensitive);
    const label = (p) => `${p.port} ${p.service}`;

    const details = {
      target: ip,
      scanned: `${PORTS.length} common TCP ports (connect test only, nothing sent)`,
      openPorts: open.map(label),
      sensitiveServicesOpen: sensitive.map(label),
      note: 'Service names are inferred from the well-known port number and were not verified.',
    };

    if (sensitive.length > 0) {
      return { name: NAME, status: 'fail', message: `Sensitive service(s) reachable from the internet: ${sensitive.map(label).join(', ')}`, details };
    }
    if (open.length === 0) {
      return { name: NAME, status: 'warn', message: `None of the ${PORTS.length} common ports answered (host may be filtering probes)`, details };
    }
    return { name: NAME, status: 'pass', message: `${open.length} of ${PORTS.length} common ports open; no sensitive services exposed`, details };
  } catch (err) {
    return skipped(`Skipped: port probe failed (${err.message}).`);
  }
}

module.exports = { checkPorts, PORTS };
