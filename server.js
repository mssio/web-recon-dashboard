const express = require('express');
const path = require('path');
const { runAllChecks } = require('./checks');

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

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Web Recon Dashboard listening on port ${PORT}`);
});
