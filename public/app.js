const form = document.getElementById('scan-form');
const domainInput = document.getElementById('domain-input');
const authorizedInput = document.getElementById('authorized-input');
const scanBtn = document.getElementById('scan-btn');
const scanBtnLabel = document.getElementById('scan-btn-label');
const errorBanner = document.getElementById('error-banner');
const scanStatus = document.getElementById('scan-status');
const scanStatusText = document.getElementById('scan-status-text');
const scoreDisplay = document.getElementById('score-display');
const results = document.getElementById('results');
const chartContainer = document.getElementById('chart-container');
const chartCanvas = document.getElementById('score-chart');
const overview = document.getElementById('overview');
const findingsTitle = document.getElementById('findings-title');
const srStatus = document.getElementById('sr-status');

const SVG_NS = 'http://www.w3.org/2000/svg';
const STATUS_VALUE = { pass: 100, warn: 50, fail: 0 };
const SAMPLE_DOMAINS = ['example.com', 'your-site.org', 'mycompany.io', 'blog.example.net'];
const SCAN_MESSAGES = [
  'Resolving DNS records…',
  'Inspecting security headers…',
  'Checking the TLS certificate…',
  'Testing the HTTPS redirect…',
  'Looking for robots.txt and sitemap…',
  'Fingerprinting the technology stack…',
  'Checking common ports…',
];
const reduceMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;

let scoreChart = null;
let scanTimer = null;

form.addEventListener('submit', async (e) => {
  e.preventDefault();
  errorBanner.classList.add('hidden');
  scoreDisplay.classList.add('hidden');
  chartContainer.classList.add('hidden');
  overview.classList.remove('two-col');
  findingsTitle.classList.add('hidden');
  srStatus.textContent = '';
  results.innerHTML = '';

  const domain = domainInput.value.trim();
  setScanning(true);

  try {
    const res = await fetch('/scan', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ domain, authorized: authorizedInput.checked }),
    });
    let data = {};
    try {
      data = await res.json();
    } catch (_) {}

    if (!res.ok) {
      showError(data.error || `Scan failed (HTTP ${res.status})`);
      return;
    }

    renderReport(data);
  } catch (err) {
    showError('Network error: ' + err.message);
  } finally {
    setScanning(false);
  }
});

function setScanning(active) {
  scanBtn.disabled = active;
  scanBtn.classList.toggle('loading', active);
  scanBtnLabel.textContent = active ? 'Scanning…' : 'Scan';
  clearInterval(scanTimer);
  if (!active) {
    scanStatus.classList.add('hidden');
    return;
  }
  let i = 0;
  scanStatusText.textContent = SCAN_MESSAGES[0];
  scanStatus.classList.remove('hidden');
  scanTimer = setInterval(() => {
    i = (i + 1) % SCAN_MESSAGES.length;
    scanStatusText.textContent = SCAN_MESSAGES[i];
  }, 900);
}

function showError(message) {
  errorBanner.textContent = message;
  errorBanner.classList.remove('hidden');
}

function scoreTier(score) {
  if (score >= 80) return { cls: 'good', verdict: 'Strong' };
  if (score >= 50) return { cls: 'mid', verdict: 'Needs work' };
  return { cls: 'bad', verdict: 'At risk' };
}

function renderScore(report) {
  const tier = scoreTier(report.score);
  const radius = 52;
  const circumference = 2 * Math.PI * radius;

  scoreDisplay.textContent = '';

  const wrap = document.createElement('div');
  wrap.className = 'gauge-wrap';

  const svg = document.createElementNS(SVG_NS, 'svg');
  svg.setAttribute('viewBox', '0 0 120 120');
  svg.setAttribute('class', 'gauge');
  const track = document.createElementNS(SVG_NS, 'circle');
  track.setAttribute('class', 'gauge-track');
  track.setAttribute('cx', '60');
  track.setAttribute('cy', '60');
  track.setAttribute('r', String(radius));
  const arc = document.createElementNS(SVG_NS, 'circle');
  arc.setAttribute('class', `gauge-arc ${tier.cls}`);
  arc.setAttribute('cx', '60');
  arc.setAttribute('cy', '60');
  arc.setAttribute('r', String(radius));
  arc.style.strokeDasharray = String(circumference);
  arc.style.strokeDashoffset = String(circumference);
  svg.appendChild(track);
  svg.appendChild(arc);

  const number = document.createElement('div');
  number.className = 'gauge-number';
  number.textContent = reduceMotion ? String(report.score) : '0';

  wrap.appendChild(svg);
  wrap.appendChild(number);

  const info = document.createElement('div');
  info.className = 'score-info';
  const label = document.createElement('p');
  label.className = 'score-label';
  label.textContent = 'Security score';
  const verdict = document.createElement('p');
  verdict.className = `score-verdict ${tier.cls}`;
  verdict.textContent = tier.verdict;
  const domain = document.createElement('p');
  domain.className = 'score-domain';
  domain.textContent = report.domain;
  info.appendChild(label);
  info.appendChild(verdict);
  info.appendChild(domain);
  info.appendChild(buildChips(report.checks));

  scoreDisplay.appendChild(wrap);
  scoreDisplay.appendChild(info);
  scoreDisplay.classList.remove('hidden');

  const targetOffset = circumference * (1 - report.score / 100);
  requestAnimationFrame(() => requestAnimationFrame(() => {
    arc.style.strokeDashoffset = String(targetOffset);
  }));
  if (!reduceMotion) {
    countUp(number, report.score, 1200);
  }
}

const CHIP_LABELS = [
  ['pass', (n) => `${n} passed`],
  ['warn', (n) => `${n} ${n === 1 ? 'warning' : 'warnings'}`],
  ['fail', (n) => `${n} failed`],
  ['info', (n) => `${n} informational`],
  ['skip', (n) => `${n} skipped`],
];

function buildChips(checks) {
  const chips = document.createElement('div');
  chips.className = 'chips';
  CHIP_LABELS.forEach(([status, label]) => {
    const count = checks.filter((c) => c.status === status).length;
    if (count === 0) return;
    const chip = document.createElement('span');
    chip.className = `chip ${status}`;
    chip.textContent = label(count);
    chips.appendChild(chip);
  });
  return chips;
}

function countUp(el, target, duration) {
  const start = performance.now();
  function frame(now) {
    const t = Math.min((now - start) / duration, 1);
    const eased = 1 - Math.pow(1 - t, 3);
    el.textContent = String(Math.round(target * eased));
    if (t < 1) requestAnimationFrame(frame);
  }
  requestAnimationFrame(frame);
}

function renderReport(report) {
  renderScore(report);
  renderChart(report.checks);
  findingsTitle.classList.remove('hidden');
  srStatus.textContent = `Scan complete for ${report.domain}. Score ${report.score} out of 100, ${scoreTier(report.score).verdict}.`;

  results.innerHTML = '';
  report.checks.forEach((check, index) => {
    const card = document.createElement('div');
    card.className = `card ${check.status}`;
    card.style.animationDelay = `${300 + index * 110}ms`;

    const header = document.createElement('div');
    header.className = 'card-header';

    const badge = document.createElement('span');
    badge.className = `badge ${check.status}`;
    badge.textContent = check.status.toUpperCase();

    const title = document.createElement('h3');
    title.className = 'card-title';
    title.textContent = check.name;

    header.appendChild(badge);
    header.appendChild(title);

    const message = document.createElement('p');
    message.className = 'card-message';
    message.textContent = check.message;

    card.appendChild(header);
    card.appendChild(message);

    const detailsList = buildDetailsList(check.details);
    if (detailsList) {
      card.appendChild(detailsList);
    }

    results.appendChild(card);
  });
}

function buildDetailsList(details) {
  if (!details || Object.keys(details).length === 0) {
    return null;
  }
  const list = document.createElement('dl');
  list.className = 'details-list';
  Object.entries(details).forEach(([key, value]) => {
    const dt = document.createElement('dt');
    dt.textContent = formatDetailKey(key);
    const dd = document.createElement('dd');
    if (Array.isArray(value) && value.length > 1) {
      const ul = document.createElement('ul');
      value.forEach((item) => {
        const li = document.createElement('li');
        li.textContent = String(item);
        ul.appendChild(li);
      });
      dd.appendChild(ul);
    } else {
      dd.textContent = formatDetailValue(value);
    }
    list.appendChild(dt);
    list.appendChild(dd);
  });
  return list;
}

const DETAIL_LABELS = { aRecords: 'A records', aaaaRecords: 'AAAA records', mxRecords: 'MX records' };

function formatDetailKey(key) {
  if (DETAIL_LABELS[key]) return DETAIL_LABELS[key];
  return key.replace(/([A-Z])/g, ' $1').replace(/^./, (c) => c.toUpperCase());
}

function formatDetailValue(value) {
  if (Array.isArray(value)) {
    return value.length > 0 ? value.join(', ') : '(none)';
  }
  if (typeof value === 'boolean') {
    return value ? 'yes' : 'no';
  }
  if (value === '' || value === null || value === undefined) {
    return '(none)';
  }
  return String(value);
}

function renderChart(allChecks) {
  // Only scored checks (pass/warn/fail) belong on the radar; info/skip have no value.
  const checks = allChecks.filter((c) => c.status in STATUS_VALUE);
  if (typeof Chart === 'undefined' || checks.length < 3) {
    chartContainer.classList.add('hidden');
    overview.classList.remove('two-col');
    return;
  }
  overview.classList.add('two-col');
  const labels = checks.map((c) => wrapLabel(c.name));
  const data = checks.map((c) => STATUS_VALUE[c.status]);

  if (scoreChart) {
    scoreChart.destroy();
    scoreChart = null;
  }
  // Unhide first: Chart.js sizes itself from the container, which is 0x0 while hidden.
  chartContainer.classList.remove('hidden');

  scoreChart = new Chart(chartCanvas, {
    type: 'radar',
    data: {
      labels,
      datasets: [{
        label: 'Check score',
        data,
        backgroundColor: 'rgba(56, 189, 248, 0.25)',
        borderColor: 'rgba(56, 189, 248, 0.95)',
        pointBackgroundColor: 'rgba(99, 102, 241, 1)',
      }],
    },
    options: {
      layout: { padding: 8 },
      animation: reduceMotion ? false : { duration: 1400, easing: 'easeOutQuart' },
      scales: {
        r: {
          min: 0,
          max: 100,
          ticks: { stepSize: 25, color: '#94a3b8', backdropColor: 'transparent' },
          grid: { color: '#24304d' },
          angleLines: { color: '#24304d' },
          pointLabels: { color: '#e2e8f0', font: { size: 11 } },
        },
      },
      plugins: {
        legend: { display: false },
      },
    },
  });
}

// Split a long check name into short lines so radar axis labels don't clip.
function wrapLabel(name, maxLen = 14) {
  const lines = [];
  let line = '';
  name.split(' ').forEach((word) => {
    if (line && (line + ' ' + word).length > maxLen) {
      lines.push(line);
      line = word;
    } else {
      line = line ? line + ' ' + word : word;
    }
  });
  if (line) lines.push(line);
  return lines;
}

// Typing placeholder: cycles through sample domains while the input is idle.
function startPlaceholderTyping() {
  if (reduceMotion) return;
  let word = 0;
  let chars = 0;
  let deleting = false;

  function tick() {
    if (document.activeElement === domainInput || domainInput.value) {
      domainInput.placeholder = 'example.com';
      setTimeout(tick, 600);
      return;
    }
    const text = SAMPLE_DOMAINS[word];
    chars += deleting ? -1 : 1;
    domainInput.placeholder = text.slice(0, chars);
    let delay = deleting ? 40 : 90;
    if (!deleting && chars === text.length) {
      deleting = true;
      delay = 1400;
    } else if (deleting && chars === 0) {
      deleting = false;
      word = (word + 1) % SAMPLE_DOMAINS.length;
      delay = 400;
    }
    setTimeout(tick, delay);
  }
  tick();
}

startPlaceholderTyping();
