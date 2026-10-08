const form = document.getElementById('scan-form');
const domainInput = document.getElementById('domain-input');
const errorBanner = document.getElementById('error-banner');
const scoreDisplay = document.getElementById('score-display');
const results = document.getElementById('results');
const chartContainer = document.getElementById('chart-container');
const chartCanvas = document.getElementById('score-chart');

let scoreChart = null;
const STATUS_VALUE = { pass: 100, warn: 50, fail: 0 };

form.addEventListener('submit', async (e) => {
  e.preventDefault();
  errorBanner.classList.add('hidden');
  scoreDisplay.classList.add('hidden');
  chartContainer.classList.add('hidden');
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

  renderChart(report.checks);

  results.innerHTML = '';
  report.checks.forEach((check) => {
    const card = document.createElement('div');
    card.className = `card ${check.status}`;

    const header = document.createElement('div');
    header.className = 'card-header';

    const badge = document.createElement('span');
    badge.className = `badge ${check.status}`;
    badge.textContent = check.status.toUpperCase();

    const title = document.createElement('span');
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
    dd.textContent = formatDetailValue(value);
    list.appendChild(dt);
    list.appendChild(dd);
  });
  return list;
}

function formatDetailKey(key) {
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

function renderChart(checks) {
  if (typeof Chart === 'undefined') {
    chartContainer.classList.add('hidden');
    return;
  }
  const labels = checks.map((c) => c.name);
  const data = checks.map((c) => STATUS_VALUE[c.status] ?? 0);

  if (scoreChart) {
    scoreChart.destroy();
    scoreChart = null;
  }

  scoreChart = new Chart(chartCanvas, {
    type: 'radar',
    data: {
      labels,
      datasets: [{
        label: 'Check score',
        data,
        backgroundColor: 'rgba(59, 130, 246, 0.25)',
        borderColor: 'rgba(59, 130, 246, 0.9)',
        pointBackgroundColor: 'rgba(59, 130, 246, 0.9)',
      }],
    },
    options: {
      scales: {
        r: {
          min: 0,
          max: 100,
          ticks: { stepSize: 25, color: '#94a3b8', backdropColor: 'transparent' },
          grid: { color: '#334155' },
          angleLines: { color: '#334155' },
          pointLabels: { color: '#e2e8f0', font: { size: 11 } },
        },
      },
      plugins: {
        legend: { display: false },
      },
    },
  });
  chartContainer.classList.remove('hidden');
}
