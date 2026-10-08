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
    results.appendChild(card);
  });
}
