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
