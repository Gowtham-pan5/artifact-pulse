let poller = null;

function riskClass(v) {
  const r = Number(v || 0);
  if (r >= 0.7) return ['HIGH', 'risk-high'];
  if (r >= 0.4) return ['MED', 'risk-med'];
  return ['LOW', 'risk-low'];
}

function layerClass(layer) {
  return `layer-${layer}`;
}

async function startExtraction() {
  const res = await fetch('/api/extraction/start', { method: 'POST' });
  if (res.status === 202) {
    document.getElementById('progressWrap').classList.remove('hidden');
    pollStatus();
    poller = setInterval(pollStatus, 2000);
  }
}

async function pollStatus() {
  const res = await fetch('/api/extraction/status');
  const data = await res.json();
  document.getElementById('progressBar').style.width = `${data.progress || 0}%`;
  document.getElementById('progressText').innerText = `${data.progress || 0}% - ${data.stage}: ${data.message}`;
  if (!data.running && (data.progress || 0) >= 100) {
    clearInterval(poller);
    loadStats();
    loadArtifacts('all');
    document.getElementById('genBtn').disabled = false;
  }
}

async function loadArtifacts(layer) {
  const query = layer && layer !== 'all' ? `?layer=${encodeURIComponent(layer)}` : '';
  const res = await fetch(`/api/artifacts${query}`);
  const list = await res.json();
  const body = document.getElementById('artifactBody');
  body.innerHTML = '';
  list.forEach(a => {
    const [label, klass] = riskClass(a.risk_weight);
    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td>${a.artifact_id || ''}</td>
      <td><span class="badge ${layerClass(a.source_layer)}">${a.source_layer || ''}</span></td>
      <td>${a.artifact_type || ''}</td>
      <td>${a.event_time || ''}</td>
      <td><span class="${klass}">${label}</span></td>
    `;
    body.appendChild(tr);
  });
}

async function loadStats() {
  const res = await fetch('/api/stats');
  const s = await res.json();
  document.getElementById('sTotal').innerText = s.total_artifacts || 0;
  document.getElementById('sAF').innerText = s.antiforensic || 0;
  document.getElementById('sHigh').innerText = s.high_risk || 0;
  document.getElementById('sCluster').innerText = s.clusters || 0;
}

async function verifyChain() {
  const res = await fetch('/api/chain/verify');
  const j = await res.json();
  alert(`${j.status}: ${j.message}`);
}

async function generateReport() {
  const res = await fetch('/api/report/generate', { method: 'POST' });
  if (res.status === 201) {
    document.getElementById('dlBtn').disabled = false;
  }
}

function downloadReport() {
  window.location = '/api/report/download';
}

window.addEventListener('DOMContentLoaded', () => {
  loadStats();
  loadArtifacts('all');
});
