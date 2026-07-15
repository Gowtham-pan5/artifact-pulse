const API_BASE = "http://127.0.0.1:5000";

// Fetch Stats for your dashboard cards
export async function fetchStats() {
  const res = await fetch(`${API_BASE}/api/stats`);
  return res.json();
}

// Start a new forensic scan
export async function startExtraction() {
  const res = await fetch(`${API_BASE}/api/extraction/start`, { method: "POST" });
  return res.json();
}

// Poll extraction status (progress bar)
export async function checkStatus() {
  const res = await fetch(`${API_BASE}/api/extraction/status`);
  return res.json();
}

// Fetch identified anomalous events
export async function fetchArtifacts() {
  const res = await fetch(`${API_BASE}/api/artifacts`);
  return res.json();
}
