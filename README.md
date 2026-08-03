# Artifact-Pulse

Artifact-Pulse is a Windows endpoint forensic artifact extraction and correlation platform with anti-forensic detection, machine-learning anomaly scoring, and legal-grade PDF report generation.

## Features
- Filesystem, event log, process, and registry-layer artifact ingestion
- Chain-of-custody hashing with blockchain-style artifact linking
- Anti-forensic behavior detection (log clear, wiping tools, VSS deletion indicators)
- Correlation engine with temporal suspicious cluster scoring
- Isolation Forest + KMeans + TF-IDF suspicious keyword enrichment
- Flask dashboard and API for pipeline operations and reporting
- PDF report generation with legal and compliance narrative sections

## Getting Started

### Prerequisites
*   **Operating System**: Windows 10 or 11
*   **Python**: Version 3.11+
*   **Node.js**: Version 20.19+ or 22.12+ (Vite 7 requirement — latest LTS recommended)

> [!IMPORTANT]
> Run your terminal (PowerShell / Command Prompt) as **Administrator** to ensure the platform has permission to read low-level event logs and system registry artifacts.

---

### Quick Start — 3 commands

```bash
git clone https://github.com/Gowtham-pan5/artifact-pulse.git
cd artifact-pulse
START.bat
```

`START.bat` creates the Python venv, installs backend + frontend dependencies (first run only),
starts the Flask API on `http://127.0.0.1:5000`, starts the React UI on `http://localhost:5173`,
and opens your browser automatically.

### How the flow works

1. Browser opens **http://localhost:5173** (Operations Dashboard).
2. Go to **Pipeline Runner → run pipeline**. The tool now scans **your own Windows machine**:
   filesystem, event logs, live processes, and registry — then runs ML anomaly scoring and
   seals the chain of custody. First run takes a few minutes.
3. Back on the dashboard you see **your** artifacts, processes, event logs, and risk scores.
4. Browse **Artifacts / Anomalies / Chain of Custody / Anti-Forensic** — all real data from your device.
5. **Reports → generate report** produces a forensic PDF (download via the download button).

### Manual setup (instead of START.bat)

Terminal 1 — backend:
```powershell
python -m venv .venv
.\.venv\Scripts\pip install -r requirements.txt
.\.venv\Scripts\python.exe -m web.app
```
*The API runs at `http://127.0.0.1:5000`. The pipeline starts on demand from the UI button —
it is **not** run at startup (use `python main.py` only if you want the CLI-only pipeline).*

Terminal 2 — frontend:
```powershell
cd artifact-pulse-ui
npm install
npm run dev
```
*The frontend runs at `http://localhost:5173` and proxies `/api/*` to the backend.*

### Optional: skip the re-scan

`seed_serve.py` loads the last run's evidence store straight into the API (no re-scan) —
handy for demos: `.\.venv\Scripts\python.exe seed_serve.py`

---

## API Endpoints
- `GET /api/health`
- `POST /api/extraction/start`
- `GET /api/extraction/status`
- `GET /api/artifacts`
- `GET /api/antiforensic`
- `GET /api/clusters`
- `GET /api/stats`
- `GET /api/chain/verify`
- `POST /api/report/generate`
- `GET /api/report/download`

---

## Output Files
All forensic databases, generated integrity hashes, and legal PDF reports are saved under the `output/` directory.
