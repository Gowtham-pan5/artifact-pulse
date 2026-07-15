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
*   **Node.js**: Version 18+ (for the frontend UI)

> [!IMPORTANT]
> Run your terminal (PowerShell / Command Prompt) as **Administrator** to ensure the platform has permission to read low-level event logs and system registry artifacts.

---

### Setup Instructions

#### 1. Clone the Repository
```bash
git clone https://github.com/YOUR_USERNAME/artifact-pulse.git
cd artifact-pulse
```

#### 2. Backend Installation & Startup
Activate your virtual environment and install python dependencies:
```powershell
# Create virtual environment if needed
python -m venv .venv

# Activate virtual environment
.\.venv\Scripts\Activate.ps1

# Install requirements
pip install -r requirements.txt

# Run the backend API server and analysis pipeline
python main.py
```
*The backend API server will run at `http://127.0.0.1:5000`.*

#### 3. Frontend Installation & Startup
In a separate terminal (with PowerShell Execution Policy bypassed if needed: `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass`):
```powershell
cd artifact-pulse-ui
npm install
npm run dev
```
*The frontend dashboard will run at `http://localhost:5173`.*

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
