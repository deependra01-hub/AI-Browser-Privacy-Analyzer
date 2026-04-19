# AI-Based Browser Privacy Analyzer with Local Intelligence Engine

This project is a local-first privacy analysis platform that combines:

- a Chrome extension for request collection
- a FastAPI backend for analysis
- a SQLite database for persistence
- a live dashboard for visualization

The system monitors your real browser requests, detects trackers, flags possible sensitive data leakage, scores website privacy risk, and surfaces alerts in real time.

## Folder Structure

```text
ai-browser-privacy-analyzer/
├── backend/
│   ├── analyzer/
│   ├── database/
│   └── main.py
├── dashboard/
├── data/
├── docs/
├── extension/
├── samples/
├── requirements.txt
└── README.md
```

## Setup

### 1. Use the local virtual environment

```powershell
cd "D:\minor project"
.\.venv\Scripts\python.exe -m pip --version
```

### 2. Install dependencies

```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
```

### 3. Start the backend and dashboard

```powershell
.\.venv\Scripts\python.exe -m uvicorn backend.main:app --reload
```

Backend and dashboard will be available at:

- API: [http://localhost:8000](http://localhost:8000)
- Dashboard: [http://localhost:8000](http://localhost:8000)
- Health: [http://localhost:8000/health](http://localhost:8000/health)

SQLite is stored locally at:

- default: `%TEMP%\AIBrowserPrivacyAnalyzer\privacy_analyzer.db`
- optional override: set `PRIVACY_ANALYZER_DB_PATH` before starting the server

## Use With Your Real Browser

The `samples` folder is optional and only exists for testing or demonstrations.

For actual use on your system:

1. Start the backend with the command above.
2. Load the extension in a Chromium browser.
3. Browse normally.
4. Open the dashboard at [http://localhost:8000](http://localhost:8000).

The dashboard will fill with your own local browsing data, not fake data.

If you previously loaded sample data and want a clean start, reset the database:

```powershell
.\.venv\Scripts\python.exe samples\reset_database.py
```

## Load the Extension in Chrome, Edge, or Brave

1. Open the extensions page:
   - Chrome: `chrome://extensions/`
   - Edge: `edge://extensions/`
   - Brave: `brave://extensions/`
2. Enable `Developer mode`
3. Click `Load unpacked`
4. Select `D:\minor project\extension`
5. Open the extension popup and confirm the backend URL is `http://localhost:8000`
6. Browse any normal `http` or `https` site in that browser

The extension will capture live request metadata from that browser and send it to your local FastAPI backend.

## Sample Test Data

This step is optional. It is only for demo/testing if you want to prefill the dashboard.

```powershell
.\.venv\Scripts\python.exe samples\load_sample_data.py
```

## API Endpoints

- `POST /analyze`
- `GET /health`
- `GET /api/summary`
- `GET /api/websites`
- `GET /api/domains`
- `GET /api/alerts`
- `GET /api/websites/{website}`

## Risk Formula

```text
risk_score = (trackers * 20) + (sensitive_hits * 15) + (request_frequency * 2) + (third_party * 15) + (aggressive_domains * 10)
```

## Alert Rules

Alerts are raised when:

- a known tracker is detected
- aggressive or cross-site tracking behavior is observed
- possible sensitive metadata is found
- a website reaches the `High Risk` category
