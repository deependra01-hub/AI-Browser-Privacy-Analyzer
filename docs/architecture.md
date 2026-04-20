# Architecture Overview

## Data Flow

```text
Browser
  -> Chrome Extension
  -> FastAPI Backend
  -> SQLite Database
  -> Dashboard APIs
  -> Dashboard UI
```

## Analysis Engine

- `tracker_detection.py` handles tracker, keyword, third-party, and sensitive metadata checks
- `behavior_analysis.py` profiles request frequency and cross-site behavior
- `risk_scoring.py` computes request and website privacy risk and generates alerts
