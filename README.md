# CyberShield AI — Browser Protection Platform

Advanced AI-powered cybersecurity browser protection system combining a Chrome Extension (MV3) with a FastAPI backend.

---

## Quick Start

### 1. Start the Backend

```bash
cd backend
pip install -r requirements.txt
python -m ml.train_model          # Train ML model (first run only)
python -m uvicorn main:app --host 127.0.0.1 --port 8000 --reload
```

Or use the convenience script:
```
backend\start.bat
```

API docs: http://127.0.0.1:8000/docs

### 2. Generate Icons

```bash
python generate_icons.py
```

### 3. Load Chrome Extension

1. Open Chrome → `chrome://extensions/`
2. Enable **Developer Mode**
3. Click **Load unpacked**
4. Select the `extension/` folder

---

## Architecture

```
d:\AI\
├── backend\                    FastAPI + SQLite backend
│   ├── main.py                 App entry point
│   ├── database.py             SQLAlchemy models
│   ├── schemas.py              Pydantic schemas
│   ├── requirements.txt
│   ├── routers\
│   │   ├── check.py            POST /api/v1/check
│   │   ├── history.py          GET  /api/v1/history
│   │   ├── analytics.py        GET  /api/v1/analytics
│   │   ├── threats.py          GET  /api/v1/threats
│   │   ├── blacklist.py        CRUD /api/v1/blacklist
│   │   ├── whitelist.py        CRUD /api/v1/whitelist
│   │   └── settings_router.py  GET/PUT /api/v1/settings
│   ├── services\
│   │   ├── ai_engine.py        Core AI detection (heuristics + ML)
│   │   ├── domain_reputation.py Domain scoring
│   │   ├── content_analyzer.py HTML/DOM analysis
│   │   └── cache_service.py    In-memory LRU cache
│   └── ml\
│       ├── feature_extractor.py URL feature extraction (30 features)
│       └── train_model.py      Random Forest + Gradient Boosting ensemble
│
├── extension\                  Chrome Extension (Manifest V3)
│   ├── manifest.json
│   ├── background\
│   │   └── background.js       Service worker (tab monitor, badge, API calls)
│   ├── content\
│   │   └── content.js          DOM analysis + threat overlay injection
│   ├── popup\                  Extension popup UI
│   ├── settings\               Settings page
│   ├── dashboard\              Analytics dashboard (Chart.js)
│   └── icons\
│
└── generate_icons.py           Icon generation utility
```

---

## AI Detection Engine

Multi-layer detection combining:

1. **URL Heuristics** — 20+ rule-based checks (IP detection, suspicious TLDs, brand impersonation, entropy analysis, redirect patterns)
2. **ML Model** — Random Forest + Gradient Boosting ensemble trained on 1,200+ URL samples with 30 features
3. **Domain Reputation** — TLD risk scoring, typosquatting detection, entropy analysis, punycode/homograph detection
4. **Content Analysis** — Form analysis, JavaScript pattern detection, social engineering text, hidden elements

### Threat Types
`phishing` · `fake_login` · `fake_banking` · `crypto_scam` · `fake_payment` · `malware` · `scam` · `suspicious_redirect` · `suspicious`

### Risk Levels
`safe (0-20)` · `low (20-40)` · `medium (40-60)` · `high (60-80)` · `critical (80-100)`

---

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/v1/check` | Scan a URL |
| GET | `/api/v1/history` | Scan history |
| GET | `/api/v1/analytics` | Analytics data |
| GET | `/api/v1/stats` | Quick stats |
| GET | `/api/v1/threats` | Threat records |
| GET/POST/DELETE | `/api/v1/blacklist` | Blacklist management |
| GET/POST/DELETE | `/api/v1/whitelist` | Whitelist management |
| GET/PUT | `/api/v1/settings` | App settings |
| GET | `/health` | Health check |

---

## Extension Features

- **Real-time tab monitoring** — Scans every page automatically
- **Threat overlay** — Full-screen warning with Shadow DOM isolation
- **Dynamic badge** — Color-coded risk indicator (green/yellow/red)
- **Popup dashboard** — Current page status, risk meter, threat details
- **Settings page** — Whitelist/blacklist management, sensitivity control
- **Analytics dashboard** — Charts, graphs, threat history (Chart.js)
- **Smart caching** — LRU cache prevents duplicate API calls
- **Offline mode** — Falls back to local storage when API unavailable

---

## Tech Stack

**Backend:** FastAPI · SQLAlchemy · SQLite · scikit-learn · tldextract  
**Extension:** Chrome MV3 · Vanilla JS · Shadow DOM  
**UI:** CSS glassmorphism · Cybersecurity aesthetic · Chart.js  
**ML:** Random Forest + Gradient Boosting ensemble · 30-feature URL extraction
