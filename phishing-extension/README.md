# AI Phishing Detector — Chrome Extension (Manifest V3)

Real-time phishing detection using an AI/ML FastAPI backend.

---

## File Structure

```
phishing-extension/
├── manifest.json        # MV3 manifest
├── background.js        # Service worker — tab monitoring, backend calls
├── content.js           # Injected into pages — overlay management
├── popup.html           # Extension popup UI
├── popup.js             # Popup logic
├── style.css            # Overlay styles (injected via content_scripts)
├── icons/
│   ├── icon16.png       # 16×16 toolbar icon
│   ├── icon48.png       # 48×48 icon
│   ├── icon128.png      # 128×128 store icon
│   └── generate_icons.html  # Helper to generate placeholder icons
└── README.md
```

---

## Quick Start

### 1. Generate Icons

Open `icons/generate_icons.html` in any browser and download the three PNG
files into the `icons/` folder. Then delete `generate_icons.html`.

### 2. Start the FastAPI Backend

The extension expects a POST endpoint at `http://127.0.0.1:8000/check`.

**Expected request body:**
```json
{ "url": "https://example.com" }
```

**Expected response:**
```json
{
  "prediction":  "phishing",   // "phishing" | "safe"
  "confidence":  0.97,         // float 0–1
  "risk_level":  "HIGH",       // "LOW" | "MEDIUM" | "HIGH" | "CRITICAL"
  "is_phishing": true          // optional bool shortcut
}
```

### 3. Load the Extension in Chrome

1. Open Chrome and navigate to `chrome://extensions/`
2. Enable **Developer mode** (toggle, top-right)
3. Click **Load unpacked**
4. Select the `phishing-extension/` folder
5. The shield icon appears in the toolbar

### 4. Test It

- Navigate to any website — the extension auto-checks the URL
- Click the toolbar icon to see the popup with AI results
- If phishing is detected: a full-screen red overlay appears + notification
- Click **↺ RE-ANALYSE URL** to force a fresh check

---

## Architecture

```
chrome.tabs.onUpdated
        │
        ▼
  background.js          ← Service Worker (persistent)
  ├── URL filter
  ├── Result cache (5 min TTL)
  ├── POST /check  ──────► FastAPI Backend
  ├── chrome.storage.session  (per-tab state)
  ├── chrome.scripting.executeScript  ──► content.js overlay
  └── chrome.notifications

  content.js             ← Injected per-page
  ├── __phishingShowWarning()
  └── __phishingHideWarning()

  popup.js               ← Extension popup
  ├── Reads tab state via background message
  ├── Renders safe / danger / checking / error UI
  └── Re-check button
```

---

## Backend CORS

If your FastAPI backend returns CORS errors, add this to `main.py`:

```python
from fastapi.middleware.cors import CORSMiddleware

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],     # restrict in production
    allow_methods=["POST"],
    allow_headers=["Content-Type"],
)
```

---

## Permissions Used

| Permission | Why |
|---|---|
| `tabs` | Monitor tab URL changes |
| `activeTab` | Read current tab URL in popup |
| `scripting` | Inject overlay into pages |
| `notifications` | Show system alert on phishing |
| `storage` | Cache detection results per-tab |
| `host_permissions: <all_urls>` | Fetch URLs to backend |
