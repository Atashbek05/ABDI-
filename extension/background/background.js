// CyberShield AI — Background Service Worker (MV3)

const API_BASE = "http://127.0.0.1:8000/api/v1";
const SCAN_DEBOUNCE_MS = 800;
const BADGE_COLORS = {
  safe: "#00ff88",
  low: "#ffdd00",
  medium: "#ff9900",
  high: "#ff4400",
  critical: "#ff0044",
  scanning: "#00aaff",
  unknown: "#888888",
};

// Per-tab state: { url, result, scanning }
const tabState = {};
const scanTimers = {};

// ── Init ────────────────────────────────────────────────────────────────────

chrome.runtime.onInstalled.addListener(() => {
  chrome.storage.local.set({
    protectionEnabled: true,
    autoBlock: false,
    sensitivity: "medium",
    notifications: true,
    realtimeScan: true,
    scanMode: "full",
    scanHistory: [],
    totalScans: 0,
    totalThreats: 0,
  });
  setBadge("unknown", "—");
});

// ── Tab monitoring ──────────────────────────────────────────────────────────

chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status === "complete" && tab.url && isHttpUrl(tab.url)) {
    scheduleTabScan(tabId, tab.url);
  }
});

chrome.tabs.onActivated.addListener(({ tabId }) => {
  if (tabState[tabId]) {
    updateBadgeFromState(tabId);
  } else {
    chrome.tabs.get(tabId, (tab) => {
      if (tab && tab.url && isHttpUrl(tab.url)) {
        scheduleTabScan(tabId, tab.url);
      }
    });
  }
});

chrome.tabs.onRemoved.addListener((tabId) => {
  delete tabState[tabId];
  if (scanTimers[tabId]) {
    clearTimeout(scanTimers[tabId]);
    delete scanTimers[tabId];
  }
});

// ── Web navigation — detect redirects ──────────────────────────────────────

chrome.webNavigation.onCommitted.addListener(({ tabId, url, transitionType }) => {
  if (!isHttpUrl(url)) return;
  if (["redirect", "server_redirect", "client_redirect"].includes(transitionType)) {
    const state = tabState[tabId];
    if (state) {
      state.redirectCount = (state.redirectCount || 0) + 1;
    }
  }
});

// ── Scan scheduling ─────────────────────────────────────────────────────────

function scheduleTabScan(tabId, url) {
  if (scanTimers[tabId]) clearTimeout(scanTimers[tabId]);
  scanTimers[tabId] = setTimeout(() => scanTab(tabId, url), SCAN_DEBOUNCE_MS);
}

async function scanTab(tabId, url) {
  const settings = await getSettings();
  if (!settings.protectionEnabled || !settings.realtimeScan) return;

  // Mark as scanning
  tabState[tabId] = { url, result: null, scanning: true, redirectCount: 0 };
  setBadgeForTab(tabId, "scanning", "…");

  try {
    // Request DOM data from content script
    let domData = {};
    try {
      const resp = await chrome.tabs.sendMessage(tabId, { type: "GET_DOM_DATA" });
      domData = resp || {};
    } catch (_) {
      // Content script not ready yet — scan URL only
    }

    const payload = {
      url,
      html_content: domData.htmlSnippet || null,
      page_title: domData.pageTitle || null,
      page_text: domData.pageText || null,
      forms: domData.forms || null,
      scripts: domData.scripts || null,
      redirects: domData.redirects || null,
      dom_data: domData.domData || null,  // Enhanced visual analysis data
    };

    const result = await callAPI("/check", payload);
    if (!result) return;

    tabState[tabId] = { url, result, scanning: false, redirectCount: 0 };
    updateBadgeFromState(tabId);
    await persistScanResult(result);

    if (!result.is_safe) {
      await handleThreat(tabId, result, settings);
    }
  } catch (err) {
    console.error("[CyberShield] Scan error:", err);
    tabState[tabId] = { url, result: null, scanning: false };
    setBadgeForTab(tabId, "unknown", "?");
  }
}

async function handleThreat(tabId, result, settings) {
  const { risk_level, threat_type, confidence } = result;

  // Show notification
  if (settings.notifications) {
    chrome.notifications.create(`threat_${tabId}_${Date.now()}`, {
      type: "basic",
      iconUrl: chrome.runtime.getURL("icons/icon128.png"),
      title: `⚠ CyberShield — ${risk_level.toUpperCase()} THREAT`,
      message: `${result.domain}: ${threat_type.replace("_", " ")} (${confidence.toFixed(0)}% confidence)`,
      priority: risk_level === "critical" ? 2 : 1,
    });
  }

  // Inject overlay into page
  try {
    await chrome.scripting.executeScript({
      target: { tabId },
      func: showOverlay,
      args: [result],
    });
  } catch (err) {
    console.warn("[CyberShield] Overlay injection failed:", err);
  }

  // Auto-block critical threats if enabled
  if (settings.autoBlock && (risk_level === "critical" || risk_level === "high")) {
    try {
      await chrome.tabs.update(tabId, { url: chrome.runtime.getURL("blocked.html") });
    } catch (_) {}
  }
}

// ── Overlay injector (runs in page context) ─────────────────────────────────

function showOverlay(result) {
  if (document.getElementById("cybershield-overlay")) return;

  const riskColors = {
    low: "#ffdd00", medium: "#ff9900", high: "#ff4400", critical: "#ff0044",
  };
  const color = riskColors[result.risk_level] || "#ff4400";

  const overlay = document.createElement("div");
  overlay.id = "cybershield-overlay";
  overlay.style.cssText = `
    position: fixed; top: 0; left: 0; width: 100%; height: 100%; z-index: 2147483647;
    background: rgba(0,0,0,0.97); display: flex; align-items: center; justify-content: center;
    font-family: 'Courier New', monospace; animation: cs-fade-in 0.3s ease;
  `;

  const threatNames = {
    phishing: "PHISHING ATTACK", fake_login: "FAKE LOGIN PAGE",
    fake_banking: "FAKE BANKING SITE", crypto_scam: "CRYPTO SCAM",
    fake_payment: "FAKE PAYMENT PAGE", malware: "MALWARE SITE",
    scam: "SCAM WEBSITE", suspicious_redirect: "SUSPICIOUS REDIRECT",
    suspicious: "SUSPICIOUS SITE",
  };
  const threatName = threatNames[result.threat_type] || "SECURITY THREAT";

  overlay.innerHTML = `
    <style>
      @keyframes cs-fade-in { from { opacity: 0; transform: scale(0.95); } to { opacity: 1; transform: scale(1); } }
      @keyframes cs-pulse { 0%,100% { box-shadow: 0 0 20px ${color}44; } 50% { box-shadow: 0 0 60px ${color}88, 0 0 120px ${color}44; } }
      @keyframes cs-scan { 0% { transform: translateY(-100%); } 100% { transform: translateY(100vh); } }
      #cs-card { background: linear-gradient(145deg, #0a0a0f, #0f0f1a); border: 2px solid ${color};
        border-radius: 16px; padding: 40px; max-width: 680px; width: 90%; text-align: center;
        animation: cs-pulse 2s ease-in-out infinite; position: relative; overflow: hidden; }
      #cs-scanline { position: absolute; top: 0; left: 0; right: 0; height: 2px;
        background: linear-gradient(90deg, transparent, ${color}, transparent);
        animation: cs-scan 3s linear infinite; }
      #cs-shield { font-size: 80px; margin-bottom: 20px; }
      #cs-threat-type { font-size: 11px; letter-spacing: 4px; color: ${color}; text-transform: uppercase; margin-bottom: 8px; }
      #cs-title { font-size: 28px; font-weight: 900; color: #ffffff; margin-bottom: 6px; letter-spacing: 1px; }
      #cs-domain { font-size: 14px; color: #aaaacc; margin-bottom: 24px; word-break: break-all; }
      #cs-confidence { margin: 20px 0; }
      #cs-bar-bg { background: #1a1a2e; border-radius: 6px; height: 10px; overflow: hidden; margin-top: 8px; }
      #cs-bar-fill { height: 100%; border-radius: 6px; background: linear-gradient(90deg, ${color}88, ${color});
        width: ${result.confidence.toFixed(0)}%; transition: width 1s ease; }
      #cs-reasons { background: rgba(255,255,255,0.04); border: 1px solid #333366; border-radius: 8px;
        padding: 16px; margin: 20px 0; text-align: left; max-height: 140px; overflow-y: auto; }
      #cs-reasons li { font-size: 12px; color: #ccccdd; margin: 4px 0; list-style: none; padding-left: 16px; position: relative; }
      #cs-reasons li::before { content: "▸"; position: absolute; left: 0; color: ${color}; }
      #cs-actions { display: flex; gap: 12px; justify-content: center; margin-top: 28px; flex-wrap: wrap; }
      .cs-btn { padding: 12px 28px; border-radius: 8px; font-size: 13px; font-weight: 700;
        letter-spacing: 1px; cursor: pointer; transition: all 0.2s; border: 2px solid; font-family: inherit; }
      .cs-btn-back { background: ${color}22; border-color: ${color}; color: ${color}; }
      .cs-btn-back:hover { background: ${color}44; transform: scale(1.02); }
      .cs-btn-proceed { background: transparent; border-color: #444466; color: #666688; }
      .cs-btn-proceed:hover { background: #1a1a2e; color: #8888aa; }
    </style>
    <div id="cs-card">
      <div id="cs-scanline"></div>
      <div id="cs-shield">🛡️</div>
      <div id="cs-threat-type">⚠ THREAT DETECTED — ${threatName}</div>
      <div id="cs-title">DANGER: Access Blocked</div>
      <div id="cs-domain">${result.domain}</div>
      <div id="cs-confidence">
        <div style="display:flex;justify-content:space-between;font-size:11px;color:#666688">
          <span>AI CONFIDENCE</span><span style="color:${color}">${result.confidence.toFixed(1)}%</span>
        </div>
        <div id="cs-bar-bg"><div id="cs-bar-fill"></div></div>
      </div>
      ${result.reasons && result.reasons.length ? `
        <div id="cs-reasons">
          <div style="font-size:11px;color:#666688;letter-spacing:2px;margin-bottom:8px">THREAT INDICATORS</div>
          <ul>${result.reasons.slice(0, 5).map(r => `<li>${r}</li>`).join("")}</ul>
        </div>` : ""}
      <div style="font-size:11px;color:#555577;margin-top:12px;line-height:1.6">${result.explanation || ""}</div>
      <div id="cs-actions">
        <button class="cs-btn cs-btn-back" onclick="history.back()">← GO BACK (SAFE)</button>
        <button class="cs-btn cs-btn-proceed" onclick="document.getElementById('cybershield-overlay').remove()">
          PROCEED ANYWAY (RISK)
        </button>
      </div>
    </div>
  `;

  document.body.appendChild(overlay);
}

// ── Badge helpers ────────────────────────────────────────────────────────────

function setBadge(level, text) {
  const color = BADGE_COLORS[level] || BADGE_COLORS.unknown;
  chrome.action.setBadgeBackgroundColor({ color });
  chrome.action.setBadgeText({ text: text || "" });
}

function setBadgeForTab(tabId, level, text) {
  const color = BADGE_COLORS[level] || BADGE_COLORS.unknown;
  chrome.action.setBadgeBackgroundColor({ color, tabId });
  chrome.action.setBadgeText({ text: text || "", tabId });
}

function updateBadgeFromState(tabId) {
  const state = tabState[tabId];
  if (!state) { setBadgeForTab(tabId, "unknown", "?"); return; }
  if (state.scanning) { setBadgeForTab(tabId, "scanning", "…"); return; }
  if (!state.result) { setBadgeForTab(tabId, "unknown", "?"); return; }

  const level = state.result.risk_level || "unknown";
  const badgeTexts = { safe: "✓", low: "!", medium: "!!", high: "!!", critical: "⚠" };
  setBadgeForTab(tabId, level, badgeTexts[level] || "?");
}

// ── API call ─────────────────────────────────────────────────────────────────

async function callAPI(endpoint, body) {
  try {
    const resp = await fetch(API_BASE + endpoint, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
      signal: AbortSignal.timeout(10000),
    });
    if (!resp.ok) throw new Error(`API error ${resp.status}`);
    return resp.json();
  } catch (err) {
    console.error("[CyberShield] API call failed:", err);
    return null;
  }
}

// ── Storage helpers ──────────────────────────────────────────────────────────

async function getSettings() {
  return chrome.storage.local.get([
    "protectionEnabled", "autoBlock", "sensitivity",
    "notifications", "realtimeScan", "scanMode",
  ]);
}

async function persistScanResult(result) {
  const data = await chrome.storage.local.get(["scanHistory", "totalScans", "totalThreats"]);
  const history = data.scanHistory || [];
  history.unshift({
    url: result.url,
    domain: result.domain,
    is_safe: result.is_safe,
    threat_type: result.threat_type,
    risk_level: result.risk_level,
    confidence: result.confidence,
    timestamp: result.timestamp,
  });
  if (history.length > 200) history.splice(200);

  await chrome.storage.local.set({
    scanHistory: history,
    totalScans: (data.totalScans || 0) + 1,
    totalThreats: (data.totalThreats || 0) + (result.is_safe ? 0 : 1),
    lastScan: result,
  });
}

// ── Message handling ─────────────────────────────────────────────────────────

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg.type === "GET_TAB_STATE") {
    const tabId = sender.tab?.id || msg.tabId;
    sendResponse(tabState[tabId] || null);
    return true;
  }

  if (msg.type === "RESCAN_TAB") {
    const tabId = msg.tabId;
    chrome.tabs.get(tabId, (tab) => {
      if (tab && tab.url) scheduleTabScan(tabId, tab.url);
    });
    sendResponse({ started: true });
    return true;
  }

  if (msg.type === "MARK_BLOCKED") {
    const { tabId } = msg;
    if (tabState[tabId]?.result) {
      tabState[tabId].result.blocked = true;
    }
    sendResponse({ ok: true });
    return true;
  }

  if (msg.type === "GET_STATS") {
    chrome.storage.local.get(["totalScans", "totalThreats"], sendResponse);
    return true;
  }
});

// ── Utility ──────────────────────────────────────────────────────────────────

function isHttpUrl(url) {
  return url && (url.startsWith("http://") || url.startsWith("https://"));
}
