// =============================================
// AI Phishing Detector - Popup Script v2
// Scan results + History tab + Dashboard link
// =============================================

const BACKEND_BASE = "http://127.0.0.1:8000";
const BACKEND_URL  = `${BACKEND_BASE}/check`;

// ---- DOM refs ----
const el = {
  url:            document.getElementById("currentUrl"),
  backendStatus:  document.getElementById("backendStatus"),
  backendLabel:   document.getElementById("backendLabel"),
  resultCard:     document.getElementById("resultCard"),
  badgeIcon:      document.getElementById("badgeIcon"),
  badgeLabel:     document.getElementById("badgeLabel"),
  metricsGrid:    document.getElementById("metricsGrid"),
  metricVerdict:  document.getElementById("metricVerdict"),
  metricRisk:     document.getElementById("metricRisk"),
  confidenceWrap: document.getElementById("confidenceWrap"),
  confidenceText: document.getElementById("confidenceText"),
  confidenceFill: document.getElementById("confidenceFill"),
  reasonsSection: document.getElementById("reasonsSection"),
  reasonsList:    document.getElementById("reasonsList"),
  recheckBtn:     document.getElementById("recheckBtn"),
  // Tabs
  tabScan:        document.getElementById("tabScan"),
  tabHistory:     document.getElementById("tabHistory"),
  panelScan:      document.getElementById("panelScan"),
  panelHistory:   document.getElementById("panelHistory"),
  openDashboard:  document.getElementById("openDashboard"),
  // History
  historyCount:   document.getElementById("historyCount"),
  clearHistoryBtn:document.getElementById("clearHistoryBtn"),
  historyLoading: document.getElementById("historyLoading"),
  historyEmpty:   document.getElementById("historyEmpty"),
  historyOffline: document.getElementById("historyOffline"),
  historyList:    document.getElementById("historyList"),
};

function escapeHtml(str) {
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;");
}

function relativeTime(iso) {
  const diff = Date.now() - new Date(iso).getTime();
  const s = Math.floor(diff / 1000);
  if (s < 60)  return `${s}s ago`;
  const m = Math.floor(s / 60);
  if (m < 60)  return `${m}m ago`;
  const h = Math.floor(m / 60);
  if (h < 24)  return `${h}h ago`;
  return new Date(iso).toLocaleDateString();
}

// ── Tab management ────────────────────────────────────────────────────────────

let activeTab = "scan";
let historyCache  = null;
let historyCacheTs = 0;
const HISTORY_CACHE_TTL = 30_000;

function switchTab(name) {
  activeTab = name;
  el.tabScan.classList.toggle("active", name === "scan");
  el.tabHistory.classList.toggle("active", name === "history");
  el.panelScan.hidden    = name !== "scan";
  el.panelHistory.hidden = name !== "history";

  if (name === "history") loadHistory();
}

el.tabScan.addEventListener("click",    () => switchTab("scan"));
el.tabHistory.addEventListener("click", () => switchTab("history"));

el.openDashboard.addEventListener("click", () => {
  chrome.tabs.create({ url: chrome.runtime.getURL("dashboard.html") });
});

// ── Backend health ping ───────────────────────────────────────────────────────

async function pingBackend() {
  try {
    const res = await fetch(BACKEND_URL, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url: "https://ping.test" }),
      signal: AbortSignal.timeout(3000),
    });
    setBackendStatus(res.ok ? "online" : "offline");
  } catch {
    setBackendStatus("offline");
  }
}

function setBackendStatus(state) {
  el.backendStatus.className = `backend-status ${state}`;
  el.backendLabel.textContent =
    state === "online"  ? "Online"  :
    state === "offline" ? "Offline" : "—";
}

// ── Scan tab render states ────────────────────────────────────────────────────

function renderChecking() {
  el.resultCard.className = "result-card checking";
  el.badgeIcon.textContent = "⏳";
  el.badgeLabel.className  = "badge-label checking";
  el.badgeLabel.textContent = "SCANNING…";
  el.metricsGrid.style.display    = "none";
  el.confidenceWrap.style.display = "none";
  el.reasonsSection.style.display = "none";
}

function renderError(message) {
  el.resultCard.className = "result-card error";
  el.badgeIcon.textContent = "✖";
  el.badgeLabel.className  = "badge-label error";
  el.badgeLabel.textContent = "ERROR";
  el.metricsGrid.style.display = "grid";
  el.metricVerdict.textContent  = "N/A";
  el.metricVerdict.className    = "metric-value";
  el.metricRisk.textContent     = message ?? "Backend unreachable";
  el.metricRisk.className       = "metric-value";
  el.confidenceWrap.style.display = "none";
  el.reasonsSection.style.display = "none";
}

function renderResult(tabState) {
  const { status, result } = tabState;
  const riskLevel = (result?.risk_level ?? (status === "danger" ? "high" : "safe")).toLowerCase();

  let cardState, icon, labelText, labelClass, fillClass;
  if (riskLevel === "high") {
    cardState = "danger";     icon = "🚨"; labelText = "PHISHING DETECTED"; labelClass = "danger"; fillClass = "danger";
  } else if (riskLevel === "suspicious") {
    cardState = "suspicious"; icon = "⚠️"; labelText = "SUSPICIOUS SITE";   labelClass = "warn";   fillClass = "warn";
  } else {
    cardState = "safe";       icon = "✔";  labelText = "SAFE";              labelClass = "safe";   fillClass = "safe";
  }

  el.resultCard.className  = `result-card ${cardState}`;
  el.badgeIcon.textContent = icon;
  el.badgeLabel.className  = `badge-label ${labelClass}`;
  el.badgeLabel.textContent = labelText;

  if (!result) return;

  const confidence = Math.round(result.confidence ?? 0);
  const prediction = (result.prediction ?? (cardState === "danger" ? "phishing" : "safe")).toUpperCase();
  const riskDisplay = riskLevel.toUpperCase();

  el.metricsGrid.style.display = "grid";
  el.metricVerdict.textContent = prediction;
  el.metricVerdict.className   = `metric-value ${riskLevelClass(riskDisplay)}`;
  el.metricRisk.textContent    = riskDisplay;
  el.metricRisk.className      = `metric-value ${riskLevelClass(riskDisplay)}`;

  el.confidenceWrap.style.display = "block";
  el.confidenceText.textContent   = `${confidence}%`;
  el.confidenceFill.style.width   = `${Math.min(confidence, 100)}%`;
  el.confidenceFill.className     = `confidence-fill ${fillClass}`;

  const reasons = Array.isArray(result.reasons) ? result.reasons : [];
  if (reasons.length > 0) {
    el.reasonsSection.style.display = "block";
    el.reasonsList.innerHTML = reasons.map((r, i) =>
      `<li class="reason-item ${fillClass === "safe" ? "ok" : fillClass === "warn" ? "warn-item" : "threat"}" style="animation-delay:${i * 40}ms">` +
      `<span class="reason-dot"></span>${escapeHtml(r)}</li>`
    ).join("");
  } else {
    el.reasonsSection.style.display = "none";
  }
}

function riskLevelClass(level) {
  if (level === "HIGH" || level === "CRITICAL") return "v-danger";
  if (level === "MEDIUM" || level === "SUSPICIOUS") return "v-warn";
  return "v-safe";
}

// ── History tab ───────────────────────────────────────────────────────────────

function showHistoryState(state) {
  el.historyLoading.hidden  = state !== "loading";
  el.historyEmpty.hidden    = state !== "empty";
  el.historyOffline.hidden  = state !== "offline";
  el.historyList.hidden     = state !== "list";
}

function riskBadgeHtml(risk) {
  const cls   = risk === "high" ? "rb-high" : risk === "suspicious" ? "rb-suspicious" : "rb-safe";
  const label = risk === "high" ? "HIGH"    : risk === "suspicious" ? "SUSP"          : "SAFE";
  return `<span class="risk-badge ${cls}">${label}</span>`;
}

function truncateUrl(url, maxLen = 38) {
  try {
    const parsed = new URL(url);
    const short  = parsed.hostname + parsed.pathname;
    return short.length > maxLen ? short.slice(0, maxLen) + "…" : short;
  } catch {
    return url.length > maxLen ? url.slice(0, maxLen) + "…" : url;
  }
}

function renderHistoryItems(scans) {
  el.historyList.innerHTML = scans.map((s, i) => {
    const cls = s.risk_level === "high" ? "hi-high"
              : s.risk_level === "suspicious" ? "hi-suspicious"
              : "hi-safe";
    return `
      <div class="history-item ${cls}" style="animation-delay:${i * 25}ms" title="${escapeHtml(s.url)}">
        <div class="hi-url">${escapeHtml(truncateUrl(s.url))}</div>
        <div class="hi-meta">
          ${riskBadgeHtml(s.risk_level)}
          <span class="hi-conf">${s.confidence.toFixed(1)}%</span>
          <span class="hi-time">${relativeTime(s.timestamp)}</span>
        </div>
      </div>`;
  }).join("");
}

async function loadHistory(force = false) {
  const now = Date.now();
  if (!force && historyCache && now - historyCacheTs < HISTORY_CACHE_TTL) {
    applyHistoryData(historyCache);
    return;
  }

  showHistoryState("loading");

  try {
    const res = await fetch(`${BACKEND_BASE}/history?limit=30`, {
      signal: AbortSignal.timeout(5000),
    });
    if (!res.ok) throw new Error("non-200");
    const data = await res.json();
    historyCache   = data;
    historyCacheTs = Date.now();
    applyHistoryData(data);
  } catch {
    // If we have stale cache, show it; otherwise show offline state
    if (historyCache) {
      applyHistoryData(historyCache);
    } else {
      showHistoryState("offline");
      el.historyCount.textContent = "offline";
    }
  }
}

function applyHistoryData(data) {
  const scans = data?.scans ?? [];
  const total = data?.total ?? 0;

  el.historyCount.textContent = `${total} scan${total !== 1 ? "s" : ""} total`;

  if (scans.length === 0) {
    showHistoryState("empty");
    return;
  }

  renderHistoryItems(scans);
  showHistoryState("list");
}

el.clearHistoryBtn.addEventListener("click", async () => {
  el.clearHistoryBtn.disabled = true;
  el.clearHistoryBtn.textContent = "Clearing…";

  try {
    await fetch(`${BACKEND_BASE}/history`, {
      method: "DELETE",
      signal: AbortSignal.timeout(5000),
    });
    historyCache   = null;
    historyCacheTs = 0;
    el.historyCount.textContent = "0 scans total";
    showHistoryState("empty");
  } catch {
    // Backend unreachable — restore button
  }

  el.clearHistoryBtn.disabled = false;
  el.clearHistoryBtn.textContent = "✕ CLEAR ALL";
});

// ── Scan tab init ─────────────────────────────────────────────────────────────

async function init() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tab) return;

  el.url.textContent = tab.url ?? "Unknown";
  renderChecking();

  // Fire backend health check in parallel
  pingBackend();

  // Ask background for existing result
  const tabState = await chrome.runtime.sendMessage({
    type: "GET_TAB_STATUS",
    tabId: tab.id,
  });

  if (!tabState) {
    renderError("No result yet — navigate to a page first.");
    return;
  }

  if (tabState.status === "checking") {
    renderChecking();
    const interval = setInterval(async () => {
      const updated = await chrome.runtime.sendMessage({
        type: "GET_TAB_STATUS",
        tabId: tab.id,
      });
      if (updated && updated.status !== "checking") {
        clearInterval(interval);
        updated.status === "error"
          ? renderError(updated.error)
          : renderResult(updated);
      }
    }, 600);
  } else if (tabState.status === "error") {
    renderError(tabState.error);
  } else {
    renderResult(tabState);
  }

  // Recheck button
  el.recheckBtn.addEventListener("click", async () => {
    el.recheckBtn.disabled = true;
    el.recheckBtn.textContent = "↺ ANALYSING…";
    renderChecking();

    const response = await chrome.runtime.sendMessage({
      type: "RECHECK",
      tabId: tab.id,
      url: tab.url,
    }).catch(() => null);

    if (response?.ok) {
      const updated = await chrome.runtime.sendMessage({
        type: "GET_TAB_STATUS",
        tabId: tab.id,
      });
      updated?.status === "error"
        ? renderError(updated.error)
        : updated && renderResult(updated);
      // Invalidate history cache after a new scan
      historyCache   = null;
      historyCacheTs = 0;
    } else {
      renderError("Recheck failed.");
    }

    el.recheckBtn.disabled = false;
    el.recheckBtn.textContent = "↺ RE-ANALYSE URL";
  });

  // Live updates from background
  chrome.runtime.onMessage.addListener((message) => {
    if (message.type === "DETECTION_RESULT" && message.tabId === tab.id) {
      message.isPhishing
        ? renderResult({ status: "danger", result: message.result })
        : renderResult({ status: "safe",   result: message.result });
      // Invalidate history cache so next visit to History tab is fresh
      historyCache   = null;
      historyCacheTs = 0;
    }
  });
}

init().catch(console.error);
