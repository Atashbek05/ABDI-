// =============================================
// AI Phishing Detector — Background Service Worker v3
// Realtime protection: blacklist/whitelist, badge colours, settings, DOM signals
// =============================================

const BACKEND_BASE  = "http://127.0.0.1:8000";
const BACKEND_CHECK = `${BACKEND_BASE}/check`;
const CACHE_TTL_MS  = 5 * 60 * 1000;   // 5-minute per-URL result cache

const resultCache  = {};                 // { [url]: { result, timestamp } }
const overlayedTabs = new Set();
const pageSignals   = {};                // { [tabId]: signals } from content script

// ── Settings ──────────────────────────────────────────────────────────────────

const DEFAULT_SETTINGS = {
  protectionEnabled:  true,
  notificationsEnabled: true,
  blockHighRisk:      true,     // full-page block for high-risk sites
  warnSuspicious:     true,     // overlay warning for suspicious sites
  autoBlockBlacklist: true,     // always hard-block blacklisted domains
};

async function getSettings() {
  const data = await chrome.storage.local.get("settings");
  return { ...DEFAULT_SETTINGS, ...(data.settings ?? {}) };
}

// ── URL filter ────────────────────────────────────────────────────────────────

function shouldSkipUrl(url) {
  if (!url) return true;
  try {
    const { protocol } = new URL(url);
    return ["chrome:", "chrome-extension:", "about:", "data:", "file:", "edge:", "moz-extension:"]
      .includes(protocol);
  } catch {
    return true;
  }
}

// ── Cache helpers ─────────────────────────────────────────────────────────────

function getCached(url) {
  const entry = resultCache[url];
  if (!entry) return null;
  if (Date.now() - entry.timestamp > CACHE_TTL_MS) { delete resultCache[url]; return null; }
  return entry.result;
}

function setCached(url, result) {
  resultCache[url] = { result, timestamp: Date.now() };
}

function invalidateCache(url) {
  delete resultCache[url];
}

// ── Badge management ──────────────────────────────────────────────────────────

const BADGE_CFG = {
  safe:       { text: "✓",   color: "#00cc66", title: "Безопасно — Угрозы не обнаружены" },
  whitelist:  { text: "✓",   color: "#00aaff", title: "Доверенный — Домен в белом списке" },
  suspicious: { text: "!",   color: "#ffaa00", title: "Подозрительно — Соблюдайте осторожность" },
  danger:     { text: "✕",   color: "#ff1a1a", title: "Опасно — Фишинг обнаружен" },
  blocked:    { text: "БЛК", color: "#cc0000", title: "Заблокировано — Известный фишинговый домен" },
  checking:   { text: "...", color: "#3366ff", title: "Сканирование…" },
  error:      { text: "?",   color: "#555555", title: "Ошибка — Сервер недоступен" },
  disabled:   { text: "ВЫКЛ", color: "#444444", title: "Защита отключена" },
};

function setBadge(tabId, status) {
  const cfg = BADGE_CFG[status] ?? BADGE_CFG.error;
  chrome.action.setBadgeText({ text: cfg.text, tabId }).catch(() => {});
  chrome.action.setBadgeBackgroundColor({ color: cfg.color, tabId }).catch(() => {});
  chrome.action.setTitle({ title: `AI Phishing Detector — ${cfg.title}`, tabId }).catch(() => {});
}

// ── Backend communication ─────────────────────────────────────────────────────

async function checkUrl(url, signals) {
  const cached = getCached(url);
  if (cached) return { ...cached, cached: true };

  const body = { url };
  if (signals && Object.values(signals).some(Boolean)) {
    body.page_signals = signals;
  }

  const response = await fetch(BACKEND_CHECK, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
    signal: AbortSignal.timeout(8000),
  });

  if (!response.ok) throw new Error(`Backend returned ${response.status}`);

  const result = await response.json();
  setCached(url, result);
  return result;
}

// ── Overlay management ────────────────────────────────────────────────────────

async function injectOverlay(tabId, result, blocking) {
  if (overlayedTabs.has(tabId)) return;
  overlayedTabs.add(tabId);

  try {
    await chrome.scripting.executeScript({
      target: { tabId },
      func: (data, shouldBlock) => {
        if (typeof window.__phishingShowWarning === "function") {
          window.__phishingShowWarning(data, shouldBlock);
        }
      },
      args: [result, blocking],
    });
  } catch (err) {
    overlayedTabs.delete(tabId);
    console.warn("[PhishingDetector] Overlay injection failed:", err.message);
  }
}

async function removeOverlay(tabId) {
  if (!overlayedTabs.has(tabId)) return;
  overlayedTabs.delete(tabId);
  try {
    await chrome.scripting.executeScript({
      target: { tabId },
      func: () => { if (typeof window.__phishingHideWarning === "function") window.__phishingHideWarning(); },
    });
  } catch { /* tab may already be gone */ }
}

// ── Notifications ─────────────────────────────────────────────────────────────

function showThreatNotification(url, result) {
  const confidence  = Math.round(result.confidence ?? 0);
  const firstReason = Array.isArray(result.reasons) && result.reasons.length
    ? `\n${result.reasons[0]}` : "";
  const isBlacklisted = result.source === "blacklist";

  chrome.notifications.create(`threat_${Date.now()}`, {
    type:     "basic",
    iconUrl:  "icons/icon48.png",
    title:    isBlacklisted ? "🚫 Известный фишинговый домен заблокирован" : "⚠️ Фишинговая угроза обнаружена",
    message:  `${url}\nРиск: ${(result.risk_level ?? "HIGH").toUpperCase()} — Уверенность: ${confidence}%${firstReason}`,
    priority: 2,
  });
}

// ── Core detection flow ───────────────────────────────────────────────────────

async function runDetection(tabId, url) {
  if (shouldSkipUrl(url)) return;

  const settings = await getSettings();

  if (!settings.protectionEnabled) {
    setBadge(tabId, "disabled");
    await chrome.storage.session.set({ [`tab_${tabId}`]: { status: "disabled", url } });
    return;
  }

  setBadge(tabId, "checking");
  await chrome.storage.session.set({ [`tab_${tabId}`]: { status: "checking", url } });

  let result;
  try {
    const signals = pageSignals[tabId] ?? {};
    result = await checkUrl(url, signals);
  } catch (err) {
    console.error("[PhishingDetector] Backend error:", err.message);
    setBadge(tabId, "error");
    await chrome.storage.session.set({ [`tab_${tabId}`]: { status: "error", url, error: err.message } });
    return;
  }

  const isPhishing    = result.prediction === "phishing";
  const riskLevel     = result.risk_level ?? "safe";
  const isBlacklisted = result.source === "blacklist";
  const isWhitelisted = result.source === "whitelist";

  // Badge colour
  if (isWhitelisted) {
    setBadge(tabId, "whitelist");
  } else if (isBlacklisted) {
    setBadge(tabId, "blocked");
  } else if (isPhishing && riskLevel === "high") {
    setBadge(tabId, "danger");
  } else if (riskLevel === "suspicious") {
    setBadge(tabId, "suspicious");
  } else {
    setBadge(tabId, "safe");
  }

  // Persist for popup
  await chrome.storage.session.set({
    [`tab_${tabId}`]: {
      status: isPhishing ? "danger" : "safe",
      url,
      result,
    },
  });

  // Overlay decision
  const shouldBlock = isBlacklisted
    || (isPhishing && riskLevel === "high" && settings.blockHighRisk);
  const shouldWarn  = isPhishing && riskLevel === "suspicious" && settings.warnSuspicious;

  if (shouldBlock || shouldWarn) {
    await injectOverlay(tabId, result, shouldBlock);
    if (settings.notificationsEnabled) {
      showThreatNotification(url, result);
    }
  } else {
    await removeOverlay(tabId);
  }

  // Notify popup if open
  chrome.runtime.sendMessage({
    type: "DETECTION_RESULT", tabId, url, result, isPhishing,
  }).catch(() => {});
}

// ── Tab listeners ─────────────────────────────────────────────────────────────

chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status !== "complete" || !tab.url) return;
  overlayedTabs.delete(tabId);
  delete pageSignals[tabId];
  runDetection(tabId, tab.url);
});

chrome.tabs.onRemoved.addListener((tabId) => {
  overlayedTabs.delete(tabId);
  delete pageSignals[tabId];
  chrome.storage.session.remove(`tab_${tabId}`);
});

// ── Message handler ───────────────────────────────────────────────────────────

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {

  if (message.type === "GET_TAB_STATUS") {
    const key = `tab_${message.tabId}`;
    chrome.storage.session.get(key).then((data) => sendResponse(data[key] ?? null));
    return true;
  }

  if (message.type === "OVERLAY_CLOSED") {
    overlayedTabs.delete(sender.tab?.id);
  }

  if (message.type === "RECHECK") {
    invalidateCache(message.url);
    runDetection(message.tabId, message.url).then(() => sendResponse({ ok: true }));
    return true;
  }

  if (message.type === "PAGE_SECURITY_SIGNALS") {
    if (sender.tab?.id) pageSignals[sender.tab.id] = message.signals;
  }

  if (message.type === "GET_SETTINGS") {
    getSettings().then(sendResponse);
    return true;
  }

  if (message.type === "SAVE_SETTINGS") {
    chrome.storage.local.set({ settings: message.settings }).then(() => {
      sendResponse({ ok: true });
      if (message.settings.protectionEnabled) {
        chrome.tabs.query({ active: true, currentWindow: true }).then(([tab]) => {
          if (tab?.url) { invalidateCache(tab.url); runDetection(tab.id, tab.url); }
        });
      } else {
        chrome.tabs.query({ active: true, currentWindow: true }).then(([tab]) => {
          if (tab?.id) setBadge(tab.id, "disabled");
        });
      }
    });
    return true;
  }

  // Quick add-to-list helpers used by popup
  if (message.type === "ADD_TO_BLACKLIST") {
    fetch(`${BACKEND_BASE}/blacklist/add`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ domain: message.domain, reason: message.reason ?? "" }),
    })
      .then(r => r.json())
      .then(data => { invalidateCache(message.domain); sendResponse(data); })
      .catch(() => sendResponse({ ok: false }));
    return true;
  }

  if (message.type === "ADD_TO_WHITELIST") {
    fetch(`${BACKEND_BASE}/whitelist/add`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ domain: message.domain }),
    })
      .then(r => r.json())
      .then(data => { invalidateCache(message.domain); sendResponse(data); })
      .catch(() => sendResponse({ ok: false }));
    return true;
  }

  if (message.type === "REMOVE_FROM_BLACKLIST") {
    fetch(`${BACKEND_BASE}/blacklist/${message.id}`, { method: "DELETE" })
      .then(r => r.json()).then(sendResponse).catch(() => sendResponse({ ok: false }));
    return true;
  }

  if (message.type === "REMOVE_FROM_WHITELIST") {
    fetch(`${BACKEND_BASE}/whitelist/${message.id}`, { method: "DELETE" })
      .then(r => r.json()).then(sendResponse).catch(() => sendResponse({ ok: false }));
    return true;
  }
});
