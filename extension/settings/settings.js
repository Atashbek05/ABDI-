// CyberShield AI — Settings Page

let API_BASE = "https://abdi-d1ph.onrender.com/api/v1";

const $ = (id) => document.getElementById(id);

document.addEventListener("DOMContentLoaded", async () => {
  await loadSettings();
  await loadWhitelist();
  await loadBlacklist();
  setupListeners();

  document.getElementById("back-btn").addEventListener("click", () => {
    window.location.href = chrome.runtime.getURL("dashboard/dashboard.html");
  });
});

// ── Load ─────────────────────────────────────────────────────────────────────

async function loadSettings() {
  const data = await chrome.storage.local.get([
    "protectionEnabled", "autoBlock", "sensitivity",
    "notifications", "realtimeScan", "scanMode", "apiUrl",
  ]);
  $("s-protection").checked = data.protectionEnabled !== false;
  $("s-realtime").checked = data.realtimeScan !== false;
  $("s-autoblock").checked = !!data.autoBlock;
  $("s-notifications").checked = data.notifications !== false;
  $("s-sensitivity").value = data.sensitivity || "medium";
  $("s-scan-mode").value = data.scanMode || "full";
  const DEFAULT_API = "https://abdi-d1ph.onrender.com";
  const isStale = !data.apiUrl || /localhost|127\.0\.0\.1/.test(data.apiUrl);
  const resolvedUrl = isStale ? DEFAULT_API : data.apiUrl;
  if (isStale) await chrome.storage.local.set({ apiUrl: DEFAULT_API });
  $("s-api-url").value = resolvedUrl;
  API_BASE = resolvedUrl + "/api/v1";
}

async function loadWhitelist() {
  try {
    const resp = await fetch(`${API_BASE}/whitelist`, { signal: AbortSignal.timeout(4000) });
    if (resp.ok) {
      const entries = await resp.json();
      renderDomainList("whitelist-list", entries, removeFromWhitelist, "white");
      return;
    }
  } catch (_) {}
  $("whitelist-list").innerHTML = `<div class="list-empty">Сервер недоступен — изменения не сохранятся</div>`;
}

async function loadBlacklist() {
  try {
    const resp = await fetch(`${API_BASE}/blacklist`, { signal: AbortSignal.timeout(4000) });
    if (resp.ok) {
      const entries = await resp.json();
      renderDomainList("blacklist-list", entries, removeFromBlacklist, "black");
      return;
    }
  } catch (_) {}
  $("blacklist-list").innerHTML = `<div class="list-empty">Сервер недоступен — изменения не сохранятся</div>`;
}

function renderDomainList(containerId, entries, removeFn, type) {
  const container = $(containerId);
  if (!entries.length) {
    container.innerHTML = `<div class="list-empty">Нет записей</div>`;
    return;
  }
  container.innerHTML = entries
    .map(
      (e) => `
      <div class="domain-tag" id="tag-${type}-${CSS.escape(e.domain)}">
        <span class="domain-name">${escapeHtml(e.domain)}</span>
        <button class="domain-remove" data-domain="${escapeHtml(e.domain)}" data-type="${type}" title="Удалить">✕</button>
      </div>`
    )
    .join("");

  container.querySelectorAll(".domain-remove").forEach((btn) => {
    btn.addEventListener("click", () => {
      if (type === "white") removeFromWhitelist(btn.dataset.domain);
      else removeFromBlacklist(btn.dataset.domain);
    });
  });
}

// ── Mutations ─────────────────────────────────────────────────────────────────

async function addToWhitelist(domain) {
  try {
    const resp = await fetch(`${API_BASE}/whitelist`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ domain, reason: "User added" }),
    });
    if (resp.ok || resp.status === 409) {
      loadWhitelist();
    }
  } catch (_) {
    alert("Сервер недоступен — невозможно сохранить");
  }
}

async function removeFromWhitelist(domain) {
  try {
    await fetch(`${API_BASE}/whitelist/${encodeURIComponent(domain)}`, { method: "DELETE" });
    loadWhitelist();
  } catch (_) {}
}

async function addToBlacklist(domain) {
  try {
    const resp = await fetch(`${API_BASE}/blacklist`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ domain, reason: "User blocked" }),
    });
    if (resp.ok || resp.status === 409) {
      loadBlacklist();
    }
  } catch (_) {
    alert("Сервер недоступен — невозможно сохранить");
  }
}

async function removeFromBlacklist(domain) {
  try {
    await fetch(`${API_BASE}/blacklist/${encodeURIComponent(domain)}`, { method: "DELETE" });
    loadBlacklist();
  } catch (_) {}
}

// ── Save ──────────────────────────────────────────────────────────────────────

async function saveSettings() {
  const apiUrl = $("s-api-url").value.trim().replace(/\/$/, "");
  await chrome.storage.local.set({
    protectionEnabled: $("s-protection").checked,
    realtimeScan: $("s-realtime").checked,
    autoBlock: $("s-autoblock").checked,
    notifications: $("s-notifications").checked,
    sensitivity: $("s-sensitivity").value,
    scanMode: $("s-scan-mode").value,
    apiUrl,
  });

  const msg = $("save-msg");
  msg.textContent = "✓ Настройки сохранены!";
  setTimeout(() => { msg.textContent = ""; }, 3000);
}

// ── Test connection ──────────────────────────────────────────────────────────

async function testConnection() {
  const apiUrl = $("s-api-url").value.trim().replace(/\/$/, "");
  const status = $("connection-status");
  status.className = "connection-status";
  status.textContent = "Проверка…";
  status.style.display = "block";

  try {
    const resp = await fetch(`${apiUrl}/health`, { signal: AbortSignal.timeout(5000) });
    if (resp.ok) {
      const data = await resp.json();
      status.className = "connection-status ok";
      status.textContent = `✓ Подключено — ${data.service} v${data.version} (${data.ml_model})`;
    } else {
      status.className = "connection-status fail";
      status.textContent = `✗ Сервер вернул HTTP ${resp.status} — проверьте логи сервера`;
    }
  } catch (err) {
    status.className = "connection-status fail";
    if (err instanceof TypeError) {
      // Network-level failure: server not running or wrong host
      status.textContent = `✗ Backend не запущен — запустите сервер (${apiUrl})`;
    } else if (err.name === "AbortError") {
      status.textContent = "✗ Превышено время ожидания (5 с) — сервер перегружен или недоступен";
    } else {
      status.textContent = `✗ Не удалось достучаться до сервера — проверьте правильность URL`;
    }
  }
}

// ── Export ────────────────────────────────────────────────────────────────────

async function exportReport() {
  try {
    const resp = await fetch(`${API_BASE}/history?limit=500`, { signal: AbortSignal.timeout(8000) });
    if (!resp.ok) throw new Error("Failed to fetch history");
    const history = await resp.json();
    const csv = buildCSV(history);
    downloadFile("cybershield-report.csv", csv, "text/csv");
  } catch (err) {
    alert("Ошибка экспорта: " + err.message);
  }
}

function buildCSV(records) {
  const header = "ID,URL,Domain,Safe,ThreatType,RiskLevel,Confidence,Timestamp\n";
  const rows = records
    .map((r) => [r.id, `"${r.url}"`, r.domain, r.is_safe, r.threat_type, r.risk_level, r.confidence, r.timestamp].join(","))
    .join("\n");
  return header + rows;
}

function downloadFile(filename, content, type) {
  const blob = new Blob([content], { type });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

// ── Event listeners ──────────────────────────────────────────────────────────

function setupListeners() {
  $("save-btn").addEventListener("click", saveSettings);
  $("test-connection-btn").addEventListener("click", testConnection);
  $("export-btn").addEventListener("click", exportReport);

  $("clear-history-btn").addEventListener("click", async () => {
    if (!confirm("Очистить всю историю проверок?")) return;
    try {
      await fetch(`${API_BASE}/history`, { method: "DELETE" });
      await chrome.storage.local.set({ scanHistory: [], totalScans: 0, totalThreats: 0 });
      alert("История очищена.");
    } catch (_) {
      await chrome.storage.local.set({ scanHistory: [], totalScans: 0, totalThreats: 0 });
      alert("Локальная история очищена (сервер офлайн).");
    }
  });

  $("whitelist-add-btn").addEventListener("click", () => {
    const val = $("whitelist-input").value.trim().toLowerCase().replace(/^https?:\/\//, "").replace(/^www\./, "").split("/")[0];
    if (val) {
      addToWhitelist(val);
      $("whitelist-input").value = "";
    }
  });

  $("blacklist-add-btn").addEventListener("click", () => {
    const val = $("blacklist-input").value.trim().toLowerCase().replace(/^https?:\/\//, "").replace(/^www\./, "").split("/")[0];
    if (val) {
      addToBlacklist(val);
      $("blacklist-input").value = "";
    }
  });

  $("whitelist-input").addEventListener("keydown", (e) => {
    if (e.key === "Enter") $("whitelist-add-btn").click();
  });
  $("blacklist-input").addEventListener("keydown", (e) => {
    if (e.key === "Enter") $("blacklist-add-btn").click();
  });
}

function escapeHtml(s) {
  return String(s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}
