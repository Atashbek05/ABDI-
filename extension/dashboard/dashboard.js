// CyberShield AI — Analytics Dashboard

const API_BASE = "https://abdi-d1ph.onrender.com/api/v1";

const CHART_FONT = { family: "system-ui, -apple-system, 'Segoe UI', sans-serif", size: 11 };

const CHART_DEFAULTS = {
  plugins: { legend: { labels: { color: "#8b949e", font: CHART_FONT } } },
  scales: {
    x: { ticks: { color: "#484f58", font: CHART_FONT }, grid: { color: "#21262d" } },
    y: { ticks: { color: "#484f58", font: CHART_FONT }, grid: { color: "#21262d" } },
  },
};

const THREAT_COLORS = {
  phishing: "#f85149", fake_login: "#ff7b72", fake_banking: "#ffa198",
  crypto_scam: "#d29922", fake_payment: "#e3b341", malware: "#ff6b6b",
  scam: "#d29922", suspicious_redirect: "#79c0ff", suspicious: "#8b949e",
};

const RISK_COLORS = {
  safe: "#3fb950", low: "#58a6ff", medium: "#d29922", high: "#e3b341", critical: "#f85149",
};

let charts = {};
let analyticsData = null;
let historyPage = 0;
const PAGE_SIZE = 50;

// ── Init ──────────────────────────────────────────────────────────────────────

document.addEventListener("DOMContentLoaded", () => {
  setupNav();
  loadAll();
  setInterval(loadAll, 30000); // auto-refresh every 30s
});

function setupNav() {
  document.querySelectorAll(".nav-item").forEach((btn) => {
    btn.addEventListener("click", () => {
      document.querySelectorAll(".nav-item").forEach((b) => b.classList.remove("active"));
      document.querySelectorAll(".view").forEach((v) => v.classList.remove("active"));
      btn.classList.add("active");
      const viewId = "view-" + btn.dataset.view;
      document.getElementById(viewId).classList.add("active");
      const label = btn.querySelector(".nav-label");
      document.getElementById("view-title").textContent = label ? label.textContent : btn.textContent.trim();

      if (btn.dataset.view === "analytics") renderAnalyticsCharts();
      if (btn.dataset.view === "threats") loadThreats();
      if (btn.dataset.view === "history") loadHistory();
    });
  });

  document.getElementById("refresh-btn").addEventListener("click", loadAll);
  document.getElementById("export-btn").addEventListener("click", exportData);
  document.getElementById("threats-filter-btn").addEventListener("click", loadThreats);
  document.getElementById("history-search").addEventListener("input", () => { historyPage = 0; loadHistory(); });
  document.getElementById("history-threats-only").addEventListener("change", () => { historyPage = 0; loadHistory(); });
}

async function loadAll() {
  await loadAnalytics();
  await loadHistory();
  await loadThreats();
}

// ── Analytics ─────────────────────────────────────────────────────────────────

async function loadAnalytics() {
  try {
    const resp = await fetch(`${API_BASE}/analytics`, { signal: AbortSignal.timeout(8000) });
    if (!resp.ok) throw new Error("API error");
    analyticsData = await resp.json();
    updateStatCards(analyticsData);
    renderOverviewCharts(analyticsData);
    renderRecentThreats(analyticsData.recent_threats || []);
  } catch (err) {
    console.error("Analytics load error:", err);
    showOfflineState();
  }
}

function updateStatCards(data) {
  animateCounter("v-total",   data.total_scans,       formatNum);
  animateCounter("v-threats", data.threats_detected,  formatNum);
  animateCounter("v-safe",    data.safe_sites,        formatNum);
  animateCounter("v-rate",    data.detection_rate,    (v) => v.toFixed(1) + "%");
  if (data.avg_scan_duration) {
    animateCounter("v-speed", data.avg_scan_duration, (v) => Math.round(v) + "ms");
  } else {
    setText("v-speed", "—");
  }
  if (data.avg_confidence) {
    animateCounter("v-confidence", data.avg_confidence, (v) => v.toFixed(1) + "%");
  } else {
    setText("v-confidence", "—");
  }
  setText("v-total-trend", `+${data.daily_scans.at(-1)?.scans || 0} сегодня`);
  setText("v-threat-trend", `${data.daily_scans.at(-1)?.threats || 0} сегодня`);
}

function renderOverviewCharts(data) {
  renderDailyChart(data.daily_scans || []);
  renderThreatDistChart(data.threat_distribution || {});
  renderRiskDistChart(data.risk_level_distribution || {});
}

function renderDailyChart(dailyScans) {
  const labels = dailyScans.map((d) => d.date.slice(5));
  const scans = dailyScans.map((d) => d.scans);
  const threats = dailyScans.map((d) => d.threats);

  destroyChart("chart-daily");
  charts["chart-daily"] = new Chart(document.getElementById("chart-daily"), {
    type: "bar",
    data: {
      labels,
      datasets: [
        {
          label: "Проверки",
          data: scans,
          backgroundColor: "rgba(88,166,255,0.25)",
          borderColor: "rgba(88,166,255,0.8)",
          borderWidth: 1,
          borderRadius: 4,
        },
        {
          label: "Угрозы",
          data: threats,
          backgroundColor: "rgba(248,81,73,0.45)",
          borderColor: "rgba(248,81,73,0.9)",
          borderWidth: 1,
          borderRadius: 4,
          type: "line",
          tension: 0.4,
          pointRadius: 3,
          yAxisID: "y",
        },
      ],
    },
    options: {
      responsive: true, maintainAspectRatio: false,
      ...CHART_DEFAULTS,
      plugins: { ...CHART_DEFAULTS.plugins, legend: { labels: { color: "#8b949e", font: CHART_FONT } } },
    },
  });
}

function renderThreatDistChart(dist) {
  const labels = Object.keys(dist).map(formatThreatType);
  const values = Object.values(dist);
  const colors = Object.keys(dist).map((k) => THREAT_COLORS[k] || "#8b949e");

  destroyChart("chart-threats");
  if (!labels.length) return;

  charts["chart-threats"] = new Chart(document.getElementById("chart-threats"), {
    type: "doughnut",
    data: {
      labels,
      datasets: [{
        data: values,
        backgroundColor: colors.map((c) => c + "cc"),
        borderColor: colors,
        borderWidth: 2,
        hoverOffset: 8,
      }],
    },
    options: {
      responsive: true, maintainAspectRatio: false,
      plugins: {
        legend: { position: "right", labels: { color: "#8b949e", font: CHART_FONT, boxWidth: 12 } },
      },
    },
  });
}

function renderRiskDistChart(dist) {
  const order = ["safe", "low", "medium", "high", "critical"];
  const labels = order.filter((k) => dist[k]);
  const values = labels.map((k) => dist[k]);
  const colors = labels.map((k) => RISK_COLORS[k] || "#8b949e");

  destroyChart("chart-risk");
  if (!labels.length) return;

  charts["chart-risk"] = new Chart(document.getElementById("chart-risk"), {
    type: "polarArea",
    data: {
      labels: labels.map((l) => l.toUpperCase()),
      datasets: [{
        data: values,
        backgroundColor: colors.map((c) => c + "88"),
        borderColor: colors,
        borderWidth: 2,
      }],
    },
    options: {
      responsive: true, maintainAspectRatio: false,
      plugins: {
        legend: { labels: { color: "#8b949e", font: CHART_FONT, boxWidth: 12 } },
      },
      scales: {
        r: { ticks: { color: "#484f58", backdropColor: "transparent" }, grid: { color: "#21262d" } },
      },
    },
  });
}

function renderRecentThreats(threats) {
  const tbody = document.getElementById("recent-threats-body");
  if (!threats.length) {
    tbody.innerHTML = `<tr><td colspan="5" class="loading-row">Угрозы ещё не обнаружены</td></tr>`;
    return;
  }
  tbody.innerHTML = threats.map((t) => `
    <tr>
      <td><strong>${escapeHtml(t.domain)}</strong></td>
      <td>${formatThreatType(t.threat_type)}</td>
      <td><span class="badge badge-${t.risk_level}">${(t.risk_level || "").toUpperCase()}</span></td>
      <td>${t.confidence ? t.confidence.toFixed(1) + "%" : "—"}</td>
      <td>${formatTime(t.timestamp)}</td>
    </tr>
  `).join("");
}

// ── Threats view ──────────────────────────────────────────────────────────────

async function loadThreats() {
  const type = document.getElementById("threats-filter-type").value;
  const risk = document.getElementById("threats-filter-risk").value;
  let url = `${API_BASE}/threats?limit=200`;
  if (type) url += `&threat_type=${type}`;
  if (risk) url += `&risk_level=${risk}`;

  try {
    const resp = await fetch(url, { signal: AbortSignal.timeout(8000) });
    if (!resp.ok) throw new Error("API error");
    const threats = await resp.json();
    renderThreatsTable(threats);
  } catch (err) {
    document.getElementById("threats-body").innerHTML =
      `<tr><td colspan="6" class="loading-row">Ошибка загрузки — запущен ли сервер?</td></tr>`;
  }
}

function renderThreatsTable(threats) {
  const tbody = document.getElementById("threats-body");
  if (!threats.length) {
    tbody.innerHTML = `<tr><td colspan="6" class="loading-row">Угрозы по фильтру не найдены</td></tr>`;
    return;
  }
  tbody.innerHTML = threats.map((t, i) => `
    <tr>
      <td>${i + 1}</td>
      <td><strong>${escapeHtml(t.domain)}</strong></td>
      <td>${formatThreatType(t.threat_type)}</td>
      <td><span class="badge badge-${t.risk_level}">${(t.risk_level || "").toUpperCase()}</span></td>
      <td>${t.confidence ? t.confidence.toFixed(1) + "%" : "—"}</td>
      <td>${formatTime(t.timestamp)}</td>
    </tr>
  `).join("");
}

// ── History view ──────────────────────────────────────────────────────────────

async function loadHistory() {
  const search = document.getElementById("history-search").value.trim().toLowerCase();
  const threatsOnly = document.getElementById("history-threats-only").checked;
  const offset = historyPage * PAGE_SIZE;
  let url = `${API_BASE}/history?limit=${PAGE_SIZE}&offset=${offset}`;
  if (threatsOnly) url += "&threat_only=true";

  try {
    const resp = await fetch(url, { signal: AbortSignal.timeout(8000) });
    if (!resp.ok) throw new Error("API error");
    let records = await resp.json();
    if (search) {
      records = records.filter((r) => r.url.toLowerCase().includes(search) || r.domain.toLowerCase().includes(search));
    }
    renderHistoryTable(records);
    renderPagination(records.length);
  } catch (err) {
    document.getElementById("history-body").innerHTML =
      `<tr><td colspan="8" class="loading-row">Ошибка загрузки</td></tr>`;
  }
}

function renderHistoryTable(records) {
  const tbody = document.getElementById("history-body");
  if (!records.length) {
    tbody.innerHTML = `<tr><td colspan="8" class="loading-row">Записи не найдены</td></tr>`;
    return;
  }
  tbody.innerHTML = records.map((r, i) => `
    <tr>
      <td>${historyPage * PAGE_SIZE + i + 1}</td>
      <td class="url-cell" title="${escapeHtml(r.url)}">${escapeHtml(r.url)}</td>
      <td>${escapeHtml(r.domain)}</td>
      <td><span class="badge ${r.is_safe ? "badge-safe" : "badge-" + (r.risk_level || "high")}">${r.is_safe ? "БЕЗОПАСНО" : "УГРОЗА"}</span></td>
      <td>${r.threat_type ? formatThreatType(r.threat_type) : "—"}</td>
      <td>${r.confidence ? r.confidence.toFixed(1) + "%" : "—"}</td>
      <td>${r.scan_duration_ms ? r.scan_duration_ms.toFixed(0) + "ms" : "—"}</td>
      <td>${formatTime(r.timestamp)}</td>
    </tr>
  `).join("");
}

function renderPagination(count) {
  const pg = document.getElementById("history-pagination");
  const btns = [];
  if (historyPage > 0) {
    btns.push(`<button class="page-btn" onclick="changePage(-1)">&#8592; Назад</button>`);
  }
  if (count === PAGE_SIZE) {
    btns.push(`<button class="page-btn" onclick="changePage(1)">Вперёд &#8594;</button>`);
  }
  pg.innerHTML = btns.join("");
}

function changePage(delta) {
  historyPage = Math.max(0, historyPage + delta);
  loadHistory();
}

// ── Analytics view ────────────────────────────────────────────────────────────

function renderAnalyticsCharts() {
  if (!analyticsData) return;

  // Trend chart
  const daily = analyticsData.daily_scans || [];
  const labels = daily.map((d) => d.date.slice(5));

  destroyChart("chart-trend");
  charts["chart-trend"] = new Chart(document.getElementById("chart-trend"), {
    type: "line",
    data: {
      labels,
      datasets: [{
        label: "Угрозы",
        data: daily.map((d) => d.threats),
        borderColor: "#f85149",
        backgroundColor: "rgba(248,81,73,0.12)",
        tension: 0.4,
        fill: true,
        pointRadius: 3,
        pointBackgroundColor: "#f85149",
      }],
    },
    options: { responsive: true, maintainAspectRatio: false, ...CHART_DEFAULTS },
  });

  // Categories bar chart
  const dist = analyticsData.threat_distribution || {};
  const catLabels = Object.keys(dist).map(formatThreatType);
  const catValues = Object.values(dist);
  const catColors = Object.keys(dist).map((k) => THREAT_COLORS[k] || "#8b949e");

  destroyChart("chart-categories");
  if (catLabels.length) {
    charts["chart-categories"] = new Chart(document.getElementById("chart-categories"), {
      type: "bar",
      data: {
        labels: catLabels,
        datasets: [{
          label: "Количество",
          data: catValues,
          backgroundColor: catColors.map((c) => c + "99"),
          borderColor: catColors,
          borderWidth: 1,
          borderRadius: 4,
        }],
      },
      options: {
        responsive: true, maintainAspectRatio: false, ...CHART_DEFAULTS,
        plugins: { legend: { display: false } },
        indexAxis: "y",
      },
    });
  }

  // Scans vs threats stacked
  destroyChart("chart-ratio");
  charts["chart-ratio"] = new Chart(document.getElementById("chart-ratio"), {
    type: "bar",
    data: {
      labels,
      datasets: [
        { label: "Безопасные",   data: daily.map((d) => d.scans - d.threats), backgroundColor: "rgba(63,185,80,0.4)",  stack: "s" },
        { label: "Угрозы",       data: daily.map((d) => d.threats),           backgroundColor: "rgba(248,81,73,0.55)", stack: "s" },
      ],
    },
    options: {
      responsive: true, maintainAspectRatio: false, ...CHART_DEFAULTS,
      scales: {
        ...CHART_DEFAULTS.scales,
        x: { ...CHART_DEFAULTS.scales.x, stacked: true },
        y: { ...CHART_DEFAULTS.scales.y, stacked: true },
      },
    },
  });

  // Top threat domains
  const topDomains = (analyticsData.top_threats || []).slice(0, 8);
  destroyChart("chart-domains");
  if (topDomains.length) {
    charts["chart-domains"] = new Chart(document.getElementById("chart-domains"), {
      type: "bar",
      data: {
        labels: topDomains.map((t) => t.domain),
        datasets: [{
          label: "Угрозы",
          data: topDomains.map((t) => t.count),
          backgroundColor: "rgba(248,81,73,0.45)",
          borderColor: "#f85149",
          borderWidth: 1,
          borderRadius: 4,
        }],
      },
      options: {
        responsive: true, maintainAspectRatio: false, ...CHART_DEFAULTS,
        plugins: { legend: { display: false } },
        indexAxis: "y",
      },
    });
  }
}

// ── Export ────────────────────────────────────────────────────────────────────

async function exportData() {
  try {
    const resp = await fetch(`${API_BASE}/history?limit=1000`, { signal: AbortSignal.timeout(12000) });
    const records = await resp.json();
    const csv = ["ID,URL,Domain,Safe,ThreatType,RiskLevel,Confidence,ScanDuration,Timestamp"]
      .concat(records.map((r) => [r.id, `"${r.url}"`, r.domain, r.is_safe, r.threat_type, r.risk_level, r.confidence, r.scan_duration_ms, r.timestamp].join(",")))
      .join("\n");
    download("cybershield-export.csv", csv);
  } catch (err) {
    alert("Ошибка экспорта: " + err.message);
  }
}

function download(filename, content) {
  const blob = new Blob([content], { type: "text/csv" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url; a.download = filename; a.click();
  URL.revokeObjectURL(url);
}

// ── Helpers ───────────────────────────────────────────────────────────────────

function destroyChart(id) {
  if (charts[id]) { charts[id].destroy(); delete charts[id]; }
}

function animateCounter(id, endValue, formatter, duration = 900) {
  const el = document.getElementById(id);
  if (!el || isNaN(endValue)) return;
  const start = performance.now();
  (function tick(now) {
    const p = Math.min((now - start) / duration, 1);
    const ease = 1 - Math.pow(1 - p, 3);
    el.textContent = formatter(endValue * ease);
    if (p < 1) requestAnimationFrame(tick);
    else el.textContent = formatter(endValue);
  })(start);
}

function formatThreatType(t) {
  const map = {
    phishing: "Фишинг", fake_login: "Фейковый вход", fake_banking: "Фейковый банк",
    crypto_scam: "Крипто-мошенничество", fake_payment: "Фейковый платёж", malware: "Вредоносное ПО",
    scam: "Мошенничество", suspicious_redirect: "Перенаправление", suspicious: "Подозрительно", safe: "Безопасно",
  };
  return map[t] || t || "—";
}

function formatTime(ts) {
  if (!ts) return "—";
  try {
    const d = new Date(ts);
    return d.toLocaleDateString() + " " + d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
  } catch (_) { return ts; }
}

function formatNum(n) {
  if (n >= 1000000) return (n / 1000000).toFixed(1) + "M";
  if (n >= 1000) return (n / 1000).toFixed(1) + "K";
  return String(Math.round(n));
}

function setText(id, val) {
  const el = document.getElementById(id);
  if (el) el.textContent = val;
}

function escapeHtml(s) {
  return String(s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}

function showOfflineState() {
  setText("v-total", "—");
  setText("v-threats", "—");
  setText("v-safe", "—");
  setText("v-rate", "—");
}

// Expose for inline onclick
window.changePage = changePage;
