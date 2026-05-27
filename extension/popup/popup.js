// CyberShield AI — Popup Script v2.1

const API_BASE = "https://abdi-d1ph.onrender.com/api/v1";

const $ = (id) => document.getElementById(id);

const THREAT_DISPLAY = {
  safe: "SAFE",
  phishing: "Phishing",
  fake_login: "Fake Login",
  fake_banking: "Fake Banking",
  crypto_scam: "Crypto Scam",
  fake_payment: "Fake Payment",
  malware: "Malware",
  scam: "Scam",
  suspicious_redirect: "Redirect",
  suspicious: "Suspicious",
};

const STATUS_CONFIG = {
  safe:     { icon: "🛡️", label: "SECURE",         sub: "No threats detected",        cardClass: "safe",     ringClass: "safe" },
  low:      { icon: "⚠️", label: "LOW RISK",        sub: "Minor suspicious indicators", cardClass: "low",      ringClass: "danger" },
  medium:   { icon: "⚠️", label: "MEDIUM RISK",     sub: "Suspicious site detected",   cardClass: "medium",   ringClass: "danger" },
  high:     { icon: "🚨", label: "HIGH RISK",       sub: "Likely malicious site",      cardClass: "high",     ringClass: "danger" },
  critical: { icon: "💀", label: "CRITICAL THREAT", sub: "Dangerous site detected",    cardClass: "critical", ringClass: "danger" },
  scanning: { icon: "🔍", label: "SCANNING",        sub: "Analyzing page...",          cardClass: "",         ringClass: "scanning" },
  unknown:  { icon: "🔒", label: "STANDBY",         sub: "Enable protection to scan",  cardClass: "",         ringClass: "" },
};

let currentTab = null;
let currentResult = null;

// ── Realtime inspection stream state ────────────────────────────────────────
let inspectTimer = null;
let typeTimer = null;
let inspectStartedAt = 0;

const INSPECTION_STAGES = [
  "Initializing scan engine...",
  "Hashing URL signature...",
  "Querying domain reputation...",
  "Inspecting page title & meta tags...",
  "Mapping DOM structure...",
  "Scanning forms & input fields...",
  "Probing hidden password fields...",
  "Detecting iframe injections...",
  "Analyzing CSS hiding tricks...",
  "Examining overlays & modals...",
  "Evaluating submit buttons...",
  "Profiling credential patterns...",
  "Comparing brand impersonation...",
  "Auditing inline scripts...",
  "Computing visual risk score...",
  "Aggregating neural threat layers...",
];

// ── Init ─────────────────────────────────────────────────────────────────────

document.addEventListener("DOMContentLoaded", async () => {
  await loadCurrentTab();
  await loadStats();
  setupListeners();
});

async function loadCurrentTab() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tab) return;
  currentTab = tab;

  const domain = extractDomain(tab.url || "");
  $("status-domain").textContent = domain || "N/A";

  const { protectionEnabled } = await chrome.storage.local.get("protectionEnabled");
  $("protection-toggle").checked = protectionEnabled !== false;

  if (!protectionEnabled) {
    showUnknownState("Protection disabled");
    return;
  }

  chrome.runtime.sendMessage({ type: "GET_TAB_STATE", tabId: tab.id }, (state) => {
    if (chrome.runtime.lastError) {
      loadLastScanFromStorage();
      return;
    }
    if (state?.scanning) {
      showScanningState();
    } else if (state?.result) {
      displayResult(state.result);
    } else {
      loadLastScanFromStorage();
    }
  });
}

async function loadLastScanFromStorage() {
  const { lastScan } = await chrome.storage.local.get("lastScan");
  if (lastScan && currentTab) {
    const tabDomain = extractDomain(currentTab.url || "");
    if (lastScan.domain === tabDomain) {
      displayResult(lastScan);
      return;
    }
  }
  showUnknownState("Not yet scanned");
}

async function loadStats() {
  try {
    const resp = await fetch(`${API_BASE}/stats`, { signal: AbortSignal.timeout(3000) });
    if (resp.ok) {
      const stats = await resp.json();
      $("stat-total").textContent = formatNum(stats.total_scans || 0);
      $("stat-threats").textContent = formatNum(stats.threats_detected || 0);
      $("stat-rate").textContent = (stats.detection_rate || 0).toFixed(1) + "%";
      $("footer-status").innerHTML = `<span class="dot dot-green"></span> Engine Active`;
      return;
    }
  } catch (_) {}

  const data = await chrome.storage.local.get(["totalScans", "totalThreats"]);
  $("stat-total").textContent = formatNum(data.totalScans || 0);
  $("stat-threats").textContent = formatNum(data.totalThreats || 0);
  $("footer-status").innerHTML = `<span class="dot dot-yellow"></span> Offline Mode`;
}

// ── Display ──────────────────────────────────────────────────────────────────

function displayResult(result) {
  stopInspectionAnimation();
  currentResult = result;
  const level = result.risk_level || (result.is_safe ? "safe" : "high");
  const cfg = STATUS_CONFIG[level] || STATUS_CONFIG.unknown;

  // Status card
  const card = $("status-card");
  card.className = `status-card ${cfg.cardClass}`;
  $("scan-anim").className = "scan-anim";
  $("status-icon").textContent = cfg.icon;
  $("status-ring").className = `status-ring ${cfg.ringClass}`;
  $("status-label").textContent = cfg.label;
  $("status-domain").textContent = result.domain || extractDomain(result.url || "");
  const subText = $("status-sub-text");
  if (subText) subText.textContent = cfg.sub;
  else $("status-sub").textContent = cfg.sub;

  // Fake login warning banner
  const fakeLogin = result.fake_login_detected || result.page_analysis?.fake_login_detected;
  $("fake-login-banner").style.display = fakeLogin ? "flex" : "none";

  // Risk meter
  $("risk-section").style.display = "block";
  $("details-grid").style.display = "grid";
  $("actions-section").style.display = "flex";
  setTimeout(() => {
    $("risk-bar-fill").style.width = `${result.risk_score || 0}%`;
  }, 50);
  $("risk-score-num").textContent = Math.round(result.risk_score || 0);

  const badge = $("risk-level-badge");
  badge.textContent = level.toUpperCase();
  badge.className = `risk-level-badge badge-${level}`;

  // Details grid
  $("d-threat-type").textContent = THREAT_DISPLAY[result.threat_type] || result.threat_type || "—";
  $("d-confidence").textContent = result.confidence ? result.confidence.toFixed(1) + "%" : "—";
  $("d-scan-time").textContent = result.scan_duration_ms ? result.scan_duration_ms.toFixed(0) + " ms" : "—";

  const vrs = result.visual_risk_score;
  const vrsDisplay = (vrs != null && vrs > 0) ? Math.round(vrs) + "%" : "N/A";
  const vrsEl = $("d-visual-risk");
  vrsEl.textContent = vrsDisplay;
  if (vrs > 60) vrsEl.style.color = "var(--accent-red)";
  else if (vrs > 30) vrsEl.style.color = "var(--accent-orange)";
  else vrsEl.style.color = "var(--accent-green)";

  // Reasons
  if (!result.is_safe && result.reasons?.length) {
    $("reasons-section").style.display = "block";
    const list = $("reasons-list");
    list.innerHTML = result.reasons
      .slice(0, 5)
      .map((r) => `<li>${escapeHtml(r)}</li>`)
      .join("");
  } else {
    $("reasons-section").style.display = "none";
  }

  // Explanation text (only for threats)
  if (!result.is_safe && result.explanation) {
    $("explanation-section").style.display = "block";
    $("explanation-text").textContent = result.explanation;
  } else {
    $("explanation-section").style.display = "none";
  }

  // AI multi-model panel (renders ensemble + per-model + scores)
  renderAIPanel(result);

  // Page analysis panel
  renderPageAnalysis(result.page_analysis, level);
}

// ── AI multi-model panel ─────────────────────────────────────────────────────
// Visualises the ensemble decision: animated risk meter, per-model breakdown
// (RF / XGBoost / Neural Net / Logistic Regression), and the specialised
// scoring engine output (phishing / malware / impersonation / etc).

const MODEL_DISPLAY = {
  random_forest:       { label: "Random Forest",      icon: "🌲" },
  xgboost:             { label: "XGBoost",            icon: "⚡" },
  neural_network:      { label: "Neural Network",     icon: "🧠" },
  logistic_regression: { label: "Logistic Regression", icon: "📈" },
};

const SCORE_DISPLAY = {
  phishing_probability:      "Phishing",
  malware_probability:       "Malware",
  impersonation_risk:        "Impersonation",
  credential_theft_risk:     "Credential Theft",
  redirect_abuse_risk:       "Redirect Abuse",
  suspicious_behavior_score: "Suspicious Behavior",
};

function renderAIPanel(result) {
  const panel = $("ai-panel");
  if (!panel) return;

  const models = result.models;
  const scores = result.scores;
  const ensemble = result.ensemble;

  // Hide gracefully if the ML engine wasn't engaged (e.g. whitelist shortcut).
  if (!models || Object.keys(models).length === 0) {
    panel.style.display = "none";
    return;
  }
  panel.style.display = "block";

  // Engine status chip
  const status = ensemble?.engine_status || "ml";
  const statusEl = $("ai-engine-status");
  if (statusEl) {
    if (status === "ml") {
      statusEl.textContent = `${Object.keys(models).length} MODELS · LIVE`;
      statusEl.className = "ai-panel-status live";
    } else {
      statusEl.textContent = "ENSEMBLE · STANDBY";
      statusEl.className = "ai-panel-status standby";
    }
  }

  // Animated risk meter — uses ensemble probability, falls back to risk_score
  const meterPct = Math.max(0, Math.min(100,
    ensemble?.probability ?? result.risk_score ?? 0
  ));
  animateAIMeter(meterPct);

  // Per-model breakdown bars
  const modelsEl = $("ai-models");
  if (modelsEl) {
    modelsEl.innerHTML = Object.keys(MODEL_DISPLAY)
      .filter((k) => k in models)
      .map((k) => {
        const v = models[k] || 0;
        const info = MODEL_DISPLAY[k];
        const cls = severityClass(v);
        return `
          <div class="ai-model ${cls}">
            <div class="ai-model-head">
              <span class="ai-model-icon">${info.icon}</span>
              <span class="ai-model-name">${info.label}</span>
              <span class="ai-model-val">${v.toFixed(1)}%</span>
            </div>
            <div class="ai-model-bar">
              <div class="ai-model-fill" data-target="${v}"></div>
            </div>
          </div>
        `;
      })
      .join("");

    // Animate bar widths in after insertion
    requestAnimationFrame(() => {
      modelsEl.querySelectorAll(".ai-model-fill").forEach((el) => {
        el.style.width = `${Number(el.dataset.target || 0)}%`;
      });
    });
  }

  // Specialised score grid
  const scoresEl = $("ai-scores");
  if (scoresEl && scores) {
    scoresEl.innerHTML = Object.keys(SCORE_DISPLAY)
      .map((k) => {
        const v = scores[k] || 0;
        const cls = severityClass(v);
        return `
          <div class="ai-score ${cls}">
            <span class="ai-score-name">${SCORE_DISPLAY[k]}</span>
            <span class="ai-score-num">${Math.round(v)}</span>
            <div class="ai-score-bar"><div class="ai-score-bar-fill" data-target="${v}"></div></div>
          </div>
        `;
      })
      .join("");
    requestAnimationFrame(() => {
      scoresEl.querySelectorAll(".ai-score-bar-fill").forEach((el) => {
        el.style.width = `${Number(el.dataset.target || 0)}%`;
      });
    });
  }

  // Decision footer
  $("ai-prediction").textContent = (result.prediction || "—").toUpperCase().replace(/_/g, " ");
  $("ai-prediction").className = "ai-decision-value " + severityClass(meterPct);
  $("ai-confidence").textContent = (ensemble?.confidence ?? result.confidence ?? 0).toFixed(1) + "%";
  $("ai-agreement").textContent = (ensemble?.agreement ?? 0).toFixed(1) + "%";
}

// Animate the SVG risk-meter arc to the given percentage.
let aiMeterAnimHandle = null;
function animateAIMeter(targetPct) {
  const fill = $("ai-meter-fill");
  const num = $("ai-meter-num");
  const caption = $("ai-meter-caption");
  if (!fill || !num) return;

  if (aiMeterAnimHandle) cancelAnimationFrame(aiMeterAnimHandle);

  const arcLen = 157; // length of the half-arc path (≈ π * 50)
  let current = 0;
  const start = performance.now();
  const duration = 1100;

  const step = (t) => {
    const prog = Math.min(1, (t - start) / duration);
    // ease-out cubic
    const eased = 1 - Math.pow(1 - prog, 3);
    current = targetPct * eased;
    fill.setAttribute("stroke-dasharray", `${(current / 100) * arcLen} ${arcLen}`);
    num.textContent = Math.round(current);
    if (prog < 1) aiMeterAnimHandle = requestAnimationFrame(step);
  };
  aiMeterAnimHandle = requestAnimationFrame(step);

  // Caption text adapts to severity for that "realtime scoring" feel
  if (caption) {
    if (targetPct >= 80)      caption.textContent = "CRITICAL THREAT DETECTED";
    else if (targetPct >= 60) caption.textContent = "HIGH RISK · BLOCK RECOMMENDED";
    else if (targetPct >= 40) caption.textContent = "ELEVATED RISK · CAUTION";
    else if (targetPct >= 20) caption.textContent = "LOW RISK · MONITORING";
    else                       caption.textContent = "THREAT PROBABILITY";
  }
}

function severityClass(v) {
  if (v >= 80) return "sev-critical";
  if (v >= 60) return "sev-high";
  if (v >= 40) return "sev-medium";
  if (v >= 20) return "sev-low";
  return "sev-safe";
}

function showScanningState() {
  const card = $("status-card");
  card.className = "status-card scanning-realtime";
  $("scan-anim").className = "scan-anim active";
  $("status-icon").textContent = "🔍";
  $("status-ring").className = "status-ring scanning";
  $("status-label").textContent = "SCANNING";
  $("fake-login-banner").style.display = "none";
  $("risk-section").style.display = "none";
  $("details-grid").style.display = "none";
  $("reasons-section").style.display = "none";
  $("explanation-section").style.display = "none";
  $("page-analysis-panel").style.display = "none";
  $("actions-section").style.display = "none";

  startInspectionAnimation();
}

// ── Realtime inspection animation ───────────────────────────────────────────
// Cycles the inspect-stream console + typewriter sub-text so the user
// gets continuous feedback during the analysis pipeline.

function startInspectionAnimation() {
  stopInspectionAnimation();

  const stream = $("inspect-stream");
  const list = $("inspect-stream-list");
  if (!stream || !list) return;

  stream.style.display = "block";
  list.innerHTML = "";
  inspectStartedAt = Date.now();

  // Deterministic but lightly randomized stage order for variety
  const stages = pickStages(INSPECTION_STAGES, 8);
  let idx = 0;

  const advance = () => {
    // Mark previous active stage as done
    const prevActive = list.querySelector("li.active");
    if (prevActive) prevActive.classList.replace("active", "done");

    if (idx >= stages.length) {
      // Loop: keep streaming until cancelled
      idx = 0;
      list.innerHTML = "";
    }

    const li = document.createElement("li");
    li.textContent = stages[idx++];
    li.classList.add("active");
    list.appendChild(li);

    // Keep only the last 4 visible so it feels like a live console
    while (list.children.length > 4) list.removeChild(list.firstChild);

    runTypewriter(stages[idx - 1]);
  };

  advance();
  // Slightly variable cadence makes the console feel alive without being noisy
  inspectTimer = setInterval(advance, 520);
}

function stopInspectionAnimation() {
  if (inspectTimer) { clearInterval(inspectTimer); inspectTimer = null; }
  if (typeTimer)    { clearInterval(typeTimer);    typeTimer = null; }
  const stream = $("inspect-stream");
  if (stream) stream.style.display = "none";
  const subText = $("status-sub-text");
  if (subText) subText.textContent = "Analyzing page...";
}

// Typewriter effect for the status card's sub-text
function runTypewriter(message) {
  const el = $("status-sub-text");
  if (!el) return;
  if (typeTimer) clearInterval(typeTimer);

  let i = 0;
  el.textContent = "";
  typeTimer = setInterval(() => {
    if (i >= message.length) { clearInterval(typeTimer); typeTimer = null; return; }
    el.textContent += message[i++];
  }, 18);
}

// Shuffle-pick N stages while preserving "Initializing" first for cold feel
function pickStages(arr, n) {
  const head = arr[0];
  const rest = arr.slice(1);
  for (let i = rest.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1));
    [rest[i], rest[j]] = [rest[j], rest[i]];
  }
  return [head, ...rest.slice(0, Math.max(1, n - 1))];
}

function showUnknownState(message) {
  stopInspectionAnimation();
  $("status-card").className = "status-card";
  $("scan-anim").className = "scan-anim";
  $("status-icon").textContent = "🔒";
  $("status-ring").className = "status-ring";
  $("status-label").textContent = "STANDBY";
  const subText = $("status-sub-text");
  if (subText) subText.textContent = message;
  else $("status-sub").textContent = message;
  $("fake-login-banner").style.display = "none";
  $("risk-section").style.display = "none";
  $("details-grid").style.display = "none";
  $("reasons-section").style.display = "none";
  $("explanation-section").style.display = "none";
  $("page-analysis-panel").style.display = "none";
  $("actions-section").style.display = "flex";
}

// ── Page Analysis Panel ──────────────────────────────────────────────────────

function renderPageAnalysis(pa, riskLevel) {
  if (!pa) {
    $("page-analysis-panel").style.display = "none";
    return;
  }

  const hasAnyData = (
    pa.login_risk > 0 ||
    pa.impersonation_risk > 0 ||
    pa.credential_theft_probability > 0 ||
    pa.hidden_iframes > 0 ||
    pa.hidden_elements_found > 0 ||
    pa.suspicious_overlays > 0 ||
    pa.css_tricks_detected ||
    pa.credential_harvesting_patterns?.length > 0 ||
    pa.impersonation_signals?.length > 0
  );

  if (!hasAnyData) {
    $("page-analysis-panel").style.display = "none";
    return;
  }

  $("page-analysis-panel").style.display = "block";

  // Build header badges
  const badgesEl = $("pa-badges");
  badgesEl.innerHTML = "";
  if (pa.fake_login_detected) badgesEl.innerHTML += `<span class="pa-badge warn">FAKE LOGIN</span>`;
  if (pa.cloned_page_detected) badgesEl.innerHTML += `<span class="pa-badge warn">CLONED PAGE</span>`;
  if (pa.hidden_iframes > 0) badgesEl.innerHTML += `<span class="pa-badge warn">HIDDEN IFRAME</span>`;
  if (pa.css_tricks_detected) badgesEl.innerHTML += `<span class="pa-badge info">CSS TRICKS</span>`;

  // Visual risk score bars (animate after reveal)
  renderScoreBar("pa-login-bar", "pa-login-val", pa.login_risk);
  renderScoreBar("pa-imp-bar", "pa-imp-val", pa.impersonation_risk);
  renderScoreBar("pa-cred-bar", "pa-cred-val", pa.credential_theft_probability);

  // Structural indicators grid
  const indicators = buildStructuralIndicators(pa);
  const indEl = $("pa-indicators");
  indEl.innerHTML = indicators
    .map(({ icon, label, cls }) => `<div class="pa-indicator ${cls}">${icon} ${escapeHtml(label)}</div>`)
    .join("");

  // Credential harvesting patterns
  if (pa.credential_harvesting_patterns?.length > 0) {
    $("pa-patterns").style.display = "block";
    $("pa-patterns-list").innerHTML = pa.credential_harvesting_patterns
      .slice(0, 4)
      .map((p) => `<li>${escapeHtml(p)}</li>`)
      .join("");
  } else {
    $("pa-patterns").style.display = "none";
  }

  // Impersonation signals
  if (pa.impersonation_signals?.length > 0) {
    $("pa-impers").style.display = "block";
    $("pa-impers-list").innerHTML = pa.impersonation_signals
      .slice(0, 4)
      .map((s) => `<li>${escapeHtml(s)}</li>`)
      .join("");
  } else {
    $("pa-impers").style.display = "none";
  }

  // Auto-expand panel for high/critical risk levels
  if (riskLevel === "high" || riskLevel === "critical") {
    openPageAnalysisPanel();
  }
}

function renderScoreBar(barId, valId, score) {
  const bar = $(barId);
  const val = $(valId);
  if (!bar || !val) return;
  const pct = Math.round(score || 0);
  val.textContent = pct + "%";

  // Color based on score
  let color = "rgba(0,255,136,0.7)";
  if (pct > 70) color = "var(--accent-critical)";
  else if (pct > 50) color = "var(--accent-red)";
  else if (pct > 25) color = "var(--accent-orange)";
  else if (pct > 10) color = "var(--accent-yellow)";
  bar.style.background = `linear-gradient(90deg, ${color}88, ${color})`;
  val.style.color = pct > 25 ? "var(--accent-red)" : "var(--accent-green)";

  setTimeout(() => {
    bar.style.width = `${pct}%`;
  }, 80);
}

function buildStructuralIndicators(pa) {
  const items = [];

  if (pa.hidden_iframes > 0) {
    items.push({ icon: "🖼", label: `${pa.hidden_iframes} hidden iframe`, cls: "threat" });
  }
  if (pa.hidden_elements_found > 0) {
    items.push({ icon: "👁", label: `${pa.hidden_elements_found} hidden el.`, cls: "threat" });
  }
  if (pa.suspicious_overlays > 0) {
    items.push({ icon: "📄", label: `${pa.suspicious_overlays} overlay`, cls: "warn" });
  }
  if (pa.css_tricks_detected) {
    items.push({ icon: "🎨", label: "CSS tricks", cls: "warn" });
  }
  if (pa.iframe_count > 3) {
    items.push({ icon: "🖼", label: `${pa.iframe_count} iframes`, cls: "warn" });
  }
  if (pa.fake_login_detected) {
    items.push({ icon: "🔑", label: "Fake login", cls: "threat" });
  }
  if (pa.cloned_page_detected) {
    items.push({ icon: "📋", label: "Cloned page", cls: "threat" });
  }
  if (pa.suspicious_buttons?.length > 0) {
    items.push({ icon: "🔘", label: `${pa.suspicious_buttons.length} sus. button`, cls: "warn" });
  }

  if (items.length === 0) {
    items.push({ icon: "✓", label: "DOM looks clean", cls: "ok" });
  }

  return items;
}

function openPageAnalysisPanel() {
  const body = $("pa-body");
  const chevron = $("pa-chevron");
  const header = $("pa-toggle");
  if (body && body.style.display === "none") {
    body.style.display = "block";
    chevron?.classList.add("open");
    header?.classList.add("open");
    header?.setAttribute("aria-expanded", "true");
  }
}

// ── Toggle page analysis panel ────────────────────────────────────────────────

function setupPageAnalysisToggle() {
  const toggle = $("pa-toggle");
  if (!toggle) return;
  toggle.addEventListener("click", () => {
    const body = $("pa-body");
    const chevron = $("pa-chevron");
    const open = body.style.display !== "none";
    body.style.display = open ? "none" : "block";
    chevron?.classList.toggle("open", !open);
    toggle.classList.toggle("open", !open);
    toggle.setAttribute("aria-expanded", String(!open));

    // Trigger bar animations on first open
    if (!open && currentResult?.page_analysis) {
      const pa = currentResult.page_analysis;
      setTimeout(() => {
        renderScoreBar("pa-login-bar", "pa-login-val", pa.login_risk);
        renderScoreBar("pa-imp-bar", "pa-imp-val", pa.impersonation_risk);
        renderScoreBar("pa-cred-bar", "pa-cred-val", pa.credential_theft_probability);
      }, 50);
    }
  });
  toggle.addEventListener("keydown", (e) => {
    if (e.key === "Enter" || e.key === " ") { e.preventDefault(); toggle.click(); }
  });
}

// ── Event listeners ─────────────────────────────────────────────────────────

function setupListeners() {
  setupPageAnalysisToggle();

  // Protection toggle
  $("protection-toggle").addEventListener("change", async (e) => {
    await chrome.storage.local.set({ protectionEnabled: e.target.checked });
    if (!e.target.checked) {
      showUnknownState("Protection disabled");
    } else {
      showScanningState();
      if (currentTab) {
        chrome.runtime.sendMessage({ type: "RESCAN_TAB", tabId: currentTab.id });
      }
    }
  });

  // Rescan
  $("rescan-btn").addEventListener("click", () => {
    if (currentTab) {
      showScanningState();
      chrome.runtime.sendMessage({ type: "RESCAN_TAB", tabId: currentTab.id }, () => {
        setTimeout(() => loadCurrentTab(), 1500);
      });
    }
  });

  // Whitelist
  $("whitelist-btn").addEventListener("click", async () => {
    if (!currentTab?.url) return;
    const domain = extractDomain(currentTab.url);
    try {
      const resp = await fetch(`${API_BASE}/whitelist`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ domain, reason: "User trusted" }),
      });
      if (resp.ok || resp.status === 409) {
        $("whitelist-btn").textContent = "✅ Trusted!";
        $("whitelist-btn").disabled = true;
        setTimeout(() => {
          $("whitelist-btn").textContent = "✅ Trust Site";
          $("whitelist-btn").disabled = false;
        }, 2000);
      }
    } catch (_) {}
  });

  // Report
  $("report-btn").addEventListener("click", () => {
    if (currentResult) {
      const pa = currentResult.page_analysis;
      let text = `URL: ${currentResult.url}\nThreat: ${currentResult.threat_type}\nConfidence: ${currentResult.confidence}%`;
      if (currentResult.fake_login_detected) text += "\n⚠ FAKE LOGIN DETECTED";
      if (pa?.cloned_page_detected) text += "\n⚠ CLONED PAGE DETECTED";
      if (pa?.credential_harvesting_patterns?.length) {
        text += `\nCredential patterns: ${pa.credential_harvesting_patterns.join(", ")}`;
      }
      navigator.clipboard?.writeText(text);
      $("report-btn").textContent = "📋 Copied!";
      setTimeout(() => { $("report-btn").textContent = "🚩 Report"; }, 2000);
    }
  });

  // Settings
  $("settings-btn").addEventListener("click", () => {
    chrome.runtime.openOptionsPage();
  });

  // Dashboard
  $("dashboard-btn").addEventListener("click", () => {
    chrome.tabs.create({ url: chrome.runtime.getURL("dashboard/dashboard.html") });
  });
}

// ── Utilities ────────────────────────────────────────────────────────────────

function extractDomain(url) {
  try {
    return new URL(url).hostname.replace(/^www\./, "");
  } catch (_) {
    return url;
  }
}

function formatNum(n) {
  if (n >= 1000000) return (n / 1000000).toFixed(1) + "M";
  if (n >= 1000) return (n / 1000).toFixed(1) + "K";
  return String(n);
}

function escapeHtml(s) {
  return String(s)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;");
}
