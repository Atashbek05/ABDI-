// =============================================
// AI Phishing Detector — Content Script v3
// DOM security analysis + full-page blocking overlay
// =============================================

const OVERLAY_ID = "phishing-detector-overlay";

// ── DOM Security Analysis ─────────────────────────────────────────────────────

function analyzePageSecurity() {
  const signals = {
    has_password_field:     false,
    insecure_form_action:   false,
    has_hidden_iframes:     false,
    external_form_action:   false,
    suspicious_js_patterns: false,
    domain_mismatch:        false,
  };

  try {
    const currentDomain = location.hostname.toLowerCase().replace(/^www\./, "");

    // Password fields
    signals.has_password_field = document.querySelectorAll('input[type="password"]').length > 0;

    // Form analysis
    for (const form of document.querySelectorAll("form")) {
      const action = form.getAttribute("action");
      if (!action || action.startsWith("#") || action === "") continue;

      try {
        const actionUrl  = new URL(action, location.href);
        const actionHost = actionUrl.hostname.toLowerCase().replace(/^www\./, "");

        if (actionHost && actionHost !== currentDomain && !actionHost.endsWith(`.${currentDomain}`)) {
          signals.external_form_action = true;
        }
        if (actionUrl.protocol === "http:" && signals.has_password_field) {
          signals.insecure_form_action = true;
        }
      } catch { /* relative URL — skip */ }
    }

    // Hidden iframes
    for (const iframe of document.querySelectorAll("iframe")) {
      const s = getComputedStyle(iframe);
      if (s.display === "none" || s.visibility === "hidden" ||
          parseFloat(s.width) < 2 || parseFloat(s.height) < 2 ||
          iframe.hasAttribute("hidden")) {
        signals.has_hidden_iframes = true;
        break;
      }
    }

    // Obfuscated inline scripts
    const OBF_RE = /eval\s*\(|document\.write\s*\(|unescape\s*\(|String\.fromCharCode|atob\s*\(|\\x[0-9a-f]{2}/i;
    for (const script of document.querySelectorAll("script:not([src])")) {
      if (OBF_RE.test(script.textContent)) {
        signals.suspicious_js_patterns = true;
        break;
      }
    }

    // Brand/domain mismatch
    const title    = document.title.toLowerCase();
    const metaDesc = (document.querySelector('meta[name="description"]')?.content ?? "").toLowerCase();
    const BRANDS   = ["paypal", "apple", "microsoft", "google", "facebook", "amazon", "netflix",
                      "instagram", "linkedin", "binance", "coinbase", "chase", "wellsfargo"];
    for (const brand of BRANDS) {
      if ((title.includes(brand) || metaDesc.includes(brand)) && !currentDomain.includes(brand)) {
        signals.domain_mismatch = true;
        break;
      }
    }
  } catch (e) {
    console.warn("[PhishingDetector] DOM analysis error:", e);
  }

  return signals;
}

function sendSecuritySignals() {
  try {
    const signals    = analyzePageSecurity();
    const hasSignals = Object.values(signals).some(Boolean);
    if (hasSignals) {
      chrome.runtime.sendMessage({ type: "PAGE_SECURITY_SIGNALS", signals });
    }
  } catch { /* extension context unavailable */ }
}

if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", sendSecuritySignals);
} else {
  sendSecuritySignals();
}

// ── Helper functions ──────────────────────────────────────────────────────────

function riskLevelClass(level) {
  if (level === "HIGH" || level === "CRITICAL") return "danger";
  if (level === "MEDIUM" || level === "SUSPICIOUS") return "warn";
  return "safe";
}

function escapeHtml(str) {
  return String(str)
    .replace(/&/g, "&amp;").replace(/</g, "&lt;")
    .replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}

// ── Overlay builder ───────────────────────────────────────────────────────────

function buildOverlay(data, blocking) {
  const confidence    = Math.round(data.confidence ?? 0);
  const riskLevel     = (data.risk_level ?? "HIGH").toUpperCase();
  const prediction    = (data.prediction ?? "phishing").toUpperCase();
  const reasons       = Array.isArray(data.reasons) ? data.reasons : [];
  const isBlacklisted = data.source === "blacklist";
  const isBlocking    = blocking || isBlacklisted;
  const threatLevel   = confidence >= 80 ? "CRITICAL" : riskLevel;
  const sourceLabel   = isBlacklisted ? "BLACKLIST" : data.source === "whitelist" ? "WHITELIST" : "AI SCAN";
  const threatId      = `THR-${Date.now().toString(36).toUpperCase().slice(-6)}`;

  const overlay = document.createElement("div");
  overlay.id = OVERLAY_ID;
  overlay.setAttribute("role", "alertdialog");
  overlay.setAttribute("aria-modal", "true");
  overlay.setAttribute("aria-label", "Phishing Warning");
  overlay.dataset.blocking = isBlocking ? "true" : "false";

  overlay.innerHTML = `
    <div class="pd-backdrop"></div>
    <div class="pd-panel pd-panel--${isBlocking ? "blocked" : "warning"}">
      <div class="pd-scanner-line"></div>
      <div class="pd-glitch-bar"></div>

      <div class="pd-header-strip">
        <span class="pd-source-badge pd-source-${isBlacklisted ? "bl" : "ai"}">${sourceLabel}</span>
        <span class="pd-threat-id">${threatId}</span>
        <span class="pd-live-dot"></span>
      </div>

      <div class="pd-icon-wrap">
        <div class="pd-icon-ring"></div>
        <div class="pd-icon pd-icon--pulse">${isBlocking ? "🚫" : "⚠"}</div>
      </div>

      <h1 class="pd-title pd-title--${isBlocking ? "blocked" : "warning"}">
        ${isBlocking ? "ACCESS BLOCKED" : "SECURITY ALERT"}
      </h1>
      <p class="pd-subtitle">
        ${isBlacklisted ? "Known Phishing Domain — Blacklist Match" : "AI Phishing Detection System"}
      </p>

      <div class="pd-alert-box pd-alert-box--${isBlocking ? "critical" : "danger"}">
        <span class="pd-alert-icon">${isBlocking ? "⛔" : "⚠"}</span>
        <p class="pd-alert-text">
          ${isBlocking ? "THIS SITE IS ON THE PHISHING BLACKLIST" : "THREAT IDENTIFIED — DO NOT PROCEED"}
        </p>
      </div>

      <div class="pd-stats">
        <div class="pd-stat">
          <span class="pd-stat-label">VERDICT</span>
          <span class="pd-stat-value pd-danger">${prediction}</span>
        </div>
        <div class="pd-stat">
          <span class="pd-stat-label">CONFIDENCE</span>
          <span class="pd-stat-value pd-${riskLevelClass(riskLevel)}">${confidence}%</span>
        </div>
        <div class="pd-stat">
          <span class="pd-stat-label">THREAT LEVEL</span>
          <span class="pd-stat-value pd-${riskLevelClass(threatLevel)}">${threatLevel}</span>
        </div>
      </div>

      <p class="pd-url-label">⚠ Flagged URL</p>
      <p class="pd-url">${escapeHtml(location.href)}</p>

      ${reasons.length > 0 ? `
      <div class="pd-reasons">
        <p class="pd-reasons-label">🔍 THREAT INDICATORS — ${reasons.length} FOUND</p>
        <ul class="pd-reasons-list">
          ${reasons.slice(0, 6).map((r, i) =>
            `<li class="pd-reason-item" style="--delay:${i * 60}ms">
               <span class="pd-reason-dot"></span>${escapeHtml(r)}
             </li>`
          ).join("")}
          ${reasons.length > 6
            ? `<li class="pd-reason-more">+${reasons.length - 6} more indicators detected</li>`
            : ""}
        </ul>
      </div>
      ` : ""}

      <div class="pd-actions">
        <button class="pd-btn pd-btn-safe" id="pd-go-back">
          ← GO BACK TO SAFETY
        </button>
        ${isBlocking
          ? `<button class="pd-btn pd-btn-forced" id="pd-dismiss-blocked">
               ⚠ I UNDERSTAND THE RISK — PROCEED ANYWAY
             </button>`
          : `<button class="pd-btn pd-btn-proceed" id="pd-proceed">
               PROCEED ANYWAY (UNSAFE)
             </button>
             <button class="pd-btn pd-btn-close" id="pd-dismiss">
               CLOSE WARNING
             </button>`
        }
      </div>

      <p class="pd-footer">
        🛡 AI Phishing Detector &bull; <span id="pd-clock">${new Date().toLocaleTimeString()}</span>
      </p>
    </div>
  `;

  return overlay;
}

// ── Show / hide ───────────────────────────────────────────────────────────────

function showWarning(data, blocking = false) {
  if (document.getElementById(OVERLAY_ID)) return;

  const isBlocking = blocking || data.source === "blacklist";
  const overlay    = buildOverlay(data, isBlocking);
  document.body.appendChild(overlay);

  // Hard-block: prevent page interaction
  if (isBlocking) {
    document.documentElement.style.overflow = "hidden";
    document.body.style.pointerEvents = "none";
    overlay.style.pointerEvents = "all";
  }

  overlay.querySelector("#pd-go-back")?.addEventListener("click", () => {
    if (history.length > 1) history.back();
    else { try { window.close(); } catch { location.href = "about:newtab"; } }
    hideWarning(true);
  });

  overlay.querySelector("#pd-dismiss")?.addEventListener("click", () => hideWarning(false));

  overlay.querySelector("#pd-proceed")?.addEventListener("click", () => {
    const ok = confirm(
      "⚠️ WARNING\n\nThis site has been flagged as a potential phishing attempt.\n\n" +
      "Proceeding may expose your passwords, personal data, or financial information.\n\n" +
      "Are you absolutely sure you want to continue?"
    );
    if (ok) hideWarning(true);
  });

  overlay.querySelector("#pd-dismiss-blocked")?.addEventListener("click", () => {
    const ok = confirm(
      "🚫 CRITICAL RISK\n\nThis domain is on the KNOWN PHISHING BLACKLIST.\n\n" +
      "Entering any information here is extremely dangerous.\n\n" +
      "Are you ABSOLUTELY CERTAIN you want to proceed?"
    );
    if (ok) hideWarning(true);
  });

  trapFocus(overlay);
}

function hideWarning(proceed = false) {
  const overlay = document.getElementById(OVERLAY_ID);
  if (overlay) {
    document.documentElement.style.overflow = "";
    document.body.style.pointerEvents = "";
    overlay.classList.add("pd-fade-out");
    overlay.addEventListener("animationend", () => overlay.remove(), { once: true });
  }
  if (!proceed) {
    chrome.runtime.sendMessage({ type: "OVERLAY_CLOSED" });
  }
}

// ── Focus trap ────────────────────────────────────────────────────────────────

function trapFocus(container) {
  const focusable = container.querySelectorAll("button, a[href], input, [tabindex]");
  if (!focusable.length) return;

  const first = focusable[0];
  const last  = focusable[focusable.length - 1];
  first.focus();

  container.addEventListener("keydown", (e) => {
    if (e.key === "Tab") {
      if (e.shiftKey && document.activeElement === first) { last.focus(); e.preventDefault(); }
      else if (!e.shiftKey && document.activeElement === last) { first.focus(); e.preventDefault(); }
    }
    if (e.key === "Escape" && container.dataset.blocking !== "true") hideWarning(false);
  });
}

// ── Public API ────────────────────────────────────────────────────────────────

window.__phishingShowWarning = showWarning;
window.__phishingHideWarning = () => hideWarning(false);

chrome.runtime.onMessage.addListener((message) => {
  if (message.type === "SHOW_PHISHING_WARNING") showWarning(message.data, message.blocking ?? false);
  if (message.type === "HIDE_PHISHING_WARNING") hideWarning(false);
});
