// CyberShield AI — Content Script v2.1
// Collects DOM data, runs visual analysis, and handles threat overlay display

(function () {
  "use strict";

  const MAX_HTML_LENGTH = 10000;
  const MAX_SCRIPT_LENGTH = 2000;
  const MAX_TEXT_LENGTH = 3000;

  // ── DOM Data Collection ────────────────────────────────────────────────────

  function collectDomData() {
    return {
      pageTitle: document.title || "",
      pageText: extractText(),
      htmlSnippet: extractHtmlSnippet(),
      forms: extractForms(),
      scripts: extractScripts(),
      redirects: extractRedirects(),
      // Enhanced visual analysis data
      domData: {
        hiddenElements: extractHiddenElements(),
        iframes: extractIframes(),
        overlays: extractOverlays(),
        suspiciousButtons: extractSuspiciousButtons(),
        inputFields: extractInputFields(),
        cssTricks: extractCssTricks(),
        externalLinks: extractExternalLinks(),
      },
    };
  }

  function extractText() {
    const body = document.body;
    if (!body) return "";
    const text = body.innerText || body.textContent || "";
    return text.slice(0, MAX_TEXT_LENGTH);
  }

  function extractHtmlSnippet() {
    const html = document.documentElement.outerHTML || "";
    return html.slice(0, MAX_HTML_LENGTH);
  }

  function extractForms() {
    const forms = [];
    document.querySelectorAll("form").forEach((form) => {
      const inputs = [];
      form.querySelectorAll("input, select, textarea").forEach((input) => {
        inputs.push({
          type: input.type || "text",
          name: input.name || "",
          id: input.id || "",
          placeholder: input.placeholder || "",
          value: input.type === "hidden" ? (input.value || "").slice(0, 50) : "",
        });
      });

      const style = window.getComputedStyle(form);
      const rect = form.getBoundingClientRect();
      forms.push({
        action: form.action || "",
        method: form.method || "get",
        inputs,
        hidden:
          style.display === "none" ||
          style.visibility === "hidden" ||
          style.opacity === "0" ||
          (rect.width === 0 && rect.height === 0),
      });
    });
    return forms.slice(0, 20);
  }

  function extractScripts() {
    const scripts = [];
    document.querySelectorAll("script:not([src])").forEach((s) => {
      const content = (s.textContent || "").slice(0, MAX_SCRIPT_LENGTH);
      if (content.length > 50) scripts.push(content);
    });
    return scripts.slice(0, 15);
  }

  function extractRedirects() {
    const metas = [];
    document.querySelectorAll('meta[http-equiv="refresh"]').forEach((m) => {
      metas.push(m.getAttribute("content") || "");
    });
    return metas;
  }

  // ── Enhanced: Hidden Elements ──────────────────────────────────────────────

  function extractHiddenElements() {
    let passwordFields = 0;
    let hiddenForms = 0;
    let hiddenInputs = 0;
    let count = 0;

    // Hidden password inputs (type=hidden named "password" etc.)
    document.querySelectorAll('input[type="hidden"]').forEach((el) => {
      const name = (el.name || el.id || "").toLowerCase();
      if (/pass|pwd|secret|token|credential/.test(name)) {
        passwordFields++;
        count++;
      }
      hiddenInputs++;
    });

    // Visually hidden inputs with password type
    document.querySelectorAll('input[type="password"]').forEach((el) => {
      const style = window.getComputedStyle(el);
      if (
        style.display === "none" ||
        style.visibility === "hidden" ||
        style.opacity === "0"
      ) {
        passwordFields++;
        count++;
      }
    });

    // Hidden forms
    document.querySelectorAll("form").forEach((form) => {
      const style = window.getComputedStyle(form);
      if (
        style.display === "none" ||
        style.visibility === "hidden" ||
        style.opacity === "0"
      ) {
        hiddenForms++;
        count++;
      }
    });

    return { count, passwordFields, forms: hiddenForms, inputs: hiddenInputs };
  }

  // ── Enhanced: Iframe Analysis ─────────────────────────────────────────────

  function extractIframes() {
    const iframeEls = document.querySelectorAll("iframe");
    let hidden = 0;
    let crossOrigin = 0;
    const currentHost = location.hostname;

    iframeEls.forEach((iframe) => {
      const style = window.getComputedStyle(iframe);
      const rect = iframe.getBoundingClientRect();
      const isHidden =
        style.display === "none" ||
        style.visibility === "hidden" ||
        style.opacity === "0" ||
        rect.width < 2 ||
        rect.height < 2 ||
        parseInt(iframe.width) === 0 ||
        parseInt(iframe.height) === 0;

      if (isHidden) hidden++;

      try {
        const src = iframe.src || "";
        if (src && !src.startsWith("javascript:") && !src.startsWith("about:")) {
          const iframeHost = new URL(src).hostname;
          if (iframeHost && iframeHost !== currentHost) crossOrigin++;
        }
      } catch (_) {}
    });

    return {
      count: iframeEls.length,
      hidden,
      crossOrigin,
    };
  }

  // ── Enhanced: Overlay / Modal Detection ──────────────────────────────────

  function extractOverlays() {
    let fullscreen = 0;
    const vw = window.innerWidth;
    const vh = window.innerHeight;

    document.querySelectorAll("div, section, aside").forEach((el) => {
      const style = window.getComputedStyle(el);
      const pos = style.position;
      if (pos !== "fixed" && pos !== "absolute") return;

      const rect = el.getBoundingClientRect();
      // Large overlay covering most of the viewport
      if (
        rect.width >= vw * 0.7 &&
        rect.height >= vh * 0.7 &&
        style.display !== "none" &&
        style.visibility !== "hidden"
      ) {
        const zIndex = parseInt(style.zIndex) || 0;
        if (zIndex > 100) fullscreen++;
      }
    });

    return { fullscreen };
  }

  // ── Enhanced: Suspicious Button Detection ────────────────────────────────

  const SUSPICIOUS_TEXTS = [
    "verify account", "verify identity", "confirm identity", "verify now",
    "update payment", "update card", "update billing",
    "unlock account", "reactivate", "restore access",
    "claim reward", "claim prize", "get reward",
    "login to continue", "sign in to verify", "continue to verify",
    "submit credentials",
  ];

  function extractSuspiciousButtons() {
    const suspicious = [];
    document.querySelectorAll("button, input[type='submit'], a[role='button']").forEach((el) => {
      const text = (el.innerText || el.value || el.textContent || "").toLowerCase().trim();
      if (!text) return;
      for (const sus of SUSPICIOUS_TEXTS) {
        if (text.includes(sus)) {
          suspicious.push(text.slice(0, 80));
          break;
        }
      }
    });
    return suspicious.slice(0, 8);
  }

  // ── Enhanced: All Input Fields ────────────────────────────────────────────

  function extractInputFields() {
    const fields = [];
    document.querySelectorAll("input, select, textarea").forEach((el) => {
      const style = window.getComputedStyle(el);
      fields.push({
        type: el.type || "text",
        name: el.name || "",
        id: el.id || "",
        placeholder: el.placeholder || "",
        hidden:
          el.type === "hidden" ||
          style.display === "none" ||
          style.visibility === "hidden" ||
          style.opacity === "0",
      });
    });
    return fields.slice(0, 50);
  }

  // ── Enhanced: CSS Trick Detection ────────────────────────────────────────

  function extractCssTricks() {
    let offscreenElements = 0;
    let zeroOpacity = 0;
    let negativePosition = 0;

    // Check all elements for suspicious positioning
    const candidates = document.querySelectorAll(
      "input, form, div[style], span[style], a[style]"
    );
    candidates.forEach((el) => {
      const style = window.getComputedStyle(el);
      const rect = el.getBoundingClientRect();

      // Off-screen but not display:none
      if (
        style.display !== "none" &&
        (rect.left < -200 || rect.top < -200 || rect.right > window.innerWidth + 200)
      ) {
        offscreenElements++;
      }

      // Zero opacity but not display:none
      if (
        parseFloat(style.opacity) === 0 &&
        style.display !== "none" &&
        el.tagName === "INPUT"
      ) {
        zeroOpacity++;
      }
    });

    // Check inline styles for hiding tricks
    document.querySelectorAll("[style]").forEach((el) => {
      const inlineStyle = (el.getAttribute("style") || "").toLowerCase();
      if (/left\s*:\s*-\d{3,}px|top\s*:\s*-\d{3,}px/.test(inlineStyle)) {
        negativePosition++;
      }
    });

    const detected = offscreenElements > 0 || zeroOpacity > 0 || negativePosition > 1;
    return { detected, offscreenElements, zeroOpacity, negativePosition };
  }

  // ── Enhanced: External Links ──────────────────────────────────────────────

  function extractExternalLinks() {
    const currentHost = location.hostname;
    let externalCount = 0;
    let suspiciousExternal = 0;

    document.querySelectorAll("a[href]").forEach((a) => {
      try {
        const href = a.href;
        if (!href || href.startsWith("javascript:") || href.startsWith("mailto:")) return;
        const linkHost = new URL(href).hostname;
        if (linkHost && linkHost !== currentHost) {
          externalCount++;
          // Suspicious if links to IP addresses or high-risk TLDs
          if (/^\d+\.\d+\.\d+\.\d+$/.test(linkHost) || /\.(tk|ml|ga|cf|xyz)$/.test(linkHost)) {
            suspiciousExternal++;
          }
        }
      } catch (_) {}
    });

    return { count: externalCount, suspicious: suspiciousExternal };
  }

  // ── Message Listener ───────────────────────────────────────────────────────

  chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
    if (msg.type === "GET_DOM_DATA") {
      try {
        sendResponse(collectDomData());
      } catch (e) {
        sendResponse({ pageTitle: "", pageText: "", htmlSnippet: "", forms: [], scripts: [], redirects: [], domData: {} });
      }
      return true;
    }

    if (msg.type === "SHOW_OVERLAY") {
      showThreatOverlay(msg.result);
      sendResponse({ shown: true });
      return true;
    }

    if (msg.type === "HIDE_OVERLAY") {
      removeThreatOverlay();
      sendResponse({ hidden: true });
      return true;
    }
  });

  // ── Threat Overlay ─────────────────────────────────────────────────────────

  function showThreatOverlay(result) {
    removeThreatOverlay();

    const riskColors = {
      low: "#ffdd00", medium: "#ff9900", high: "#ff4400", critical: "#ff0044",
    };
    const color = riskColors[result.risk_level] || "#ff4400";
    const threatNames = {
      phishing: "PHISHING ATTACK",
      fake_login: "FAKE LOGIN PAGE",
      fake_banking: "FAKE BANKING SITE",
      crypto_scam: "CRYPTOCURRENCY SCAM",
      fake_payment: "FAKE PAYMENT GATEWAY",
      malware: "MALWARE DISTRIBUTION",
      scam: "SCAM WEBSITE",
      suspicious_redirect: "SUSPICIOUS REDIRECT",
      suspicious: "SUSPICIOUS CONTENT",
    };
    const threatName = threatNames[result.threat_type] || "SECURITY THREAT";

    const host = document.createElement("div");
    host.id = "cybershield-host";
    host.style.cssText =
      "position:fixed;top:0;left:0;width:100%;height:100%;z-index:2147483647;pointer-events:all";

    const shadow = host.attachShadow({ mode: "closed" });
    shadow.innerHTML = buildOverlayHTML(result, color, threatName);

    // Button handlers
    shadow.querySelector("#cs-back-btn")?.addEventListener("click", () => {
      history.back();
    });
    shadow.querySelector("#cs-proceed-btn")?.addEventListener("click", () => {
      removeThreatOverlay();
      chrome.runtime.sendMessage({ type: "MARK_BLOCKED", tabId: null });
    });

    document.documentElement.appendChild(host);

    // Animate confidence bar after paint
    setTimeout(() => {
      const bar = shadow.querySelector("#cs-bar-fill");
      if (bar) bar.style.width = `${result.confidence.toFixed(0)}%`;

      // Animate visual risk scores if page_analysis present
      const pa = result.page_analysis;
      if (pa) {
        const loginBar = shadow.querySelector("#cs-login-bar");
        const impBar = shadow.querySelector("#cs-imp-bar");
        const credBar = shadow.querySelector("#cs-cred-bar");
        if (loginBar) loginBar.style.width = `${pa.login_risk}%`;
        if (impBar) impBar.style.width = `${pa.impersonation_risk}%`;
        if (credBar) credBar.style.width = `${pa.credential_theft_probability}%`;
      }
    }, 150);
  }

  function removeThreatOverlay() {
    document.getElementById("cybershield-host")?.remove();
  }

  function buildOverlayHTML(result, color, threatName) {
    const reasons = (result.reasons || []).slice(0, 5);
    const reasonsHtml = reasons.length
      ? `<ul class="cs-reasons">${reasons.map((r) => `<li>${escapeHtml(r)}</li>`).join("")}</ul>`
      : "";

    const pa = result.page_analysis || {};
    const fakeLoginBanner = (result.fake_login_detected || pa.fake_login_detected)
      ? `<div class="fake-login-warn">⚠ FAKE LOGIN PAGE DETECTED — Do not enter your credentials</div>`
      : "";

    const visualScores = (pa && (pa.login_risk > 0 || pa.impersonation_risk > 0 || pa.credential_theft_probability > 0))
      ? `<div class="visual-scores">
           <div class="vs-label">VISUAL THREAT ANALYSIS</div>
           <div class="vs-row">
             <span class="vs-name">Login Risk</span>
             <div class="vs-bar-bg"><div class="vs-bar-fill" id="cs-login-bar" style="--c:${color}"></div></div>
             <span class="vs-val">${Math.round(pa.login_risk || 0)}%</span>
           </div>
           <div class="vs-row">
             <span class="vs-name">Impersonation</span>
             <div class="vs-bar-bg"><div class="vs-bar-fill" id="cs-imp-bar" style="--c:${color}"></div></div>
             <span class="vs-val">${Math.round(pa.impersonation_risk || 0)}%</span>
           </div>
           <div class="vs-row">
             <span class="vs-name">Cred. Theft</span>
             <div class="vs-bar-bg"><div class="vs-bar-fill" id="cs-cred-bar" style="--c:${color}"></div></div>
             <span class="vs-val">${Math.round(pa.credential_theft_probability || 0)}%</span>
           </div>
         </div>`
      : "";

    return `
      <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        :host { all: initial; }
        @keyframes fade-in { from { opacity:0; transform:scale(0.95); } to { opacity:1; transform:scale(1); } }
        @keyframes pulse-glow { 0%,100% { box-shadow:0 0 30px ${color}33; } 50% { box-shadow:0 0 80px ${color}66, 0 0 160px ${color}33; } }
        @keyframes scan-line { 0% { top:-2px; } 100% { top:100%; } }
        @keyframes blink { 0%,100% { opacity:1; } 50% { opacity:0.4; } }
        @keyframes warn-pulse { 0%,100% { background:rgba(255,0,68,0.15); } 50% { background:rgba(255,0,68,0.3); } }
        .overlay {
          position: fixed; inset: 0; background: rgba(0,0,5,0.97);
          display: flex; align-items: center; justify-content: center;
          font-family: 'Courier New', monospace; animation: fade-in 0.35s ease;
          overflow-y: auto; padding: 20px;
        }
        .card {
          background: linear-gradient(145deg, #080810, #0c0c1c);
          border: 2px solid ${color}; border-radius: 18px;
          padding: 36px 36px 28px; max-width: 680px; width: 92%;
          text-align: center; animation: pulse-glow 2.5s ease-in-out infinite;
          position: relative; overflow: hidden;
        }
        .scanline {
          position: absolute; left: 0; right: 0; height: 2px;
          background: linear-gradient(90deg, transparent, ${color}, transparent);
          animation: scan-line 3.5s linear infinite; top: 0;
        }
        .shield-icon { font-size: 64px; margin-bottom: 12px; display: block; }
        .threat-badge {
          display: inline-block; background: ${color}22; border: 1px solid ${color}88;
          color: ${color}; font-size: 10px; letter-spacing: 3px; padding: 5px 14px;
          border-radius: 20px; text-transform: uppercase; margin-bottom: 14px;
          animation: blink 1.5s ease-in-out infinite;
        }
        .title { font-size: 27px; font-weight: 900; color: #ffffff; margin-bottom: 6px; letter-spacing: 0.5px; }
        .domain { font-size: 12px; color: #9999bb; margin-bottom: 18px; word-break: break-all; }
        .fake-login-warn {
          background: rgba(255,0,68,0.15); border: 1px solid rgba(255,0,68,0.5);
          color: #ff4466; font-size: 11px; letter-spacing: 1px; padding: 8px 16px;
          border-radius: 8px; margin-bottom: 16px; animation: warn-pulse 2s ease infinite;
          font-weight: 700;
        }
        .confidence-label {
          display: flex; justify-content: space-between; font-size: 10px;
          letter-spacing: 2px; color: #555577; margin-bottom: 6px;
        }
        .conf-val { color: ${color}; }
        .bar-bg { background: #11111f; border-radius: 6px; height: 8px; overflow: hidden; margin-bottom: 18px; }
        .bar-fill {
          height: 100%; border-radius: 6px; width: 0%;
          background: linear-gradient(90deg, ${color}66, ${color});
          transition: width 1.2s cubic-bezier(0.4, 0, 0.2, 1);
        }
        .visual-scores {
          background: rgba(255,255,255,0.02); border: 1px solid #1a1a3a;
          border-radius: 10px; padding: 12px 16px; margin-bottom: 16px; text-align: left;
        }
        .vs-label { font-size: 8px; letter-spacing: 3px; color: #444466; margin-bottom: 10px; }
        .vs-row { display: flex; align-items: center; gap: 8px; margin-bottom: 7px; }
        .vs-row:last-child { margin-bottom: 0; }
        .vs-name { font-size: 10px; color: #888899; width: 88px; flex-shrink: 0; }
        .vs-bar-bg { flex: 1; background: #0e0e20; border-radius: 4px; height: 5px; overflow: hidden; }
        .vs-bar-fill {
          height: 100%; border-radius: 4px; width: 0%;
          background: linear-gradient(90deg, var(--c, ${color})66, var(--c, ${color}));
          transition: width 1.4s cubic-bezier(0.4, 0, 0.2, 1);
        }
        .vs-val { font-size: 10px; color: ${color}; width: 30px; text-align: right; flex-shrink: 0; }
        .cs-reasons {
          background: rgba(255,255,255,0.03); border: 1px solid #22224a;
          border-radius: 10px; padding: 14px 18px; margin-bottom: 16px;
          text-align: left; max-height: 120px; overflow-y: auto; list-style: none;
        }
        .cs-reasons li {
          font-size: 11px; color: #ccccdd; padding: 3px 0 3px 18px;
          position: relative; border-bottom: 1px solid #1a1a2e;
        }
        .cs-reasons li:last-child { border-bottom: none; }
        .cs-reasons li::before { content: "▸"; position: absolute; left: 0; color: ${color}; }
        .explanation { font-size: 11px; color: #555577; line-height: 1.7; margin-bottom: 20px; }
        .actions { display: flex; gap: 12px; justify-content: center; flex-wrap: wrap; }
        .btn {
          padding: 12px 28px; border-radius: 9px; font-size: 11px; font-weight: 800;
          letter-spacing: 1.5px; cursor: pointer; transition: all 0.2s;
          border: 2px solid; font-family: 'Courier New', monospace; text-transform: uppercase;
        }
        .btn-back { background: ${color}22; border-color: ${color}; color: ${color}; }
        .btn-back:hover { background: ${color}44; transform: translateY(-1px); box-shadow: 0 4px 20px ${color}44; }
        .btn-proceed { background: transparent; border-color: #2a2a4a; color: #44446a; }
        .btn-proceed:hover { background: #111128; color: #666688; }
        .divider { width: 60px; height: 1px; background: ${color}44; margin: 0 auto 16px; }
      </style>
      <div class="overlay">
        <div class="card">
          <div class="scanline"></div>
          <span class="shield-icon">🛡️</span>
          <div class="threat-badge">⚠ ${threatName}</div>
          <div class="title">Threat Detected</div>
          <div class="divider"></div>
          <div class="domain">🌐 ${escapeHtml(result.domain || result.url || "")}</div>
          ${fakeLoginBanner}
          <div class="confidence-label">
            <span>AI RISK SCORE</span>
            <span class="conf-val">${result.confidence.toFixed(1)}% CONFIDENCE</span>
          </div>
          <div class="bar-bg"><div class="bar-fill" id="cs-bar-fill"></div></div>
          ${visualScores}
          ${reasonsHtml}
          <div class="explanation">${escapeHtml(result.explanation || "")}</div>
          <div class="actions">
            <button class="btn btn-back" id="cs-back-btn">← Go Back (Safe)</button>
            <button class="btn btn-proceed" id="cs-proceed-btn">Proceed Anyway</button>
          </div>
        </div>
      </div>
    `;
  }

  function escapeHtml(str) {
    return String(str)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");
  }
})();
