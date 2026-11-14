// CyberShield AI — Content Script (Injected DOM Security Guard & Analyzer Bridge)
// Features: Live URL Badges, Warning Banners, Toxic Text Blur, Password Security & Real-Time Telemetry

(function () {
  // Prevent duplicate execution if content.js is injected both by Chrome and by page scripts
  if (window.__cybershield_content_script_loaded) return;
  window.__cybershield_content_script_loaded = true;

  // Safe environment polyfill for direct testing in browser tabs
  if (typeof window.chrome === "undefined") {
    window.chrome = {};
  }
  if (!window.chrome.storage || !window.chrome.storage.local) {
    window.chrome.storage = {
      local: {
        get: (keys, cb) => {
          if (cb) cb({ autoScan: true, toxicBlur: true, passwordTips: true });
        },
        set: (data, cb) => {
          if (cb) cb();
        }
      }
    };
  }
  if (!window.chrome.runtime) {
    window.chrome.runtime = {
      sendMessage: (msg, cb) => {
        if (msg && msg.action === "RECORD_EXTENSION_INCIDENT" && msg.incident) {
          try {
            if (typeof BroadcastChannel !== "undefined") {
              const bus = new BroadcastChannel("cybershield_realtime_bus");
              bus.postMessage({ type: "EXTENSION_INCIDENT", incident: msg.incident });
            }
          } catch(e) {}
        }
        if (cb) cb({ status: "success" });
      },
      onMessage: {
        addListener: () => {}
      }
    };
  }

  const currentUrl = window.location.href;
  const currentHostname = window.location.hostname || "";

  // Mark extension presence in DOM for web portals like Security Analyzer
  try {
    document.documentElement.setAttribute("data-cybershield-extension-active", "true");
  } catch (e) {}

  if (!currentUrl.startsWith("http://") && !currentUrl.startsWith("https://") && !currentUrl.startsWith("file://")) return;

  // Persist current tab telemetry to storage
  try {
    chrome.storage.local.set({
      lastActiveDomain: currentHostname,
      lastActiveUrl: currentUrl,
      lastActiveTitle: document.title || currentHostname
    });
  } catch (e) {}

  let pageHasThreat = false;
  let pageThreatReason = "";
  let config = { autoScan: true, toxicBlur: true, passwordTips: true, outboundBlocker: true };

  // 1. Always render corner protection badge immediately
  renderPageBadge("SAFE", 0);
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", () => renderPageBadge("SAFE", 0), { once: true });
  }
  window.addEventListener("load", () => {
    if (!document.getElementById("cybershield-corner-badge")) {
      renderPageBadge("SAFE", 0);
    }
  }, { once: true });

  // 2. Initialize configuration from extension storage and run guards
  chrome.storage.local.get(["autoScan", "toxicBlur", "passwordTips", "outboundBlocker", "backendUrl"], (items) => {
    if (items.outboundBlocker !== undefined) config.outboundBlocker = items.outboundBlocker;
    if (items.backendUrl) config.backendUrl = items.backendUrl;
    if (items.autoScan !== undefined) config.autoScan = items.autoScan;
    if (items.toxicBlur !== undefined) config.toxicBlur = items.toxicBlur;
    if (items.passwordTips !== undefined) config.passwordTips = items.passwordTips;

    if (config.autoScan) scanActivePage();
    if (config.toxicBlur) {
      scanPageForToxicContent();
      setTimeout(scanPageForToxicContent, 400);
    }
    if (config.passwordTips) {
      attachPasswordGuards();
      setTimeout(attachPasswordGuards, 400);
    }
    if (config.outboundBlocker !== false) {
      attachOutboundMessageGuard();
    }
  });

  // Attach outbound message guard on document execution
  attachOutboundMessageGuard();

  // Run initial scan synchronously as well
  scanPageForToxicContent();

  // 3. Scan Current Webpage URL and Domain Breach via Background Service Worker
  function scanActivePage() {
    // A. Phishing & Suspicious Domain Scanner
    chrome.runtime.sendMessage({ action: "CHECK_PHISHING", url: currentUrl }, (res) => {
      if (res && res.status === "success") {
        updatePageBadge(res.risk_level, res.risk_score);
        if (res.risk_score >= 45) {
          renderTopWarningBanner(res.risk_level, res.risk_score, res.flags?.[0]);
          chrome.runtime.sendMessage({
            action: "RECORD_EXTENSION_INCIDENT",
            incident: {
              id: "phish_" + Date.now(),
              title: `Phishing Alert: ${res.flags?.[0] || 'High Risk Domain'}`,
              module: "Phishing Detection",
              target: currentHostname || currentUrl,
              date: "Just now",
              severity: res.risk_score >= 70 ? "Critical" : "High",
              status: "Quarantined",
              link: "phishing-detection.html"
            }
          });
        }
      }
    });

    // B. Historical Domain Breach Intelligence Scanner
    if (currentHostname && currentHostname !== "localhost" && currentHostname !== "127.0.0.1" && !currentHostname.includes("cybershield")) {
      chrome.runtime.sendMessage({ action: "CHECK_DOMAIN_LEAK", domain: currentHostname }, (res) => {
        if (res && res.found) {
          renderBreachWarningPopup(res);
          updatePageBadge("HISTORICAL DATA BREACH DETECTED", 85);
          chrome.runtime.sendMessage({
            action: "RECORD_EXTENSION_INCIDENT",
            incident: {
              id: "leak_" + Date.now(),
              title: `Data Breach Detected for ${currentHostname} (${res.breach_count} records)`,
              module: "Security Analyzer",
              target: currentHostname,
              date: "Just now",
              severity: "High",
              status: "Alerted",
              link: `security-analyzer.html?domain=${encodeURIComponent(currentHostname)}&type=domain`
            }
          });
        }
      });
    }
  }

  // In-Page Warning Popup Banner for Breached Websites
  function renderBreachWarningPopup(res) {
    if (document.getElementById("cybershield-breach-banner")) return;

    const banner = document.createElement("div");
    banner.id = "cybershield-breach-banner";
    banner.style.cssText = `
      position: fixed;
      top: 18px;
      right: 18px;
      max-width: 440px;
      background: linear-gradient(135deg, #180b28, #0f172a);
      color: #f1f5f9;
      border: 1px solid #ef4444;
      border-left: 6px solid #ef4444;
      border-radius: 10px;
      padding: 14px 16px;
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      font-size: 11.5px;
      z-index: 2147483647;
      box-shadow: 0 12px 36px rgba(0,0,0,0.7);
      line-height: 1.45;
    `;

    const breachName = res.breaches?.[0]?.name || "Verified Public Incident";
    const breachDate = res.breaches?.[0]?.date ? new Date(res.breaches[0].date).getFullYear() : "Archived";
    const exposedList = (res.breaches?.[0]?.data_exposed || ["Usernames", "Passwords", "Email addresses"]).slice(0, 3).join(", ");
    const rootName = currentHostname.replace(/^www\./, "");
    const bName = rootName.split(".")[0];
    const cleanBrand = bName ? bName.charAt(0).toUpperCase() + bName.slice(1) : currentHostname;
    // Always prefer the cloud Render URL for opening web portal pages (security-analyzer, etc.)
    // Fall back to whatever the user has configured, but never localhost (it may not be running)
    const rawBackend = (config && config.backendUrl) ? config.backendUrl.replace(/\/+$/, "") : "https://cybershield-ai-5bpo.onrender.com";
    const portalBase = (rawBackend.startsWith("http://localhost") || rawBackend.startsWith("http://127.0.0.1"))
      ? "https://cybershield-ai-5bpo.onrender.com"
      : rawBackend;

    banner.innerHTML = `
      <div style="display:flex; justify-content:space-between; align-items:flex-start; margin-bottom:6px;">
        <div style="display:flex; align-items:center; gap:7px;">
          <span style="font-size:17px;">⚠️</span>
          <strong style="color:#ef4444; font-size:13px; font-weight:800;">Breached Website Warning</strong>
        </div>
        <button id="csDismissBreach" style="background:transparent; border:0; color:#94a3b8; font-size:15px; cursor:pointer; padding:0 4px;">✕</button>
      </div>

      <div style="display:flex; gap:6px; margin-bottom:8px; align-items:center;">
        <span style="background:rgba(239,68,68,0.2); color:#fca5a5; padding:2px 7px; border-radius:4px; font-weight:700; font-size:9.5px; border:1px solid rgba(239,68,68,0.4);">
          Risk Rank: Critical Exposure (85/100)
        </span>
        <span style="background:rgba(99,80,244,0.2); color:#c7d2fe; padding:2px 7px; border-radius:4px; font-weight:700; font-size:9.5px; border:1px solid rgba(99,80,244,0.4);">
          ${res.breach_count} Breach Incident(s)
        </span>
      </div>

      <div style="color:#e2e8f0; font-size:11px; margin-bottom:8px;">
        <strong>${currentHostname}</strong> was compromised in a major data breach (<strong>${breachName}</strong>, ${breachDate}).
      </div>

      <div style="background:rgba(0,0,0,0.35); border-radius:6px; padding:7px 9px; margin-bottom:10px; border:1px solid #334155; font-size:10.5px; color:#cbd5e1;">
        <div style="margin-bottom:3px;"><strong style="color:#f87171;">Compromised Data:</strong> ${exposedList}</div>
        <div><strong style="color:#fcd34d;">Recommendation:</strong> Do NOT reuse your primary passwords here. Use a unique high-entropy combination.</div>
      </div>

      <div style="display:flex; gap:8px;">
        <a href="${portalBase}/pages/security-analyzer.html?domain=${encodeURIComponent(currentHostname)}&type=domain" target="_blank" style="flex:1; text-align:center; background:linear-gradient(110deg,#6350f4,#7b6bff); color:#fff; text-decoration:none; padding:6px 10px; border-radius:6px; font-size:10px; font-weight:700; box-shadow:0 3px 10px rgba(99,80,244,0.3);">
          View Full Breach Audit ↗
        </a>
        <button id="csAcknowledgeBreach" style="background:rgba(255,255,255,0.08); border:1px solid #475569; color:#cbd5e1; padding:6px 12px; border-radius:6px; font-size:10px; font-weight:600; cursor:pointer;">
          Understood
        </button>
      </div>
    `;

    document.body.appendChild(banner);

    const close = () => banner.remove();
    banner.querySelector("#csDismissBreach")?.addEventListener("click", close);
    banner.querySelector("#csAcknowledgeBreach")?.addEventListener("click", close);
  }

  // 4. In-Page Visual Badge (Safe = "Secure" / Danger = "Threat Alert")
  function renderPageBadge(riskLevel, score) {
    if (document.getElementById("cybershield-corner-badge")) return;

    const mount = document.body || document.documentElement;
    if (!mount) {
      if (document.readyState === "loading") {
        document.addEventListener("DOMContentLoaded", () => renderPageBadge(riskLevel, score), { once: true });
      } else {
        setTimeout(() => renderPageBadge(riskLevel, score), 50);
      }
      return;
    }

    const isDanger = (score && score >= 45) || pageHasThreat;
    const isWarning = !isDanger && (score && score >= 20 && score < 45);
    const badgeColor = isDanger ? "#ef4444" : (isWarning ? "#f59e0b" : "#10b981");
    const badgeText = isDanger ? "Threat Alert" : (isWarning ? "Caution" : "Secure");

    const badge = document.createElement("div");
    badge.id = "cybershield-corner-badge";
    badge.title = `CyberShield AI: ${badgeText} (${score || 0}/100)`;
    badge.style.cssText = `
      position: fixed;
      bottom: 20px;
      right: 20px;
      background: #0f172a;
      color: #f1f5f9;
      border: 1.5px solid ${badgeColor};
      padding: 6px 14px;
      border-radius: 20px;
      font-size: 11px;
      font-weight: 700;
      display: flex;
      visibility: visible;
      opacity: 1;
      align-items: center;
      gap: 6px;
      z-index: 2147483647;
      box-shadow: 0 4px 16px rgba(0,0,0,0.6);
      cursor: pointer;
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      transition: border-color 0.3s ease, box-shadow 0.3s ease;
      pointer-events: auto;
    `;
    badge.innerHTML = `<span id="cs-badge-dot" style="color:${badgeColor}; font-size:12px;">●</span> <span id="cs-badge-text">${badgeText}</span>`;
    badge.onclick = () => {
      alert(`🛡️ CyberShield AI Verdict:\n\nStatus: ${badgeText}\nRisk Score: ${score || 0}/100\nDomain: ${window.location.hostname || "Local file"}\n\n${isDanger ? (pageThreatReason ? `⚠️ ${pageThreatReason}` : '⚠️ Threat Alert: Risk detected on this page.') : '✅ Verified Secure: Phishing radar and cyberbullying shields active.'}`);
    };
    mount.appendChild(badge);
  }

  function updatePageBadge(riskLevel, score, threatNote) {
    if (threatNote) {
      pageHasThreat = true;
      pageThreatReason = threatNote;
    }
    const badge = document.getElementById("cybershield-corner-badge");
    const dot = document.getElementById("cs-badge-dot");
    const text = document.getElementById("cs-badge-text");
    if (!badge || !dot || !text) {
      renderPageBadge(riskLevel, score);
      return;
    }

    const isDanger = (score && score >= 45) || pageHasThreat;
    const isWarning = !isDanger && (score && score >= 20 && score < 45);
    const badgeColor = isDanger ? "#ef4444" : (isWarning ? "#f59e0b" : "#10b981");
    const badgeText = isDanger ? "Threat Alert" : (isWarning ? "Caution" : "Secure");

    badge.style.borderColor = badgeColor;
    dot.style.color = badgeColor;
    text.innerText = badgeText;
    badge.title = `CyberShield AI: ${badgeText} (${score || 0}/100)`;
    badge.onclick = () => {
      alert(`🛡️ CyberShield AI Verdict:\n\nStatus: ${badgeText}\nRisk Score: ${score || 0}/100\nDomain: ${window.location.hostname || "Local file"}\n\n${isDanger ? (pageThreatReason ? `⚠️ ${pageThreatReason}` : '⚠️ Threat Alert: Risk detected on this page.') : '✅ Verified Secure: Phishing radar and cyberbullying shields active.'}`);
    };
  }

  // 5. Top Floating Warning Banner for Critical Threats
  function renderTopWarningBanner(riskLevel, score, primaryFlag) {
    if (document.getElementById("cybershield-top-banner")) return;

    const banner = document.createElement("div");
    banner.id = "cybershield-top-banner";
    banner.style.cssText = `
      position: fixed;
      top: 0;
      left: 0;
      width: 100%;
      background: linear-gradient(135deg, #7f1d1d, #991b1b);
      color: #ffffff;
      padding: 10px 18px;
      font-family: -apple-system, BlinkMacSystemFont, sans-serif;
      font-size: 12.5px;
      font-weight: 600;
      z-index: 2147483647;
      display: flex;
      align-items: center;
      justify-content: space-between;
      box-shadow: 0 3px 10px rgba(0,0,0,0.4);
      border-bottom: 2px solid #ef4444;
    `;
    banner.innerHTML = `
      <div>
        <span style="font-size:15px; margin-right:6px;">⚠️</span>
        <strong>CyberShield AI:</strong> ${riskLevel} (${score}/100) — <em>${primaryFlag || "Suspicious lookalike detected"}</em>
      </div>
      <button style="background:rgba(255,255,255,0.2); border:1px solid #fff; color:#fff; padding:3px 8px; border-radius:4px; font-size:11px; cursor:pointer;" id="csDismissBanner">Dismiss</button>
    `;
    document.body.prepend(banner);
    document.getElementById("csDismissBanner").onclick = () => banner.remove();
  }

  // 6. Blur or Warn on Toxic Text (Social Media & Forums)
  
  // Dynamic MutationObserver for Chat Feeds & Live Comment Streams
  let toxicObserverDebounce = null;
  const liveToxicObserver = new MutationObserver((mutations) => {
    if (config.toxicBlur === false) return;
    let hasNewText = false;
    for (const m of mutations) {
      if (m.addedNodes.length > 0) {
        hasNewText = true;
        break;
      }
    }
    if (hasNewText) {
      clearTimeout(toxicObserverDebounce);
      toxicObserverDebounce = setTimeout(scanPageForToxicContent, 250);
    }
  });

  const attachToxicObserver = () => {
    if (document.body) {
      liveToxicObserver.observe(document.body, { childList: true, subtree: true });
    }
  };
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", attachToxicObserver);
  } else {
    attachToxicObserver();
  }

  function scanPageForToxicContent() {
    // Exact cyberbullying phrase matchers (using regex with word boundaries to avoid false positives on names/words)
    const toxicRegexes = [
      // 1. Extreme Threats & Violence
      /\b(kill\s+yourself|kill\s+you|should\s+kill\s+you|i\s+will\s+kill\s+you|i\s+will\s+find\s+you|go\s+die|should\s+die|hope\s+you\s+die|deserve\s+to\s+die|you\s+die|die\s+slut|worthless\s+piece\s+of\s+trash|destroy\s+you|beat\s+you|slit\s+your|burn\s+you|end\s+your\s+life)\b/i,
      // 2. Insults, Silencing & Intellectual Humiliation
      /\b(shut\s+up|shut\s+your\s+mouth|nobody\s+cares\s*(about\s*)?(your\s+opinion|what\s+you\s+say|what\s+you\s+think|u|you)?|nobody\s+asked\s+(you|for\s+your\s+opinion)|complete\s+joke|nobody\s+takes\s+you\s+seriously|waste\s+of\s+space|brainless|pathetic\s+loser|you\s+are\s+(an?\s+)?(idiot|loser|ugly|pathetic|moron|clown))\b/i,
      // 3. Social Exclusion & Ostracization
      /\b(don'?t\s+invite\s+(her|him|them)|nobody\s+wants\s+(her|him|you|them)\s+(around|here)|no\s*one\s+wants\s+you\s+(around|here)|no\s*one\s+likes\s+you|nobody\s+likes\s+you|make\s+a\s+group\s+without|ignore\s+all\s+(his|her|their)\s+messages|unfollow\s+this\s+person|they\s+don'?t\s+belong\s+here|you\s+don'?t\s+belong\s+here|leave\s+this\s+group)\b/i,
      // 4. Body Shaming & Aesthetic Ridicule
      /\b(looking\s+like\s+that|look\s+ridiculous|look\s+disgusting|hide\s+your\s+face|wear\s+clothes\s+like\s+that|your\s+appearance\s+is\s+the\s+reason|you\s+look\s+horrible|lose\s+some\s+weight|ugly\s+face|gross\s+body)\b/i,
      // 5. Digital Intimidation & Stalking
      /\b(keep\s+messaging\s+you\s+until|to\s+your\s+reputation|make\s+your\s+life\s+miserable|delete\s+your\s+account|can'?t\s+escape|watch\s+your\s+back|track\s+your\s+ip|you\s+will\s+pay\s+for\s+this|ruin\s+your\s+life|ruin\s+your\s+future)\b/i,
      // 6. Defamation, Rumours & Doxing
      /\b(spread\s+this\s+rumou?r|embarrassing\s+picture|fake\s+account\s+(just\s+)?to\s+expose|expose\s+you|share\s+this\s+post\s+so\s+everyone\s+can\s+laugh|leak\s+your\s+private|dox\s+you)\b/i
    ];

    // Method A: Check comment text containers (e.g. #content-text on YouTube, .comment-body, p, blockquote)
    const elements = document.querySelectorAll("yt-attributed-string#content-text, #content-text, p, blockquote, .comment-text, .user-comment, .comment-body, td");
    elements.forEach((el) => {
      if (isProtectedElement(el)) return;
      
      const text = (el.innerText || el.textContent || "").trim();
      if (text.length >= 6) {
        for (const reg of toxicRegexes) {
          if (reg.test(text)) {
            applyToxicBlur(el);
            break;
          }
        }
      }
    });

    // Method B: Selective TreeWalker ONLY for actual comment text, never for author/buttons
    const walker = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT, null, false);
    let node;
    while ((node = walker.nextNode())) {
      const parent = node.parentElement;
      if (!parent || isProtectedElement(parent)) continue;

      const val = (node.nodeValue || "").trim();
      if (val.length >= 8) {
        for (const reg of toxicRegexes) {
          if (reg.test(val)) {
            // Only blur the immediate text container, never an entire card
            applyToxicBlur(parent);
            break;
          }
        }
      }
    }
  }

  function isProtectedElement(el) {
    if (!el || !el.tagName) return true;
    
    // A. NEVER BLUR USER INPUTS, COMPOSERS, TEXTAREAS, OR POPUP MODALS
    if (
      el.tagName === "INPUT" ||
      el.tagName === "TEXTAREA" ||
      el.isContentEditable ||
      el.getAttribute("contenteditable") === "true" ||
      el.getAttribute("role") === "textbox" ||
      el.id === "contenteditable-root" ||
      el.id === "cybershield-outbound-blocker-modal" ||
      el.id === "cs-live-think-pill" ||
      el.closest('input, textarea, [contenteditable="true"], [role="textbox"], form, #contenteditable-root, ytd-commentbox, #comment-dialog, #cybershield-outbound-blocker-modal, #cs-live-think-pill')
    ) {
      return true;
    }

    // B. NEVER BLUR USERNAMES, CHANNELS, AVATARS, TIMESTAMPS, BUTTONS, OR LINKS
    const tag = el.tagName.toLowerCase();
    if (tag === "a" || tag === "button" || tag === "time" || tag === "img" || tag === "svg" || tag === "yt-icon") {
      return true;
    }

    const idStr = (el.id || "").toLowerCase();
    const classStr = (typeof el.className === "string" ? el.className : "").toLowerCase();
    if (
      idStr.includes("author") || idStr.includes("username") || idStr.includes("avatar") || idStr.includes("header") || idStr.includes("channel") ||
      classStr.includes("author") || classStr.includes("username") || classStr.includes("avatar") || classStr.includes("channel") ||
      el.closest('a, button, time, #author-text, #header-author, [id*="author"], [class*="author"], [class*="user-name"], [class*="username"], [class*="avatar"], .ytd-channel-name, ytd-author-comment-badge-renderer, ytd-comment-view-model #header-author')
    ) {
      return true;
    }

    return false;
  }

  function applyToxicBlur(element) {
    if (!element || element.hasAttribute("data-cybershield-blurred")) return;
    if (isProtectedElement(element)) return;
    element.setAttribute("data-cybershield-blurred", "true");
    element.style.filter = "blur(6px)";
    element.style.transition = "filter 0.3s ease, background-color 0.3s ease";
    element.style.backgroundColor = "rgba(239, 68, 68, 0.15)";
    element.style.borderRadius = "4px";
    element.style.padding = "2px 6px";
    element.style.cursor = "pointer";
    element.title = "🛡️ CyberShield AI: Potentially toxic harassment hidden. Click to reveal.";

    if (!element.hasAttribute("data-cybershield-incident-logged")) {
      element.setAttribute("data-cybershield-incident-logged", "true");
      updatePageBadge("TOXIC_CONTENT_DETECTED", 75, "Abusive cyberbullying or harassment content detected and blurred on page.");
      chrome.runtime.sendMessage({
        action: "RECORD_EXTENSION_INCIDENT",
        incident: {
          id: "bully_" + Date.now(),
          title: "Abusive Harassment Content Hidden",
          module: "Cyberbullying Detection",
          target: currentHostname || "Social Feed",
          date: "Just now",
          severity: "Medium",
          status: "Filtered",
          link: "cyberbullying-detection.html"
        }
      });
    }

    element.onclick = (e) => {
      e.stopPropagation();
      element.style.filter = "none";
      element.style.backgroundColor = "transparent";
      element.title = "Revealed content";
    };
  }

  // Smart High-Strength Combinations Formed STRICTLY Around User's Letters & Numbers
  function generatePersonalPasswordVariations(pwd) {
    if (!pwd || pwd.length < 3) return [];

    const letters = pwd.match(/[a-zA-Z]/g) || [];
    const digits = pwd.match(/\d/g) || [];
    const symbols = pwd.match(/[^a-zA-Z0-9\s]/g) || [];

    const wordBlocks = pwd.match(/[a-zA-Z]+/g) || ['Pass'];
    const mainWord = wordBlocks[0] || 'Pass';
    const capWord = mainWord.charAt(0).toUpperCase() + mainWord.slice(1);
    const lowerWord = mainWord.toLowerCase();
    const numBlock = digits.length > 0 ? digits.join('') : '2026';
    const sym = symbols.length > 0 ? symbols[0] : '!';
    const extraSym = sym === '!' ? '#' : (sym === '@' ? '!' : '*');

    const suggestions = [];

    // 1. Weaved / Interleaved Zip (e.g. N1e2e3@! or T9e4s1t!)
    if (letters.length > 0 && digits.length > 0) {
      let interleaved = '';
      const maxLen = Math.max(letters.length, digits.length);
      for (let i = 0; i < maxLen; i++) {
        if (i < letters.length) {
          interleaved += (i === 0 ? letters[i].toUpperCase() : letters[i].toLowerCase());
        }
        if (i < digits.length) {
          interleaved += digits[i];
        }
      }
      interleaved += sym;
      if (interleaved.length < 12) interleaved += extraSym;
      suggestions.push({
        val: interleaved,
        label: 'Weaved Interleaf',
        tag: 'Weaved'
      });
    }

    // 2. Inverted Numbers-First
    let inverted = `${numBlock}${sym}${capWord}`;
    if (inverted.length < 12) inverted += extraSym;
    suggestions.push({
      val: inverted,
      label: 'Inverted Reorder',
      tag: 'Inverted'
    });

    // 3. Shielded Sandwich
    const sandwich = `${sym}${capWord}.${numBlock}${extraSym}`;
    suggestions.push({
      val: sandwich,
      label: 'Shielded Sandwich',
      tag: 'Sandwich'
    });

    // 4. Reversed Block
    const revNums = [...digits].reverse().join('') || '99';
    let revComb = `${revNums}${sym}${lowerWord}`;
    if (revComb.length < 12) revComb += extraSym;
    suggestions.push({
      val: revComb,
      label: 'Reverse Weave',
      tag: 'Reverse'
    });

    return suggestions;
  }

  // 7. Real-Time Password Strength & Breach Analyzer in Password Fields
  function attachPasswordGuards() {
    document.querySelectorAll('input[type="password"]').forEach((input) => {
      if (input.hasAttribute("data-cybershield-guarded")) return;
      input.setAttribute("data-cybershield-guarded", "true");

      const tipBox = document.createElement("div");
      tipBox.style.cssText = `
        display: none;
        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
        font-size: 11px;
        color: #94a3b8;
        background: #0b1329;
        border: 1px solid #334155;
        border-radius: 9px;
        padding: 9px 12px;
        margin-top: 6px;
        z-index: 10000;
        box-shadow: 0 8px 24px rgba(0,0,0,0.5);
        max-width: 360px;
        line-height: 1.4;
      `;

      input.parentElement.appendChild(tipBox);

      let debounceTimer = null;

      input.addEventListener("focus", () => {
        if (input.value) tipBox.style.display = "block";
      });
      input.addEventListener("blur", () => {
        setTimeout(() => { tipBox.style.display = "none"; }, 300);
      });

      input.addEventListener("input", () => {
        tipBox.removeAttribute("data-cs-sugg-done");
        const pwd = input.value;
        if (!pwd) {
          tipBox.style.display = "none";
          return;
        }
        tipBox.style.display = "block";

        // Fast instant heuristic preview
        const length = pwd.length;
        const hasUpper = /[A-Z]/.test(pwd);
        const hasNumber = /\d/.test(pwd);
        const hasSpecial = /[@$!%*?&#^]/.test(pwd);

        let strength = "Weak";
        let color = "#ef4444";

        if (length >= 12 && hasUpper && hasNumber && hasSpecial) {
          strength = "Very Strong";
          color = "#10b981";
        } else if (length >= 8 && (hasUpper || hasNumber)) {
          strength = "Moderate";
          color = "#f59e0b";
        }

        tipBox.innerHTML = `
          <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:4px;">
            <span style="font-weight:700; color:#cbd5e1;">🛡️ CyberShield Password Shield:</span>
            <strong style="color:${color}; font-size:11px;">${strength}</strong>
          </div>
          <div style="font-size:10px; color:#64748b;" id="cs-analyzer-extra">Evaluating entropy & breach records...</div>
        `;

        // Debounce deep security analyzer query (entropy + HIBP breach check)
        clearTimeout(debounceTimer);
        debounceTimer = setTimeout(() => {
          chrome.runtime.sendMessage({ action: "CHECK_PASSWORD_SECURITY", password: pwd }, (res) => {
            const extra = tipBox.querySelector("#cs-analyzer-extra");
            if (!extra) return;

            const isCompromised = res && res.breached;
            const score = res?.score || (strength === "Very Strong" ? 85 : strength === "Moderate" ? 50 : 25);
            const isHigh = !isCompromised && score >= 75;

            if (isCompromised) {
              tipBox.style.borderColor = "#ef4444";
              extra.innerHTML = `
                <div style="color:#ef4444; font-weight:700; margin-top:2px;">⚠️ Found in ${res.breach_count.toLocaleString()} known data breaches!</div>
                <div style="color:#cbd5e1; font-size:9.5px; margin-top:2px;">Entropy: ${res.entropy_bits} bits • Do NOT use this password.</div>
              `;
              chrome.runtime.sendMessage({
                action: "RECORD_EXTENSION_INCIDENT",
                incident: {
                  id: "pwd_leak_" + Date.now(),
                  title: `Breached Password Intercepted (${res.breach_count.toLocaleString()} breaches)`,
                  module: "Security Analyzer",
                  target: currentHostname || "Credentials Field",
                  date: "Just now",
                  severity: "Critical",
                  status: "Action Needed",
                  link: "security-analyzer.html"
                }
              });
            } else if (res && res.status === "success") {
              const safeColor = isHigh ? "#10b981" : (score >= 40 ? "#f59e0b" : "#ef4444");
              tipBox.style.borderColor = safeColor;
              extra.innerHTML = `
                <div style="color:${safeColor}; font-weight:600; margin-top:2px;">Ranking: ${res.label.toUpperCase()} (${score}/100) • 0 Breaches</div>
                <div style="color:#94a3b8; font-size:9.5px; margin-top:2px;">Entropy: ${res.entropy_bits} bits • Crack time: ${res.estimated_crack_time || "N/A"}</div>
              `;
            }

            // If Moderate, Weak, or Breached, suggest high-strength variations (once per debounce)
            if (!isHigh && !tipBox.hasAttribute('data-cs-sugg-done')) {
              tipBox.setAttribute('data-cs-sugg-done', '1');
              const variations = generatePersonalPasswordVariations(pwd);
              if (variations.length > 0) {
                let suggestionsHTML = `
                  <div style="margin-top:8px; padding-top:6px; border-top:1px dashed #334155;">
                    <div style="font-size:9.5px; color:#c7d2fe; font-weight:700; margin-bottom:5px; display:flex; justify-content:space-between; align-items:center;">
                      <span>✨ High-Strength Smart Variations (from your characters):</span>
                      <span style="font-size:8px; color:#10b981;">Very Strong</span>
                    </div>
                    <div style="display:flex; flex-direction:column; gap:4px;">
                `;

                variations.slice(0, 3).forEach((v) => {
                  suggestionsHTML += `
                    <div data-val="${v.val}" class="cs-sugg-pill" style="display:flex; justify-content:space-between; align-items:center; background:#162038; border:1px solid #3b82f6; border-radius:5px; padding:4px 8px; cursor:pointer; font-family:monospace; font-size:11px; color:#38bdf8; transition:all 0.15s ease;" title="Click to apply ${v.label}">
                      <span style="font-weight:700;">${v.val}</span>
                      <span style="font-size:8px; color:#93c5fd; font-family:sans-serif; background:rgba(59,130,246,0.2); padding:1px 5px; border-radius:3px;">
                        ${v.tag} ➔ Use
                      </span>
                    </div>
                  `;
                });

                suggestionsHTML += `</div></div>`;
                extra.innerHTML += suggestionsHTML;

                // Make suggestions clickable to fill the field
                tipBox.querySelectorAll(".cs-sugg-pill").forEach(pill => {
                  pill.onmousedown = (e) => {
                    e.preventDefault(); // prevent blur
                    const chosen = pill.getAttribute("data-val");
                    input.value = chosen;
                    input.dispatchEvent(new Event("input", { bubbles: true }));
                    input.dispatchEvent(new Event("change", { bubbles: true }));
                  };
                  pill.onmouseenter = () => { pill.style.borderColor = "#60a5fa"; pill.style.background = "#1e293b"; };
                  pill.onmouseleave = () => { pill.style.borderColor = "#3b82f6"; pill.style.background = "#162038"; };
                });
              }
            }
          });
        }, 300);
      });
    });
  }

  // 8. Security Analyzer & Web Portal Inter-Process Bridge
  // Allows web pages (such as security-analyzer.html) to communicate with the extension
  window.addEventListener("message", (event) => {
    if (!event.data) return;

    if (event.data.type === "CYBERSHIELD_REQ_ACTIVE_TAB") {
      chrome.runtime.sendMessage({ action: "GET_ACTIVE_TAB_INFO" }, (res) => {
        window.postMessage({
          type: "CYBERSHIELD_RESP_ACTIVE_TAB",
          data: res || {
            url: window.location.href,
            domain: window.location.hostname,
            title: document.title
          }
        }, "*");
      });
    }

    if (event.data.type === "CYBERSHIELD_SCAN_DOMAIN_LEAK") {
      const targetDomain = event.data.domain || window.location.hostname;
      chrome.runtime.sendMessage({ action: "CHECK_DOMAIN_LEAK", domain: targetDomain }, (res) => {
        window.postMessage({
          type: "CYBERSHIELD_RESP_DOMAIN_LEAK",
          data: res
        }, "*");
      });
    }
  });

  function evaluateToxicitySync(text) {
    if (!text || typeof text !== "string" || !text.trim()) {
      return { isToxic: false, score: 0, level: "SAFE", flagged: [], categories: [] };
    }

    const rawLower = text.toLowerCase();
    const cleaned = (" " + rawLower.replace(/[^\w\s']/g, " ").replace(/\s+/g, " ") + " ");
    let score = 0;
    const flagged = [];
    const categories = [];

    // Multi-Category Taxonomy (Google Jigsaw & StopBullying Benchmark Corpus)
    const taxonomy = {
      threat: {
        name: "Violent Threat & Extreme Harm",
        weight: 75,
        patterns: [
          "i will find you", "kill yourself", "kill you", "should kill you", "i will kill you",
          "kill you with", "murder you", "shoot you", "stab you", "strangle you",
          "beat you to death", "go die", "should die", "hope you die", "deserve to die",
          "beat you", "hurt you", "destroy you", "slit your", "burn you", "murder", "end your life"
        ]
      },
      intimidation: {
        name: "Digital Intimidation & Stalking",
        weight: 50,
        patterns: [
          "keep messaging you until", "to your reputation", "make your life miserable",
          "delete your account", "can't escape", "disappear from this platform",
          "watch your back", "track your ip", "you will pay for this", "ruin your life",
          "ruin your future", "stalk"
        ]
      },
      defamation: {
        name: "Defamation & Malicious Doxing",
        weight: 50,
        patterns: [
          "spread this rumour", "spread this rumor", "embarrassing picture",
          "fake account just to expose", "fake account to expose", "expose you",
          "everyone should see this embarrassing", "share this post so everyone can laugh",
          "leak your private", "dox you"
        ]
      },
      social_exclusion: {
        name: "Social Exclusion & Ostracization",
        weight: 50,
        patterns: [
          "don't invite her", "don't invite him", "don't invite them", "nobody wants her around",
          "nobody wants him around", "nobody wants you around", "nobody wants you here",
          "no one wants you around", "no one wants you here", "no one likes you", "nobody likes you",
          "make a group without", "ignore all his messages", "ignore all her messages",
          "unfollow this person", "they don't belong here", "you don't belong here",
          "nobody asked you", "leave this group"
        ]
      },
      body_shaming: {
        name: "Body Shaming & Aesthetic Ridicule",
        weight: 50,
        patterns: [
          "looking like that", "look ridiculous", "look disgusting", "hide your face",
          "wear clothes like that", "your appearance is the reason", "you look horrible",
          "lose some weight", "so fat", "ugly face"
        ]
      },
      insult: {
        name: "Insults & Intellectual Humiliation",
        weight: 45,
        patterns: [
          "stupid", "idiot", "loser", "ugly", "fat", "dumb", "dumbest", "hate you",
          "freak", "trash", "worthless", "pathetic", "complete joke", "nobody takes you seriously",
          "embarrassing", "laughs at you behind", "stop talking", "waste of space", "shut up", "shut your mouth", "nobody cares", "nobody cares about your opinion", "nobody asked for your opinion"
        ]
      },
      profanity: {
        name: "Profanity & Misogynistic Slurs",
        weight: 55,
        patterns: [
          "bitch", "bastard", "fuck", "shit", "asshole", "crap", "slut", "whore", "cunt", "skank", "hoe", "motherfucker"
        ]
      }
    };

    for (const [key, cat] of Object.entries(taxonomy)) {
      let matched = false;
      for (const pat of cat.patterns) {
        if (cleaned.includes(" " + pat + " ") || cleaned.includes(pat)) {
          score += cat.weight;
          flagged.push(pat);
          matched = true;
        }
      }
      if (matched && !categories.includes(cat.name)) categories.push(cat.name);
    }

    // Combinatorial SVO Semantic Rules (Parity with Python Backend modules/toxicity_engine.py)
    const svoRules = [
      { cat: "Violent Threat & Extreme Harm", weight: 85, regex: /\b(kill|murder|shoot|stab|choke|strangle|beat|smash|hit|cut|attack|destroy|hurt|burn|drown|torture|crush|punch|slap|slice|hang|slaughter|butcher)\s+(you|u|your\s+(head|face|throat|neck|body|chest)|her|him)\b/i, label: "direct violent assault" },
      { cat: "Violent Threat & Extreme Harm", weight: 80, regex: /\b(i\s*('?ll|will|should|must|wanna|want\s+to|gonna|am\s+going\s+to|can))\s+.*(kill|murder|beat|hurt|destroy|stab|shoot|smash|slap|attack|burn|crush)\s+(you|u)\b/i, label: "violent declaration" },
      { cat: "Violent Threat & Extreme Harm", weight: 75, regex: /\b(with\s+(a\s+)?(hammer|knife|gun|weapon|bat|blade|axe|acid|brick|pipe|crowbar|sword|rope|pistol|rifle))\b/i, label: "weapon assault" },
      { cat: "Violent Threat & Extreme Harm", weight: 85, regex: /\b(you|u)\s+(should|must|need\s+to|deserve\s+to|ought\s+to|better|just)?\s*(die|perish|burn|suffer|rot|hang\s+yourself|kill\s+(yourself|urself)|end\s+your\s+life)\b|\bdie\s+(bitch|slut|whore|bastard|loser|idiot|now|alone|here)\b|\b(you|u)\s+die\b/i, label: "death wish / suicide incitement" },
      { cat: "Violent Threat & Extreme Harm", weight: 75, regex: /\b(should|hope|wish|want|deserve|pray)\s+(you|u)\s+(die|perish|rot|suffer|burn|get\s+killed)\b/i, label: "fatality wish" },
      { cat: "Violent Threat & Extreme Harm", weight: 75, regex: /\b(go|better|just)\s+die\b/i, label: "death incitement" },
      { cat: "Violent Threat & Extreme Harm", weight: 85, regex: /\b(kill|hang)\s+(yourself|urself)\b/i, label: "suicide incitement" },
      { cat: "Social Exclusion & Ostracization", weight: 55, regex: /\b(no\s*one|nobody|not\s+a\s+single\s+person|none\s+of\s+us)\s+(likes?|wants?|cares?\s+about|cares?|loves?|needs?|trusts?|respects?|talks?\s+to)\s+(you|u|her|him|them)\b/i, label: "universal rejection" },
      { cat: "Social Exclusion & Ostracization", weight: 50, regex: /\b(don\'?t|do\s+not|never)\s+(invite|talk\s+to|speak\s+to|hang\s+out\s+with|message)\s+(her|him|them|you|u)\b/i, label: "relational ostracization" },
      { cat: "Social Exclusion & Ostracization", weight: 50, regex: /\b(make\s+a\s+group|group\s+chat)\s+without\s+(him|her|them|you|u)\b/i, label: "exclusion group" },
      { cat: "Social Exclusion & Ostracization", weight: 50, regex: /\b(ignore|block|mute)\s+(all\s+)?(his|her|their|your)\s+(messages|texts|calls|posts)\b/i, label: "communication blocking" },
      { cat: "Social Exclusion & Ostracization", weight: 50, regex: /\b(they|you|u|she|he)\s+(don\'?t|does\s+not|doesn\'?t)\s+belong\s+(here|with\s+us|in\s+this\s+group)\b/i, label: "exclusion alienation" },
      { cat: "Body Shaming & Aesthetic Ridicule", weight: 55, regex: /\b(look|looking|looks)\s+(so\s+)?(ridiculous|disgusting|horrible|repulsive|ugly|fat|gross|hideous|repugnant|like\s+a\s+(clown|joke|pig|cow|whale|freak))\b/i, label: "appearance denigration" },
      { cat: "Body Shaming & Aesthetic Ridicule", weight: 55, regex: /\b(appearance|face|weight|body|figure|skin)\s+(is\s+the\s+reason|makes\s+me\s+sick|is\s+disgusting|looks\s+terrible)\b/i, label: "body shaming" },
      { cat: "Body Shaming & Aesthetic Ridicule", weight: 50, regex: /\b(upload|post|take)\s+(a\s+)?(picture|photo)\s+looking\s+like\s+that\b/i, label: "aesthetic mockery" },
      { cat: "Digital Intimidation & Stalking", weight: 55, regex: /\b(keep|continue)\s+(messaging|texting|calling|harassing|stalking|following)\s+(you|u)\s+(until|forever)\b/i, label: "stalking pressure" },
      { cat: "Digital Intimidation & Stalking", weight: 55, regex: /\b(make\s+your\s+life|ruin\s+your|destroy\s+your)\s+(miserable|life|reputation|future|career|family)\b/i, label: "intimidation threat" },
      { cat: "Digital Intimidation & Stalking", weight: 50, regex: /\b(delete|deactivate|remove)\s+(your\s+)?(account|profile|channel|post)\b/i, label: "account silencing" },
      { cat: "Digital Intimidation & Stalking", weight: 50, regex: /\b(can\'?t|cannot|won\'?t)\s+escape\s+(me|what\s+i|this)\b/i, label: "coercive entrapment" },
      { cat: "Defamation & Malicious Doxing", weight: 55, regex: /\b(spread|share|leak|post|circulate)\s+(this\s+)?(rumour|rumor|lie|lies|photo|picture|screenshot|chat|video|private|secret)\b/i, label: "rumour / doxing spread" },
      { cat: "Defamation & Malicious Doxing", weight: 55, regex: /\b(fake\s+account|alt\s+account)\s+(just\s+)?to\s+expose\s+(you|her|him)\b/i, label: "smear campaign" },
      { cat: "Insults & Intellectual Humiliation", weight: 50, regex: /\b(you(\'re|\s+are)|u\s+r)\s+(literally\s+)?(a\s+|an\s+|the\s+)?(dumbest|stupidest|biggest\s+loser|complete\s+joke|joke|laughing\s+stock|waste\s+of\s+space|brainless|moron|idiot|imbecile|retard|failure|clown|freak|loser)\b/i, label: "direct insult" },
      { cat: "Insults & Intellectual Humiliation", weight: 45, regex: /\b(nobody|no\s*one)\s+takes\s+you\s+seriously\b/i, label: "intellectual ridicule" },
      { cat: "Insults & Intellectual Humiliation", weight: 40, regex: /\b(your\s+)?opinions?\s+(are|is)\s+(embarrassing|pathetic|garbage|worthless)\b/i, label: "opinion humiliation" },
      { cat: "Insults & Intellectual Humiliation", weight: 55, regex: /\b(shut\s+up|shut\s+your\s+mouth|nobody\s+cares\s*(about\s*)?(your\s+opinion|what\s+you\s+say|what\s+you\s+think|u|you)?|nobody\s+asked\s+(you|for\s+your\s+opinion))\b/i, label: "aggressive silencing / contempt" },
      { cat: "Profanity & Misogynistic Slurs", weight: 55, regex: /\b(slut|whore|bitch|cunt|skank|hoe|motherfucker|asshole|bastard|dipshit|douchebag)\b/i, label: "abusive profanity / misogynistic slur" }
    ];

    for (const rule of svoRules) {
      if (rule.regex.test(cleaned)) {
        score = Math.max(score, rule.weight);
        flagged.push(rule.label);
        if (!categories.includes(rule.cat)) categories.push(rule.cat);
      }
    }

    // Compounding multi-category escalation
    if (categories.length > 1) {
      score += (categories.length - 1) * 15;
    }

    score = Math.min(score, 100);
    const uniqueFlagged = [...new Set(flagged)];

    const isToxic = score >= 35;
    let level = "SAFE / NON-TOXIC CONTENT";
    if (score >= 65) level = "HIGHLY TOXIC / SEVERE HARASSMENT";
    else if (score >= 35) level = "MODERATE TOXICITY DETECTED";

    return {
      isToxic,
      score,
      level,
      flagged: uniqueFlagged,
      categories,
      primaryReason: uniqueFlagged[0] || (categories[0] ? `Violates ${categories[0]} standards` : "Harmful language detected")
    };
  }

  // Interactive Outbound Message Blocker Modal Overlay
  function renderOutboundBlockModal(analysis, targetElement) {
    const existing = document.getElementById("cybershield-outbound-blocker-modal");
    if (existing) existing.remove();

    const originalValue = targetElement ? (targetElement.value || targetElement.innerText || targetElement.textContent || "") : "";

    const overlay = document.createElement("div");
    overlay.id = "cybershield-outbound-blocker-modal";
    overlay.style.cssText = `
      position: fixed;
      top: 0;
      left: 0;
      width: 100vw;
      height: 100vh;
      background: rgba(4, 7, 18, 0.85);
      backdrop-filter: blur(8px);
      -webkit-backdrop-filter: blur(8px);
      display: flex;
      align-items: center;
      justify-content: center;
      z-index: 2147483647;
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
      color: #f8fafc;
      animation: csFadeIn 0.2s cubic-bezier(0.16, 1, 0.3, 1);
    `;

    const isSevere = analysis.score >= 65;
    const accentColor = isSevere ? "#ef4444" : "#f59e0b";
    const badgeText = isSevere ? "CRITICAL HARASSMENT" : "MODERATE HARASSMENT";
    const categoryStr = analysis.categories.length > 0 ? analysis.categories.join(", ") : "Cyberbullying & Abuse";

    overlay.innerHTML = `
      <style>
        @keyframes csFadeIn {
          from { opacity: 0; transform: scale(0.96); }
          to { opacity: 1; transform: scale(1); }
        }
        .cs-btn-pulse {
          box-shadow: 0 0 0 0 rgba(56, 189, 248, 0.7);
          animation: csPulse 1.8s infinite cubic-bezier(0.66, 0, 0, 1);
        }
        @keyframes csPulse {
          to { box-shadow: 0 0 0 14px rgba(56, 189, 248, 0); }
        }
      </style>
      <div style="
        background: linear-gradient(145deg, #0f172a, #090d16);
        border: 1.5px solid ${accentColor};
        border-radius: 16px;
        width: 90%;
        max-width: 530px;
        padding: 24px 26px;
        box-shadow: 0 25px 60px -15px rgba(0, 0, 0, 0.9), 0 0 35px -5px ${accentColor}33;
        position: relative;
      ">
        <!-- Top Title Bar -->
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 14px; padding-bottom: 12px; border-bottom: 1px solid rgba(255,255,255,0.08);">
          <div style="display: flex; align-items: center; gap: 10px;">
            <div style="width: 32px; height: 32px; border-radius: 8px; background: rgba(239, 68, 68, 0.15); border: 1px solid rgba(239, 68, 68, 0.3); display: flex; align-items: center; justify-content: center; font-size: 16px;">
              🛡️
            </div>
            <div>
              <h3 style="margin: 0; font-size: 15px; font-weight: 800; color: #fff; letter-spacing: -0.2px;">CyberShield AI</h3>
              <span style="font-size: 11px; color: #94a3b8;">Outbound Message Interceptor</span>
            </div>
          </div>
          <div style="display: flex; align-items: center; gap: 8px;">
            <span style="background: rgba(239, 68, 68, 0.2); color: #f87171; border: 1px solid #ef4444; padding: 3px 9px; border-radius: 20px; font-size: 11px; font-weight: 800; letter-spacing: 0.5px;">
              🛑 SEND BLOCKED
            </span>
            <button id="csCloseModalX" style="background: transparent; border: none; color: #64748b; font-size: 18px; cursor: pointer; padding: 2px 6px; line-height: 1;">✕</button>
          </div>
        </div>

        <!-- Hero Warning -->
        <div style="margin-bottom: 14px;">
          <h2 style="font-size: 17px; font-weight: 800; color: #fff; margin: 0 0 5px 0; display: flex; align-items: center; gap: 8px;">
            <span>⚠️</span> Think Before You Post
          </h2>
          <p style="margin: 0; font-size: 12.5px; color: #cbd5e1; line-height: 1.5;">
            CyberShield AI prevented this message from being sent because it violates anti-cyberbullying standards and platform community guidelines.
          </p>
        </div>

        <!-- Severity Metrics Box -->
        <div style="background: rgba(2, 6, 23, 0.7); border: 1px solid rgba(255,255,255,0.06); border-radius: 10px; padding: 12px 14px; margin-bottom: 14px;">
          <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 6px;">
            <span style="font-size: 12px; color: #94a3b8; font-weight: 600;">Harm Assessment:</span>
            <span style="font-size: 12px; font-weight: 800; color: ${accentColor};">${badgeText} (${analysis.score}/100)</span>
          </div>
          <div style="display: flex; flex-wrap: wrap; gap: 6px; margin-top: 6px;">
            <span style="background: rgba(244, 63, 94, 0.15); color: #fb7185; border: 1px solid rgba(244, 63, 94, 0.3); padding: 2px 8px; border-radius: 6px; font-size: 11px; font-weight: 600;">
              ${categoryStr}
            </span>
            ${analysis.flagged.slice(0, 3).map(f => `<span style="background: rgba(255,255,255,0.05); color: #94a3b8; border: 1px solid rgba(255,255,255,0.1); padding: 2px 8px; border-radius: 6px; font-size: 10.5px;">Flag: ${f}</span>`).join('')}
          </div>
        </div>

        <!-- Blocked Message Preview -->
        <div style="margin-bottom: 14px;">
          <span style="font-size: 11px; font-weight: 700; color: #64748b; text-transform: uppercase; letter-spacing: 0.5px;">Blocked Outbound Content:</span>
          <div style="margin-top: 5px; background: rgba(239, 68, 68, 0.08); border-left: 3px solid ${accentColor}; padding: 10px 12px; border-radius: 4px; font-size: 13px; color: #e2e8f0; font-style: italic; max-height: 80px; overflow-y: auto;">
            "${originalValue.length > 180 ? originalValue.substring(0, 180) + '...' : originalValue}"
          </div>
        </div>

        <!-- Legal / Psychological Reminder -->
        <div style="font-size: 11.5px; color: #94a3b8; background: rgba(56, 189, 248, 0.06); border: 1px dashed rgba(56, 189, 248, 0.25); border-radius: 8px; padding: 9px 12px; margin-bottom: 18px; line-height: 1.45;">
          💡 <em>Legal & Safety Note:</em> Under Indian IT Act Sec 66E/67 & IPC Sec 506/507, digital intimidation, hate speech, and abusive communications carry severe legal consequences. Take a breath and rephrase constructively.
        </div>

        <!-- Interactive Actions -->
        <div style="display: flex; gap: 10px; justify-content: flex-end;">
          <button id="csClearMsgBtn" style="
            background: rgba(255, 255, 255, 0.06);
            border: 1px solid rgba(255, 255, 255, 0.15);
            color: #cbd5e1;
            padding: 9px 15px;
            border-radius: 8px;
            font-size: 13px;
            font-weight: 600;
            cursor: pointer;
            transition: background 0.2s;
          ">
            🗑️ Clear Text
          </button>
          <button id="csEditMsgBtn" class="cs-btn-pulse" style="
            background: linear-gradient(135deg, #0284c7, #0369a1);
            border: 1px solid #38bdf8;
            color: #ffffff;
            padding: 9px 20px;
            border-radius: 8px;
            font-size: 13.5px;
            font-weight: 800;
            cursor: pointer;
            display: flex;
            align-items: center;
            gap: 6px;
            transition: transform 0.15s, background 0.2s;
          ">
            ✏️ Edit Message
          </button>
        </div>
      </div>
    `;

    document.body.appendChild(overlay);

    const closeModal = () => {
      overlay.remove();
    };

    document.getElementById("csCloseModalX").onclick = closeModal;

    document.getElementById("csClearMsgBtn").onclick = () => {
      if (targetElement) {
        if (typeof targetElement.value !== "undefined") targetElement.value = "";
        targetElement.innerText = "";
        targetElement.textContent = "";
        try {
          targetElement.dispatchEvent(new Event("input", { bubbles: true }));
          targetElement.dispatchEvent(new Event("change", { bubbles: true }));
        } catch (e) {}
        targetElement.focus();
      }
      closeModal();
    };

    document.getElementById("csEditMsgBtn").onclick = () => {
      closeModal();
      if (targetElement) {
        targetElement.focus();
        if (typeof targetElement.select === "function") {
          targetElement.select();
        }
        targetElement.style.transition = "box-shadow 0.3s ease, border-color 0.3s ease";
        targetElement.style.outline = "none";
        targetElement.style.borderColor = "#38bdf8";
        targetElement.style.boxShadow = "0 0 12px rgba(56, 189, 248, 0.6)";
        setTimeout(() => {
          if (targetElement) {
            targetElement.style.boxShadow = "";
            targetElement.style.borderColor = "";
          }
        }, 2500);
      }
    };
  }

  // Helper to extract text from standard inputs, textareas, or modern contenteditable/rich-text editors
  function getTargetText(el) {
    if (!el) return "";
    if (el.tagName === "INPUT" || el.tagName === "TEXTAREA") return el.value || "";
    // If inside a contenteditable element (e.g. WhatsApp Web, Twitter, LinkedIn), climb to the root editable container
    const editable = el.isContentEditable ? (el.closest('[contenteditable="true"]') || el) : el.closest('[contenteditable="true"], [role="textbox"]');
    if (editable) return editable.innerText || editable.textContent || "";
    return el.value || el.innerText || el.textContent || "";
  }

  // Helper to find associated text input/composer when a Send or Post button is clicked across any website
  function findAssociatedInputElement(btn) {
    // WhatsApp Web specific chat composer hook
    const waRoot = document.querySelector('footer div[contenteditable="true"], div[data-tab="10"][contenteditable="true"], div[title="Type a message"][contenteditable="true"], div[data-lexical-editor="true"][contenteditable="true"], div._ak1r[contenteditable="true"]');
    if (waRoot) {
      const val = getTargetText(waRoot);
      if (val && val.trim().length >= 2) return waRoot;
    }

    // YouTube specific comment composer hook
    const ytRoot = document.querySelector('#contenteditable-root, ytd-commentbox #contenteditable-root, div#contenteditable-root[contenteditable="true"]');
    if (ytRoot) {
      const val = getTargetText(ytRoot);
      if (val && val.trim().length >= 2) return ytRoot;
    }

    // 1. Check if activeElement is currently an input/composer
    const active = document.activeElement;
    if (active && active !== btn && (active.tagName === "TEXTAREA" || active.tagName === "INPUT" || active.isContentEditable || active.getAttribute("role") === "textbox")) {
      const val = getTargetText(active);
      if (val && val.trim().length >= 2) return active;
    }

    // 2. Check closest form
    const form = btn.closest("form");
    if (form) {
      const inp = form.querySelector('textarea, [contenteditable="true"], [role="textbox"], input[type="text"], input:not([type])');
      if (inp && getTargetText(inp).trim().length >= 2) return inp;
    }

    // 3. Search upwards in container hierarchies (YouTube, WhatsApp, Twitter/X, Reddit, LinkedIn, Discord wrappers)
    let parent = btn.parentElement;
    let depth = 0;
    while (parent && depth < 8 && parent !== document.body) {
      const candidates = parent.querySelectorAll('textarea, [contenteditable="true"], [role="textbox"], input[type="text"], input:not([type])');
      for (const cand of candidates) {
        if (cand !== btn && !cand.contains(btn)) {
          const val = getTargetText(cand);
          if (val && val.trim().length >= 2) return cand;
        }
      }
      parent = parent.parentElement;
      depth++;
    }

    // 4. Fallback: Search all active textareas or contenteditables on page that have text
    const allInputs = document.querySelectorAll('textarea, [contenteditable="true"], [role="textbox"]');
    for (const cand of allInputs) {
      const val = getTargetText(cand);
      if (val && val.trim().length >= 2) return cand;
    }
    return null;
  }

  // Intercept Outbound Message Transmissions & Provide Real-Time "Think Before You Post" Guidance
  function attachOutboundMessageGuard() {
    if (window.__cybershield_outbound_guard_attached) return;
    window.__cybershield_outbound_guard_attached = true;

    // 1. Real-Time Typing Guidance ("Think Before You Post" live safety indicator)
    let liveTipTimeout = null;
    const handleTypingGuidance = (e) => {
      if (config.outboundBlocker === false) return;
      const target = e.target;
      if (!target) return;
      const el = (target.closest && target.closest('[contenteditable="true"]')) ||
                 target.closest('textarea, input[type="text"], input[type="search"], input:not([type]), [role="textbox"]') ||
                 target;
      if (!el) return;

      clearTimeout(liveTipTimeout);
      liveTipTimeout = setTimeout(() => {
        const text = getTargetText(el);
        const pillId = "cs-live-think-pill";
        const existingPill = document.getElementById(pillId);

        if (!text || text.trim().length < 3) {
          if (existingPill) existingPill.remove();
          el.style.borderColor = "";
          el.style.boxShadow = "";
          return;
        }

        const analysis = evaluateToxicitySync(text);
        if (analysis.isToxic) {
          el.style.transition = "border-color 0.2s, box-shadow 0.2s";
          el.style.borderColor = "#ef4444";
          el.style.boxShadow = "0 0 8px rgba(239, 68, 68, 0.4)";

          if (!existingPill) {
            const pill = document.createElement("div");
            pill.id = pillId;
            pill.style.cssText = `
              font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
              font-size: 11.5px;
              font-weight: 700;
              color: #f87171;
              background: #0f172a;
              border: 1px solid #ef4444;
              border-radius: 6px;
              padding: 5px 10px;
              margin-top: 4px;
              display: inline-flex;
              align-items: center;
              gap: 6px;
              z-index: 99999;
              box-shadow: 0 4px 12px rgba(0,0,0,0.4);
              animation: csFadeIn 0.2s ease;
            `;
            pill.innerHTML = `🛡️ <strong>CyberShield:</strong> ⚠️ "Think Before You Post" (Harmful language detected)`;
            if (el.parentElement) el.parentElement.appendChild(pill);
          }
        } else {
          if (existingPill) existingPill.remove();
          el.style.borderColor = "";
          el.style.boxShadow = "";
        }
      }, 200);
    };

    document.addEventListener("input", handleTypingGuidance, true);
    window.addEventListener("input", handleTypingGuidance, true);

    // 2. Intercept Enter Key (Enter, Ctrl+Enter, Cmd+Enter across chat & forum apps)
    const handleKeyDownTrigger = (e) => {
      if (config.outboundBlocker === false) return;
      if (e.key !== "Enter") return;
      if (e.shiftKey && e.target && e.target.tagName === "TEXTAREA") return;

      const target = e.target;
      if (!target) return;

      const el = (target.closest && target.closest('[contenteditable="true"]')) ||
                 target.closest('textarea, input[type="text"], input[type="search"], input:not([type]), [role="textbox"]') ||
                 target;
      
      let text = getTargetText(el);
      // Fallback: check WhatsApp Web footer compose box if event target is nested or indirect
      if (!text || text.trim().length < 2) {
        const waBox = document.querySelector('footer div[contenteditable="true"], div[data-tab="10"][contenteditable="true"]');
        if (waBox) text = getTargetText(waBox);
      }

      if (!text || text.trim().length < 2) return;

      const analysis = evaluateToxicitySync(text);
      if (analysis.isToxic) {
        e.preventDefault();
        e.stopPropagation();
        e.stopImmediatePropagation();
        renderOutboundBlockModal(analysis, el);
        return false;
      }
    };

    window.addEventListener("keydown", handleKeyDownTrigger, true);
    document.addEventListener("keydown", handleKeyDownTrigger, true);

    // 3. Intercept Form Submissions
    const handleFormSubmitTrigger = (e) => {
      if (config.outboundBlocker === false) return;
      const form = e.target;
      if (!form || !form.querySelectorAll) return;

      const inputs = form.querySelectorAll('textarea, input[type="text"], input[type="search"], input:not([type]), [contenteditable="true"], [role="textbox"]');
      for (const inp of inputs) {
        const text = getTargetText(inp);
        if (text && text.trim().length >= 2) {
          const analysis = evaluateToxicitySync(text);
          if (analysis.isToxic) {
            e.preventDefault();
            e.stopPropagation();
            e.stopImmediatePropagation();
            renderOutboundBlockModal(analysis, inp);
            return false;
          }
        }
      }
    };

    document.addEventListener("submit", handleFormSubmitTrigger, true);
    window.addEventListener("submit", handleFormSubmitTrigger, true);

    // 4. Intercept Click & Pointer Events on Send / Submit / Comment / Tweet / Post Buttons across all websites
    const handleSendActionTrigger = (e) => {
      if (config.outboundBlocker === false) return;
      const target = e.target;
      if (!target) return;

      const btn = target.closest('button, input[type="submit"], [role="button"], a.btn, div.btn, div[role="button"], span[role="button"]');
      if (!btn) return;
      if (btn.closest("#cybershield-outbound-blocker-modal")) return;

      const btnText = (btn.innerText || btn.value || btn.title || btn.getAttribute("aria-label") || btn.getAttribute("data-testid") || "").toLowerCase();
      const hasSendIcon = btn.querySelector('[data-icon="send"]') ||
                          (btn.getAttribute("data-tab") === "11") ||
                          (btn.getAttribute("data-icon") === "send") ||
                          (btn.parentElement && btn.parentElement.querySelector('[data-icon="send"]'));

      const isSendAction = btn.type === "submit" ||
        hasSendIcon ||
        btnText.includes("send") ||
        btnText.includes("post") ||
        btnText.includes("comment") ||
        btnText.includes("submit") ||
        btnText.includes("reply") ||
        btnText.includes("tweet") ||
        btnText.includes("publish") ||
        (btn.id && btn.id.toLowerCase().includes("send")) ||
        (btn.className && typeof btn.className === "string" && btn.className.toLowerCase().includes("send"));

      if (!isSendAction) return;

      const input = findAssociatedInputElement(btn);
      if (!input) return;

      const text = getTargetText(input);
      if (!text || text.trim().length < 2) return;

      const analysis = evaluateToxicitySync(text);
      if (analysis.isToxic) {
        e.preventDefault();
        e.stopPropagation();
        e.stopImmediatePropagation();
        renderOutboundBlockModal(analysis, input);
        return false;
      }
    };

    // Capture on pointerdown, mousedown, and click to beat fast single-page app listeners (e.g. WhatsApp, React)
    window.addEventListener("pointerdown", handleSendActionTrigger, true);
    window.addEventListener("mousedown", handleSendActionTrigger, true);
    window.addEventListener("click", handleSendActionTrigger, true);
    document.addEventListener("click", handleSendActionTrigger, true);
  }

  // Synchronized Fallback Toxicity Evaluator (Uses full SVO grammar engine)
  function clientAnalyzeToxicityLocal(text) {
    const analysis = evaluateToxicitySync(text);
    return {
      toxicity_score: analysis.score,
      toxicity_level: analysis.level,
      safety_actions: analysis.score >= 35 ? [
        "Block the sender on messaging platforms.",
        "Capture screenshot evidence.",
        "Report to platform moderators."
      ] : ["Content is safe."]
    };
  }



  // 8. Message Handler from Popup for Highlighted Text Scan
  chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
    if (msg.action === "SCAN_SELECTED_TEXT") {
      const selected = window.getSelection().toString().trim();
      if (!selected) {
        alert("CyberShield AI: Please highlight text on this page first to scan for cyberbullying!");
        return;
      }

      // Quick local fallback + async background check
      chrome.runtime.sendMessage({ action: "CHECK_TOXICITY", text: selected }, (res) => {
        if (res && res.status === "success") {
          alert(`CyberShield AI Toxicity Analysis:\n\nSeverity: ${res.toxicity_level}\nScore: ${res.toxicity_score}/100\nRecommendation: ${res.safety_actions?.[0] || "Content is safe."}`);
          if (res.toxicity_score >= 35) {
            chrome.runtime.sendMessage({
              action: "RECORD_EXTENSION_INCIDENT",
              incident: {
                id: "bully_sel_" + Date.now(),
                title: `Toxic Content Flagged (${res.toxicity_level})`,
                module: "Cyberbullying Detection",
                target: currentHostname || "Highlighted Text",
                date: "Just now",
                severity: res.toxicity_score >= 70 ? "Critical" : "High",
                status: "Flagged",
                link: "cyberbullying-detection.html"
              }
            });
          }
        } else {
          const fallback = clientAnalyzeToxicityLocal(selected);
          alert(`CyberShield AI Toxicity Analysis:\n\nSeverity: ${fallback.toxicity_level}\nScore: ${fallback.toxicity_score}/100\nRecommendation: ${fallback.safety_actions[0]}`);
          if (fallback.toxicity_score >= 35) {
            chrome.runtime.sendMessage({
              action: "RECORD_EXTENSION_INCIDENT",
              incident: {
                id: "bully_sel_" + Date.now(),
                title: `Toxic Content Flagged (${fallback.toxicity_level})`,
                module: "Cyberbullying Detection",
                target: currentHostname || "Highlighted Text",
                date: "Just now",
                severity: "Medium",
                status: "Flagged",
                link: "cyberbullying-detection.html"
              }
            });
          }
        }
      });
    }

    if (msg.action === "UPDATE_STATUS") {
      updatePageBadge(msg.riskLevel, msg.score);
    }

    // Live Broadcast from Background to Injected Web Portal Page
    if (msg.action === "EXTENSION_INCIDENT_BROADCAST") {
      window.postMessage({
        type: "CYBERSHIELD_EXTENSION_INCIDENT",
        incident: msg.incident,
        telemetry: msg.telemetry
      }, "*");
      if (window.CyberShieldState && typeof window.CyberShieldState.recordExtensionIncident === "function") {
        window.CyberShieldState.recordExtensionIncident(msg.incident, false);
      }
    }
  });

  // 9. Real-Time Telemetry Bridge: Connects Web App (Dashboard & AI Report) to Extension
  try {
    const rawState = localStorage.getItem("cybershield_shared_state_v1");
    if (rawState) {
      const parsed = JSON.parse(rawState);
      chrome.storage.local.set({ platformTelemetry: parsed });
    }
  } catch (e) {}

  window.addEventListener("cybershield-state-changed", (event) => {
    try {
      if (event && event.detail) {
        chrome.storage.local.set({ platformTelemetry: event.detail });
      }
    } catch (e) {}
  });

  window.addEventListener("storage", (event) => {
    try {
      if (event.key === "cybershield_shared_state_v1" && event.newValue) {
        chrome.storage.local.set({ platformTelemetry: JSON.parse(event.newValue) });
      }
    } catch (e) {}
  });
})();

