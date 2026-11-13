// CyberShield AI — Content Script (Injected DOM Security Guard & Analyzer Bridge)
// Features: Live URL Badges, Warning Banners, Toxic Text Blur, Password Security & Real-Time Telemetry

(function () {
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

  let config = { autoScan: true, toxicBlur: true, passwordTips: true };

  // 1. Always render corner protection badge immediately
  renderPageBadge("SAFE", 0);

  // 2. Initialize configuration from extension storage and run guards
  chrome.storage.local.get(["autoScan", "toxicBlur", "passwordTips"], (items) => {
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
  });

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
        <a href="http://localhost:5000/pages/security-analyzer.html?domain=${encodeURIComponent(currentHostname)}&type=domain" target="_blank" style="flex:1; text-align:center; background:linear-gradient(110deg,#6350f4,#7b6bff); color:#fff; text-decoration:none; padding:6px 10px; border-radius:6px; font-size:10px; font-weight:700; box-shadow:0 3px 10px rgba(99,80,244,0.3);">
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

  // 4. In-Page Visual Badge (Safe / Suspicious / Dangerous)
  function renderPageBadge(riskLevel, score) {
    if (document.getElementById("cybershield-corner-badge")) return;

    const badge = document.createElement("div");
    badge.id = "cybershield-corner-badge";
    badge.title = `CyberShield AI: ${riskLevel} (${score}/100)`;
    badge.style.cssText = `
      position: fixed;
      bottom: 20px;
      right: 20px;
      background: #0f172a;
      color: #f1f5f9;
      border: 1px solid #10b981;
      padding: 6px 14px;
      border-radius: 20px;
      font-size: 11px;
      font-weight: 700;
      display: flex;
      align-items: center;
      gap: 6px;
      z-index: 2147483647;
      box-shadow: 0 4px 16px rgba(0,0,0,0.6);
      cursor: pointer;
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
    `;
    badge.innerHTML = `<span id="cs-badge-dot" style="color:#10b981; font-size:12px;">●</span> <span id="cs-badge-text">Secure</span>`;
    badge.onclick = () => {
      alert(`CyberShield AI Verdict:\n\nStatus: ${riskLevel}\nRisk Score: ${score}/100\nDomain: ${window.location.hostname || "Local file"}\n\nAll real-time client defense modules active.`);
    };
    document.body.appendChild(badge);
  }

  function updatePageBadge(riskLevel, score) {
    const badge = document.getElementById("cybershield-corner-badge");
    const dot = document.getElementById("cs-badge-dot");
    const text = document.getElementById("cs-badge-text");
    if (!badge || !dot || !text) {
      renderPageBadge(riskLevel, score);
      return;
    }

    const isDanger = score >= 45;
    const isWarning = score >= 20 && score < 45;
    const badgeColor = isDanger ? "#ef4444" : (isWarning ? "#f59e0b" : "#10b981");
    const badgeText = isDanger ? "Threat Alert" : (isWarning ? "Caution" : "Secure");

    badge.style.borderColor = badgeColor;
    dot.style.color = badgeColor;
    text.innerText = badgeText;
    badge.title = `CyberShield AI: ${riskLevel} (${score}/100)`;
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
  function scanPageForToxicContent() {
    const toxicPatterns = [
      "kill yourself", "i will find you", "go die", "worthless piece of trash",
      "idiot", "loser", "shut up", "ugly", "destroy you", "hate you", "pathetic"
    ];

    // Method A: Check leaf block/inline elements
    const elements = document.querySelectorAll("p, span, div, li, blockquote, td");
    elements.forEach((el) => {
      if (el.id === "cybershield-corner-badge" || el.closest("#cybershield-corner-badge")) return;
      if (el.children.length === 0 || (el.children.length === 1 && (el.firstElementChild.tagName === "EM" || el.firstElementChild.tagName === "STRONG"))) {
        const text = (el.innerText || el.textContent || "").toLowerCase();
        if (text.length >= 8) {
          for (const pattern of toxicPatterns) {
            if (text.includes(pattern)) {
              applyToxicBlur(el);
              break;
            }
          }
        }
      }
    });

    // Method B: Selective TreeWalker for plain text nodes
    const walker = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT, null, false);
    let node;
    while ((node = walker.nextNode())) {
      if (node.nodeValue && node.nodeValue.length > 8 && node.parentElement && node.parentElement.tagName !== "SCRIPT" && node.parentElement.tagName !== "STYLE") {
        const valLower = node.nodeValue.toLowerCase();
        for (const pattern of toxicPatterns) {
          if (valLower.includes(pattern)) {
            applyToxicBlur(node.parentElement);
            break;
          }
        }
      }
    }
  }

  function applyToxicBlur(element) {
    if (element.hasAttribute("data-cybershield-blurred")) return;
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

            // If Moderate, Weak, or Breached, suggest high-strength variations formed around the user's characters!
            if (!isHigh) {
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

  // Instant fallback toxicity evaluator if background takes time
  function clientAnalyzeToxicityLocal(text) {
    const t_lower = (text || "").toLowerCase().trim();
    const insult_words = ["stupid", "idiot", "loser", "ugly", "fat", "dumb", "hate you", "freak", "trash", "worthless", "pathetic"];
    const harass_words = ["kill yourself", "die", "go die", "nobody likes you", "shut up", "get a life", "creep", "stalk"];
    const threat_words = ["i will find you", "beat you", "hurt you", "destroy you", "track your ip", "expose you"];
    const profanity_words = ["bitch", "bastard", "fuck", "shit", "asshole"];

    let score = 0;
    const flagged = [];

    insult_words.forEach(w => { if (t_lower.includes(w)) { score += 25; flagged.push(w); } });
    harass_words.forEach(w => { if (t_lower.includes(w)) { score += 40; flagged.push(w); } });
    threat_words.forEach(w => { if (t_lower.includes(w)) { score += 50; flagged.push(w); } });
    profanity_words.forEach(w => { if (t_lower.includes(w)) { score += 15; flagged.push(w); } });

    score = Math.min(score, 100);
    let level = "SAFE / NON-TOXIC CONTENT";
    if (score >= 70) level = "HIGHLY TOXIC / SEVERE HARASSMENT";
    else if (score >= 35) level = "MODERATE TOXICITY DETECTED";

    return {
      toxicity_score: score,
      toxicity_level: level,
      safety_actions: score >= 35 ? ["Block the sender on messaging platforms.", "Capture screenshot evidence.", "Report to platform moderators."] : ["Content is safe."]
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
