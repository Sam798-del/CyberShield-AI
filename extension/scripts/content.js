// CyberShield AI — Content Script (Injected DOM Security Guard)
// Owner: Shreya
// Features: Live URL Badges, Warning Banners, Toxic Text Blur, Password Strength Tips

(function () {
  const currentUrl = window.location.href;
  if (!currentUrl.startsWith("http://") && !currentUrl.startsWith("https://") && !currentUrl.startsWith("file://")) return;

  let config = { autoScan: true, toxicBlur: true, passwordTips: true };

  // 1. Initialize configuration from extension storage
  chrome.storage.local.get(["autoScan", "toxicBlur", "passwordTips"], (items) => {
    if (items.autoScan !== undefined) config.autoScan = items.autoScan;
    if (items.toxicBlur !== undefined) config.toxicBlur = items.toxicBlur;
    if (items.passwordTips !== undefined) config.passwordTips = items.passwordTips;

    if (config.autoScan) scanActivePage();
    if (config.toxicBlur) scanPageForToxicContent();
    if (config.passwordTips) attachPasswordGuards();
  });

  // 2. Scan Current Webpage URL via Background Service Worker
  function scanActivePage() {
    chrome.runtime.sendMessage({ action: "CHECK_PHISHING", url: currentUrl }, (res) => {
      if (res && res.status === "success") {
        renderPageBadge(res.risk_level, res.risk_score);
        if (res.risk_score >= 45) {
          renderTopWarningBanner(res.risk_level, res.risk_score, res.flags?.[0]);
        }
      }
    });
  }

  // 3. In-Page Visual Badge (Safe / Suspicious / Dangerous)
  function renderPageBadge(riskLevel, score) {
    if (document.getElementById("cybershield-corner-badge")) return;

    const isDanger = score >= 45;
    const isWarning = score >= 20 && score < 45;
    const badgeColor = isDanger ? "#ef4444" : (isWarning ? "#f59e0b" : "#10b981");
    const badgeText = isDanger ? "Threat Alert" : (isWarning ? "Caution" : "Secure");

    const badge = document.createElement("div");
    badge.id = "cybershield-corner-badge";
    badge.title = `CyberShield AI: ${riskLevel} (${score}/100)`;
    badge.style.cssText = `
      position: fixed;
      bottom: 20px;
      right: 20px;
      background: #0f172a;
      color: #f1f5f9;
      border: 1px solid ${badgeColor};
      padding: 6px 12px;
      border-radius: 20px;
      font-size: 11px;
      font-weight: 700;
      display: flex;
      align-items: center;
      gap: 6px;
      z-index: 2147483640;
      box-shadow: 0 4px 12px rgba(0,0,0,0.5);
      cursor: pointer;
      font-family: -apple-system, BlinkMacSystemFont, sans-serif;
    `;
    badge.innerHTML = `<span style="color:${badgeColor}">●</span> ${badgeText}`;
    badge.onclick = () => {
      alert(`CyberShield AI Verdict:\n\nStatus: ${riskLevel}\nRisk Score: ${score}/100\nDomain: ${window.location.hostname}`);
    };
    document.body.appendChild(badge);
  }

  // 4. Top Floating Warning Banner for Critical Threats
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

  // 5. Blur or Warn on Toxic Text (Social Media & Forums)
  function scanPageForToxicContent() {
    const toxicPatterns = [
      "kill yourself", "i will find you", "go die", "worthless piece of trash",
      "idiot", "loser", "shut up", "ugly", "destroy you", "hate you"
    ];
    const textNodes = [];

    // Fast selective DOM tree walk for paragraphs & comments
    const walker = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT, null, false);
    let node;
    while ((node = walker.nextNode())) {
      if (node.nodeValue && node.nodeValue.length > 10 && node.parentElement.tagName !== "SCRIPT" && node.parentElement.tagName !== "STYLE") {
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
    element.style.filter = "blur(5px)";
    element.style.cursor = "pointer";
    element.title = "CyberShield AI: Potentially toxic harassment hidden. Click to reveal.";
    element.onclick = (e) => {
      e.stopPropagation();
      element.style.filter = "none";
      element.title = "Revealed content";
    };
  }

  // 6. Real-Time Password Strength Tips in Password Fields
  // [Neeraja Integration Hook: Connects to Neeraja's Password Entropy & Breach APIs]
  function attachPasswordGuards() {
    document.querySelectorAll('input[type="password"]').forEach((input) => {
      if (input.hasAttribute("data-cybershield-guarded")) return;
      input.setAttribute("data-cybershield-guarded", "true");

      const tipBox = document.createElement("div");
      tipBox.style.cssText = `
        display: none;
        font-family: -apple-system, sans-serif;
        font-size: 11px;
        color: #94a3b8;
        background: #0f172a;
        border: 1px solid #334155;
        border-radius: 6px;
        padding: 6px 10px;
        margin-top: 4px;
        z-index: 10000;
        box-shadow: 0 4px 10px rgba(0,0,0,0.3);
      `;

      input.parentElement.appendChild(tipBox);

      input.addEventListener("focus", () => { tipBox.style.display = "block"; });
      input.addEventListener("blur", () => { tipBox.style.display = "none"; });

      input.addEventListener("input", () => {
        const pwd = input.value;
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
          <div style="display:flex; justify-content:space-between; margin-bottom:3px;">
            <span>🛡️ CyberShield Health:</span>
            <strong style="color:${color}">${strength}</strong>
          </div>
          <div style="font-size:10px; color:#64748b;">Min 12+ chars, uppercase, digits & symbols for high entropy.</div>
        `;
      });
    });
  }

  // 7. Message Handler from Popup for Highlighted Text Scan
  chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
    if (msg.action === "SCAN_SELECTED_TEXT") {
      const selected = window.getSelection().toString().trim();
      if (!selected) {
        alert("CyberShield AI: Please highlight text on this page first to scan for cyberbullying!");
        return;
      }
      chrome.runtime.sendMessage({ action: "CHECK_TOXICITY", text: selected }, (res) => {
        if (res && res.status === "success") {
          const isHarmful = res.toxicity_score >= 35;
          alert(`CyberShield AI Toxicity Analysis:\n\nSeverity: ${res.toxicity_level}\nScore: ${res.toxicity_score}/100\nRecommendation: ${res.safety_actions?.[0] || "Content is safe."}`);
        }
      });
    }

    if (msg.action === "UPDATE_STATUS") {
      renderPageBadge(msg.riskLevel, msg.score);
    }
  });
})();
