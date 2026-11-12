// CyberShield AI — Content Script (Injected DOM Security Guard)
// Owner: Shreya
// Features: Live URL Badges, Warning Banners, Toxic Text Blur, Password Strength Tips

(function () {
  const currentUrl = window.location.href;
  if (!currentUrl.startsWith("http://") && !currentUrl.startsWith("https://") && !currentUrl.startsWith("file://")) return;

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

  // 3. Scan Current Webpage URL via Background Service Worker
  function scanActivePage() {
    chrome.runtime.sendMessage({ action: "CHECK_PHISHING", url: currentUrl }, (res) => {
      if (res && res.status === "success") {
        updatePageBadge(res.risk_level, res.risk_score);
        if (res.risk_score >= 45) {
          renderTopWarningBanner(res.risk_level, res.risk_score, res.flags?.[0]);
        }
      }
    });
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

  // 6. Blur or Warn on Toxic Text (Social Media & Forums - Multi-Class Behavioral Taxonomy)
  function scanPageForToxicContent() {
    const toxicPatterns = [
      // 1. Extreme Threats & Violence
      "kill yourself", "kill you", "should kill you", "i will kill you", "kill you with",
      "i will find you", "go die", "should die", "hope you die", "deserve to die",
      "worthless piece of trash", "destroy you", "beat you", "hurt you", "slit your", "burn you", "murder", "end your life",
      // 2. Insults & Humiliation
      "idiot", "loser", "shut up", "ugly", "hate you", "pathetic", "dumbest",
      "complete joke", "nobody takes you seriously", "embarrassing", "laughs at you behind",
      "stop talking", "waste of space", "brainless", "incompetent", "clown",
      // 3. Social Exclusion & Ostracization
      "don't invite her", "don't invite him", "don't invite them", "nobody wants her around",
      "nobody wants him around", "nobody wants you around", "nobody wants you here",
      "no one wants you around", "no one wants you here", "no one likes you", "nobody likes you",
      "make a group without", "ignore all his messages", "ignore all her messages",
      "ignore all their messages", "unfollow this person", "they don't belong here",
      "you don't belong here", "nobody asked you", "leave this group", "get out of here",
      // 4. Body Shaming & Appearance Ridicule
      "looking like that", "look ridiculous", "look disgusting", "hide your face",
      "wear clothes like that", "your appearance is the reason", "you look horrible",
      "lose some weight", "so fat", "ugly face", "gross body",
      // 5. Digital Intimidation, Harassment & Stalking
      "keep messaging you until", "to your reputation", "make your life miserable",
      "delete your account", "can't escape", "disappear from this platform",
      "i'll make your life miserable", "i will make your life miserable",
      "watch your back", "track your ip", "you will pay for this", "ruin your life",
      "ruin your future", "hunt you down", "stalk",
      // 6. Defamation, Rumours & Doxing
      "spread this rumour", "spread this rumor", "embarrassing picture",
      "fake account just to expose", "fake account to expose", "expose you",
      "everyone should see this embarrassing", "share this post so everyone can laugh",
      "leak your private", "dox you",
      // 7. Profanity & Slurs
      "bitch", "bastard", "fuck", "shit", "asshole"
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

    element.onclick = (e) => {
      e.stopPropagation();
      element.style.filter = "none";
      element.style.backgroundColor = "transparent";
      element.title = "Revealed content";
    };
  }

  // 7. Real-Time Password Strength Tips in Password Fields
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
        } else {
          const fallback = clientAnalyzeToxicityLocal(selected);
          alert(`CyberShield AI Toxicity Analysis:\n\nSeverity: ${fallback.toxicity_level}\nScore: ${fallback.toxicity_score}/100\nRecommendation: ${fallback.safety_actions[0]}`);
        }
      });
    }

    if (msg.action === "UPDATE_STATUS") {
      updatePageBadge(msg.riskLevel, msg.score);
    }
  });
})();
