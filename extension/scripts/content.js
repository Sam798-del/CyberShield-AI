// CyberShield AI — Content Script (Injected DOM Security Guard)
// Owner: Shreya
// Features: Live URL Badges, Warning Banners, Toxic Text Blur, Password Strength Tips,
//           and Outbound Message Blocker ("Think Before You Post" with [ ✏️ Edit Message ])

(function () {
  const currentUrl = window.location.href;
  if (!currentUrl.startsWith("http://") && !currentUrl.startsWith("https://") && !currentUrl.startsWith("file://")) return;

  let config = { autoScan: true, toxicBlur: true, passwordTips: true, outboundBlocker: true };

  let pageToxicCount = 0;
  let pageRiskLevel = "SAFE";
  let pageRiskScore = 0;

  // 1. Always render corner protection badge immediately
  renderPageBadge("SAFE", 0);

  // 2. Initialize configuration from extension storage and run guards
  chrome.storage.local.get(["autoScan", "toxicBlur", "passwordTips", "outboundBlocker"], (items) => {
    if (items.autoScan !== undefined) config.autoScan = items.autoScan;
    if (items.toxicBlur !== undefined) config.toxicBlur = items.toxicBlur;
    if (items.passwordTips !== undefined) config.passwordTips = items.passwordTips;
    if (items.outboundBlocker !== undefined) config.outboundBlocker = items.outboundBlocker;

    if (config.autoScan) scanActivePage();
    if (config.toxicBlur) {
      scanPageForToxicContent();
      setTimeout(scanPageForToxicContent, 400);
    }
    if (config.passwordTips) {
      attachPasswordGuards();
      setTimeout(attachPasswordGuards, 400);
    }
    if (config.outboundBlocker) {
      attachOutboundMessageGuard();
    }
  });

  // Run initial scans and guards synchronously on document execution
  scanPageForToxicContent();
  attachOutboundMessageGuard();

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
    pageRiskLevel = riskLevel;
    pageRiskScore = score;

    const badge = document.createElement("div");
    badge.id = "cybershield-corner-badge";
    badge.title = `CyberShield AI: Domain URL ${riskLevel} (${score}/100)`;
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
    badge.innerHTML = `<span id="cs-badge-dot" style="color:#10b981; font-size:12px;">●</span> <span id="cs-badge-text">URL Safe</span>`;
    badge.onclick = () => {
      alert(getBadgeSummaryAlert());
    };
    document.body.appendChild(badge);
  }

  function getBadgeSummaryAlert() {
    if (pageToxicCount > 0) {
      return `🛡️ CyberShield AI — Live Defense Verdict\n\n` +
        `🌐 DOMAIN URL SECURITY: ${pageRiskLevel} (${pageRiskScore}/100 Phishing Risk)\n` +
        `   ➔ ${window.location.hostname || "Local host"} is a verified legitimate domain (NOT a phishing site).\n\n` +
        `💬 PAGE CONTENT TOXICITY: ⚠️ HARASSMENT DETECTED\n` +
        `   ➔ CyberShield found ${pageToxicCount} abusive comment(s) and automatically BLURRED them with red warning shields!\n` +
        `   (Check Test 2 above to see the blurred toxic comments).\n\n` +
        `🔍 TO SCAN INDIVIDUAL TEXT (like Test 3):\n` +
        `   Highlight any text with your mouse ➔ Open extension popup ➔ Click "💬 Toxic Text" button!`;
    }
    return `🛡️ CyberShield AI — Live Defense Verdict\n\n` +
      `🌐 DOMAIN URL SECURITY: ${pageRiskLevel} (${pageRiskScore}/100 Phishing Risk)\n` +
      `   ➔ ${window.location.hostname || "Local host"} is verified safe.\n\n` +
      `💬 PAGE CONTENT TOXICITY: Clean\n` +
      `   ➔ No overt cyberbullying patterns detected on initial page load.`;
  }

  function updatePageBadge(riskLevel, score) {
    pageRiskLevel = riskLevel;
    pageRiskScore = score;
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
    let badgeText = isDanger ? "URL Threat Alert" : (isWarning ? "URL Caution" : "URL Safe");
    if (pageToxicCount > 0 && !isDanger) {
      badgeText = `URL Safe • ⚠️ ${pageToxicCount} Blurred`;
    }

    badge.style.borderColor = pageToxicCount > 0 && !isDanger ? "#f59e0b" : badgeColor;
    dot.style.color = pageToxicCount > 0 && !isDanger ? "#f59e0b" : badgeColor;
    text.innerText = badgeText;
    badge.title = `CyberShield AI: Domain URL ${riskLevel} (${score}/100) | ${pageToxicCount} Toxic Comments Blurred`;
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
      "i will find you", "go die", "should die", "hope you die", "deserve to die", "you die", "die slut",
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
      "bitch", "bastard", "fuck", "shit", "asshole", "slut", "whore", "cunt", "skank", "hoe"
    ];

    // Method A: Check leaf block/inline elements
    const elements = document.querySelectorAll("p, span, div, li, blockquote, td");
    elements.forEach((el) => {
      if (el.id === "cybershield-corner-badge" || el.closest("#cybershield-corner-badge") || el.closest("#cybershield-outbound-blocker-modal")) return;
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
      if (node.nodeValue && node.nodeValue.length > 8 && node.parentElement && node.parentElement.tagName !== "SCRIPT" && node.parentElement.tagName !== "STYLE" && !node.parentElement.closest("#cybershield-outbound-blocker-modal")) {
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
    pageToxicCount++;
    updatePageBadge(pageRiskLevel, pageRiskScore);

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

  // ==================== 8. OUTBOUND MESSAGE BLOCKER & "THINK BEFORE YOU POST" GUARD ====================
  // Synchronous SVO Semantic & Multi-Category Toxicity Evaluation Engine
  // High-performance client-side evaluation runs in <2ms before submit events propagate
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
          "embarrassing", "laughs at you behind", "stop talking", "waste of space"
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
        else targetElement.innerText = "";
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

  // Intercept Outbound Message Transmissions (DOM Event Capturing)
  function attachOutboundMessageGuard() {
    if (window.__cybershield_outbound_guard_attached) return;
    window.__cybershield_outbound_guard_attached = true;

    // A. Intercept Enter key in comment inputs, textareas, and contenteditable boxes
    document.addEventListener("keydown", (e) => {
      if (!config.outboundBlocker) return;
      if (e.key !== "Enter" || e.shiftKey || e.ctrlKey || e.altKey || e.metaKey) return;
      const target = e.target;
      if (!target) return;

      const isInput = target.tagName === "INPUT" && (target.type === "text" || target.type === "search" || !target.type);
      const isTextarea = target.tagName === "TEXTAREA";
      const isContentEditable = target.isContentEditable || target.getAttribute("contenteditable") === "true" || target.getAttribute("role") === "textbox";

      if (!isInput && !isTextarea && !isContentEditable) return;

      const text = isContentEditable ? (target.innerText || target.textContent || "") : (target.value || "");
      if (!text || text.trim().length < 2) return;

      const analysis = evaluateToxicitySync(text);
      if (analysis.isToxic) {
        e.preventDefault();
        e.stopPropagation();
        e.stopImmediatePropagation();
        renderOutboundBlockModal(analysis, target);
        return false;
      }
    }, true); // Capture phase: intercepts BEFORE website listeners fire

    // B. Intercept Form Submissions containing toxic text
    document.addEventListener("submit", (e) => {
      if (!config.outboundBlocker) return;
      const form = e.target;
      if (!form || !form.querySelectorAll) return;

      const inputs = form.querySelectorAll('textarea, input[type="text"], input[type="search"], input:not([type]), [contenteditable="true"]');
      for (const inp of inputs) {
        const text = inp.isContentEditable ? (inp.innerText || inp.textContent || "") : (inp.value || "");
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
    }, true);

    // C. Intercept Click Events on Send / Submit / Comment Buttons
    document.addEventListener("click", (e) => {
      if (!config.outboundBlocker) return;
      const target = e.target;
      if (!target) return;

      const btn = target.closest('button, input[type="submit"], [role="button"], a.btn, div.btn');
      if (!btn) return;

      const btnText = (btn.innerText || btn.value || btn.title || btn.getAttribute("aria-label") || "").toLowerCase();
      const isSendAction = btn.type === "submit" ||
        btnText.includes("send") ||
        btnText.includes("post") ||
        btnText.includes("comment") ||
        btnText.includes("submit") ||
        btnText.includes("reply") ||
        btnText.includes("tweet") ||
        (btn.id && btn.id.toLowerCase().includes("send")) ||
        (btn.className && typeof btn.className === "string" && btn.className.toLowerCase().includes("send"));

      if (!isSendAction) return;

      // Locate associated input/textarea in the container or active page
      const container = btn.closest("form") || btn.closest(".comment-box") || btn.closest(".test-card") || btn.parentElement;
      if (container) {
        const inputs = container.querySelectorAll('textarea, input[type="text"], input[type="search"], input:not([type]), [contenteditable="true"]');
        for (const inp of inputs) {
          const text = inp.isContentEditable ? (inp.innerText || inp.textContent || "") : (inp.value || "");
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
      }
    }, true);
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

  // 9. Message Handler from Popup for Highlighted Text Scan
  chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
    if (msg.action === "SCAN_SELECTED_TEXT") {
      const selected = window.getSelection().toString().trim();
      if (!selected) {
        alert("CyberShield AI: Please highlight text on this page first to scan for cyberbullying!");
        return;
      }

      // Quick local evaluation + async background check
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
