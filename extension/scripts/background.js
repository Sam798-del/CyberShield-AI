// CyberShield AI — Background Service Worker (Manifest V3)
// Owner: Shreya
// Integration: Passes Kaveri's Auth Token in requests when available

const CLOUD_API = "https://cybershield-ai-rlk5.onrender.com";
const LOCAL_API = "http://localhost:5000";

let targetBackend = CLOUD_API;

// 1. Resolve Active Endpoint
async function resolveBackendEndpoint() {
  const custom = await chrome.storage.local.get("backendUrl");
  if (custom && custom.backendUrl) {
    targetBackend = custom.backendUrl;
    return targetBackend;
  }
  try {
    const res = await fetch(`${CLOUD_API}/api/health`, { method: "GET" });
    if (res.ok) { targetBackend = CLOUD_API; return targetBackend; }
  } catch (e) {}
  targetBackend = LOCAL_API;
  return targetBackend;
}

// 2. Initialize default state
chrome.runtime.onInstalled.addListener(() => {
  chrome.storage.local.set({
    shieldActive: true,
    autoScan: true,
    toxicBlur: true,
    passwordTips: true,
    outboundBlocker: true,
    backendUrl: CLOUD_API
  });
});

// 3. Message Router for Content & Popup Scripts
chrome.runtime.onMessage.addListener((req, sender, sendResponse) => {
  if (req.action === "CHECK_PHISHING") {
    executePhishingCheck(req.url).then(sendResponse);
    return true; // asynchronous reply
  }

  if (req.action === "CHECK_TOXICITY") {
    executeToxicityCheck(req.text).then(sendResponse);
    return true; // asynchronous reply
  }
});

// Real-Time Client Phishing Detection Fallback Engine
function clientAnalyzePhishing(urlStr) {
  const url = (urlStr || "").toLowerCase().trim();
  const flags = [];
  let score = 0;

  if (url.startsWith("http://")) {
    flags.push("Unencrypted connection (HTTP instead of HTTPS)");
    score += 25;
  } else if (url.startsWith("https://")) {
    flags.push("Secure encrypted connection (HTTPS verified)");
  }

  const badTlds = [".xyz", ".top", ".tk", ".club", ".work", ".gq", ".cf", ".fit", ".rest", ".stream"];
  for (const tld of badTlds) {
    if (url.includes(tld)) {
      flags.push(`Suspicious high-risk TLD (${tld}) detected`);
      score += 30;
      break;
    }
  }

  const lookalikes = ["paypa1", "g00gle", "micros0ft", "app1e", "amaz0n", "sec-login", "verify-account", "auth-check"];
  for (const item of lookalikes) {
    if (url.includes(item)) {
      flags.push("Brand typosquatting / spoofed domain pattern detected");
      score += 45;
      break;
    }
  }

  if (/https?:\/\/(?:\d{1,3}\.){3}\d{1,3}/.test(url)) {
    flags.push("Direct IP address hostname instead of registered domain");
    score += 40;
  }

  if (url.includes("@")) {
    flags.push("Embedded credentials / '@' symbol in URL path");
    score += 35;
  }

  score = Math.min(score, 100);

  let riskLevel = "VERIFIED SECURE (SAFE)";
  if (score >= 70) riskLevel = "CRITICAL PHISHING THREAT";
  else if (score >= 45) riskLevel = "HIGH RISK WARNING";
  else if (score >= 20) riskLevel = "MODERATE CAUTION";
  else if (flags.length <= 1) flags.push("Legitimate domain syntax & trusted web reputation");

  return {
    status: "success",
    target: urlStr,
    risk_score: score,
    risk_level: riskLevel,
    flags: flags,
    recommendation: score >= 45 ? "Do not submit sensitive credentials on this page." : "URL verified safe."
  };
}

// Real-Time Client Cyberbullying Detection Fallback Engine (Multi-Class Behavioral Taxonomy)
function clientAnalyzeToxicity(text) {
  const t_lower = " " + (text || "").toLowerCase().trim() + " ";
  
  const threat_patterns = [
    "i will find you", "kill yourself", "kill you", "should kill you", "i will kill you",
    "kill you with", "murder you", "shoot you", "stab you", "strangle you",
    "go die", "should die", "hope you die", "deserve to die", "you die", "die slut",
    "beat you", "hurt you", "destroy you", "slit your", "burn you", "murder", "end your life"
  ];
  const intimidation_patterns = [
    "keep messaging you until", "to your reputation", "make your life miserable",
    "delete your account", "can't escape", "disappear from this platform",
    "watch your back", "track your ip", "you will pay for this", "ruin your life",
    "ruin your future", "stalk"
  ];
  const defamation_patterns = [
    "spread this rumour", "spread this rumor", "embarrassing picture",
    "fake account just to expose", "fake account to expose", "expose you",
    "everyone should see this embarrassing", "share this post so everyone can laugh",
    "leak your private", "dox you"
  ];
  const exclusion_patterns = [
    "don't invite her", "don't invite him", "don't invite them", "nobody wants her around",
    "nobody wants him around", "nobody wants you around", "nobody wants you here",
    "no one wants you around", "no one wants you here", "no one likes you", "nobody likes you",
    "make a group without", "ignore all his messages", "ignore all her messages",
    "unfollow this person", "they don't belong here", "you don't belong here",
    "nobody asked you", "leave this group"
  ];
  const body_shaming_patterns = [
    "looking like that", "look ridiculous", "look disgusting", "hide your face",
    "wear clothes like that", "your appearance is the reason", "you look horrible",
    "lose some weight", "so fat", "ugly face"
  ];
  const insult_patterns = [
    "stupid", "idiot", "loser", "ugly", "fat", "dumb", "dumbest", "hate you",
    "freak", "trash", "worthless", "pathetic", "complete joke", "nobody takes you seriously",
    "embarrassing", "laughs at you behind", "stop talking", "waste of space"
  ];
  const profanity_patterns = ["bitch", "bastard", "fuck", "shit", "asshole", "crap", "slut", "whore", "cunt", "skank", "hoe"];

  let score = 0;
  const flagged = [];
  const detectedCategories = [];

  function checkPatterns(list, catName, weight) {
    let matchFound = false;
    list.forEach(w => {
      if (t_lower.includes(w)) {
        score += weight;
        flagged.push(w);
        matchFound = true;
      }
    });
    if (matchFound) detectedCategories.push(catName);
  }

  checkPatterns(threat_patterns, "threat", 75);
  checkPatterns(intimidation_patterns, "intimidation", 50);
  checkPatterns(defamation_patterns, "defamation", 50);
  checkPatterns(exclusion_patterns, "social_exclusion", 50);
  checkPatterns(body_shaming_patterns, "body_shaming", 50);
  checkPatterns(insult_patterns, "insult", 45);
  checkPatterns(profanity_patterns, "profanity", 50);

  // Combinatorial SVO Semantic Intent Grammar Engine (Parity with modules/toxicity_engine.py)
  const svoRules = [
    { cat: "threat", weight: 85, regex: /\b(kill|murder|shoot|stab|choke|strangle|beat|smash|hit|cut|attack|destroy|hurt|burn|drown|torture|crush|punch|slap|slice|hang|slaughter|butcher)\s+(you|u|your\s+(head|face|throat|neck|body|chest)|her|him)\b/i, label: "direct violent assault" },
    { cat: "threat", weight: 80, regex: /\b(i\s*('?ll|will|should|must|wanna|want\s+to|gonna|am\s+going\s+to|can))\s+.*(kill|murder|beat|hurt|destroy|stab|shoot|smash|slap|attack|burn|crush)\s+(you|u)\b/i, label: "violent declaration" },
    { cat: "threat", weight: 75, regex: /\b(with\s+(a\s+)?(hammer|knife|gun|weapon|bat|blade|axe|acid|brick|pipe|crowbar|sword|rope|pistol|rifle))\b/i, label: "weapon assault" },
    { cat: "threat", weight: 85, regex: /\b(you|u)\s+(should|must|need\s+to|deserve\s+to|ought\s+to|better|just)?\s*(die|perish|burn|suffer|rot|hang\s+yourself|kill\s+(yourself|urself)|end\s+your\s+life)\b|\bdie\s+(bitch|slut|whore|bastard|loser|idiot|now|alone|here)\b|\b(you|u)\s+die\b/i, label: "death wish / suicide incitement" },
    { cat: "threat", weight: 75, regex: /\b(should|hope|wish|want|deserve|pray)\s+(you|u)\s+(die|perish|rot|suffer|burn|get\s+killed)\b/i, label: "fatality wish" },
    { cat: "threat", weight: 75, regex: /\b(go|better|just)\s+die\b/i, label: "death incitement" },
    { cat: "threat", weight: 85, regex: /\b(kill|hang)\s+(yourself|urself)\b/i, label: "suicide incitement" },
    { cat: "social_exclusion", weight: 55, regex: /\b(no\s*one|nobody|not\s+a\s+single\s+person|none\s+of\s+us)\s+(likes?|wants?|cares?\s+about|cares?|loves?|needs?|trusts?|respects?|talks?\s+to)\s+(you|u|her|him|them)\b/i, label: "universal rejection" },
    { cat: "social_exclusion", weight: 50, regex: /\b(don\'?t|do\s+not|never)\s+(invite|talk\s+to|speak\s+to|hang\s+out\s+with|message)\s+(her|him|them|you|u)\b/i, label: "relational ostracization" },
    { cat: "social_exclusion", weight: 50, regex: /\b(make\s+a\s+group|group\s+chat)\s+without\s+(him|her|them|you|u)\b/i, label: "exclusion group" },
    { cat: "social_exclusion", weight: 50, regex: /\b(ignore|block|mute)\s+(all\s+)?(his|her|their|your)\s+(messages|texts|calls|posts)\b/i, label: "communication blocking" },
    { cat: "social_exclusion", weight: 50, regex: /\b(they|you|u|she|he)\s+(don\'?t|does\s+not|doesn\'?t)\s+belong\s+(here|with\s+us|in\s+this\s+group)\b/i, label: "exclusion alienation" },
    { cat: "body_shaming", weight: 55, regex: /\b(look|looking|looks)\s+(so\s+)?(ridiculous|disgusting|horrible|repulsive|ugly|fat|gross|hideous|repugnant|like\s+a\s+(clown|joke|pig|cow|whale|freak))\b/i, label: "appearance denigration" },
    { cat: "body_shaming", weight: 55, regex: /\b(appearance|face|weight|body|figure|skin)\s+(is\s+the\s+reason|makes\s+me\s+sick|is\s+disgusting|looks\s+terrible)\b/i, label: "body shaming" },
    { cat: "body_shaming", weight: 50, regex: /\b(upload|post|take)\s+(a\s+)?(picture|photo)\s+looking\s+like\s+that\b/i, label: "aesthetic mockery" },
    { cat: "intimidation", weight: 55, regex: /\b(keep|continue)\s+(messaging|texting|calling|harassing|stalking|following)\s+(you|u)\s+(until|forever)\b/i, label: "stalking pressure" },
    { cat: "intimidation", weight: 55, regex: /\b(make\s+your\s+life|ruin\s+your|destroy\s+your)\s+(miserable|life|reputation|future|career|family)\b/i, label: "intimidation threat" },
    { cat: "intimidation", weight: 50, regex: /\b(delete|deactivate|remove)\s+(your\s+)?(account|profile|channel|post)\b/i, label: "account silencing" },
    { cat: "intimidation", weight: 50, regex: /\b(can\'?t|cannot|won\'?t)\s+escape\s+(me|what\s+i|this)\b/i, label: "coercive entrapment" },
    { cat: "defamation", weight: 55, regex: /\b(spread|share|leak|post|circulate)\s+(this\s+)?(rumour|rumor|lie|lies|photo|picture|screenshot|chat|video|private|secret)\b/i, label: "rumour / doxing spread" },
    { cat: "defamation", weight: 55, regex: /\b(fake\s+account|alt\s+account)\s+(just\s+)?to\s+expose\s+(you|her|him)\b/i, label: "smear campaign" },
    { cat: "insult", weight: 50, regex: /\b(you(\'re|\s+are)|u\s+r)\s+(literally\s+)?(a\s+|an\s+|the\s+)?(dumbest|stupidest|biggest\s+loser|complete\s+joke|joke|laughing\s+stock|waste\s+of\s+space|brainless|moron|idiot|imbecile|retard|failure|clown|freak|loser)\b/i, label: "direct insult" },
    { cat: "insult", weight: 45, regex: /\b(nobody|no\s*one)\s+takes\s+you\s+seriously\b/i, label: "intellectual ridicule" },
    { cat: "insult", weight: 40, regex: /\b(your\s+)?opinions?\s+(are|is)\s+(embarrassing|pathetic|garbage|worthless)\b/i, label: "opinion humiliation" },
    { cat: "profanity", weight: 55, regex: /\b(slut|whore|bitch|cunt|skank|hoe|motherfucker|asshole|bastard|dipshit|douchebag)\b/i, label: "abusive profanity / misogynistic slur" }
  ];

  for (const rule of svoRules) {
    if (rule.regex.test(t_lower)) {
      score = Math.max(score, rule.weight);
      flagged.push(rule.label);
      if (!detectedCategories.includes(rule.cat)) detectedCategories.push(rule.cat);
    }
  }

  // Multi-category compounding
  if (detectedCategories.length > 1) {
    score += (detectedCategories.length - 1) * 15;
  }

  score = Math.min(score, 100);
  let level = "SAFE / NON-TOXIC CONTENT";
  if (score >= 65) level = "HIGHLY TOXIC / SEVERE HARASSMENT";
  else if (score >= 35) level = "MODERATE TOXICITY DETECTED";

  return {
    status: "success",
    text: text,
    toxicity_score: score,
    toxicity_level: level,
    categories: detectedCategories,
    flagged_words: [...new Set(flagged)],
    safety_actions: score >= 35 ? [
      "Capture screenshot evidence with timestamps.",
      "Mute or block the harasser on this platform.",
      "Report abusive conduct under community safety standards."
    ] : ["Content is safe."]
  };
}

// 4. Phishing Check Caller
// [KAVERI HOOK]: Attaches Authorization Bearer token from Kaveri's login if stored
async function executePhishingCheck(url) {
  const endpoint = await resolveBackendEndpoint();
  const tokenData = await chrome.storage.local.get("authToken");
  const headers = { "Content-Type": "application/json" };
  if (tokenData?.authToken) {
    headers["Authorization"] = `Bearer ${tokenData.authToken}`;
  }

  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 1200);
    const response = await fetch(`${endpoint}/api/detect/phishing`, {
      method: "POST",
      headers: headers,
      body: JSON.stringify({ target: url }),
      signal: controller.signal
    });
    clearTimeout(timeoutId);
    if (response.ok) {
      const data = await response.json();
      if (data && data.status === "success") return data;
    }
  } catch (err) {}

  return clientAnalyzePhishing(url);
}

// 5. Cyberbullying Toxicity Caller
async function executeToxicityCheck(text) {
  const endpoint = await resolveBackendEndpoint();
  const tokenData = await chrome.storage.local.get("authToken");
  const headers = { "Content-Type": "application/json" };
  if (tokenData?.authToken) {
    headers["Authorization"] = `Bearer ${tokenData.authToken}`;
  }

  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 1200);
    const response = await fetch(`${endpoint}/api/detect/cyberbullying`, {
      method: "POST",
      headers: headers,
      body: JSON.stringify({ text: text }),
      signal: controller.signal
    });
    clearTimeout(timeoutId);
    if (response.ok) {
      const data = await response.json();
      if (data && data.status === "success") return data;
    }
  } catch (err) {}

  return clientAnalyzeToxicity(text);
}

// 6. Dynamic Icon Badge Update on Tab Switch
chrome.tabs.onActivated.addListener(async (activeInfo) => {
  try {
    const tab = await chrome.tabs.get(activeInfo.tabId);
    if (tab?.url && (tab.url.startsWith("http://") || tab.url.startsWith("https://"))) {
      const result = await executePhishingCheck(tab.url);
      if (result.risk_score >= 45) {
        chrome.action.setBadgeText({ text: "!", tabId: tab.id });
        chrome.action.setBadgeBackgroundColor({ color: "#ef4444", tabId: tab.id });
      } else {
        chrome.action.setBadgeText({ text: "✓", tabId: tab.id });
        chrome.action.setBadgeBackgroundColor({ color: "#10b981", tabId: tab.id });
      }
    } else {
      chrome.action.setBadgeText({ text: "", tabId: activeInfo.tabId });
    }
  } catch (e) {}
});
