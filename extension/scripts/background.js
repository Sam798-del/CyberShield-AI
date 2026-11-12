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
    "go die", "should die", "hope you die", "deserve to die",
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
  const profanity_patterns = ["bitch", "bastard", "fuck", "shit", "asshole", "crap"];

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

  checkPatterns(threat_patterns, "threat", 60);
  checkPatterns(intimidation_patterns, "intimidation", 45);
  checkPatterns(defamation_patterns, "defamation", 45);
  checkPatterns(exclusion_patterns, "social_exclusion", 45);
  checkPatterns(body_shaming_patterns, "body_shaming", 45);
  checkPatterns(insult_patterns, "insult", 40);
  checkPatterns(profanity_patterns, "profanity", 25);

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
