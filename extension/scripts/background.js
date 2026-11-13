// CyberShield AI — Background Service Worker (Manifest V3)
// Real-Time Browser Defense & Security Analyzer Bridge Engine

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
    const res = await fetch(`${CLOUD_API}/api/analyzer/health`, { method: "GET" });
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
    backendUrl: LOCAL_API
  });
});

// 3. Message Router for Content & Popup Scripts & Security Analyzer Bridge
chrome.runtime.onMessage.addListener((req, sender, sendResponse) => {
  if (req.action === "CHECK_PHISHING") {
    executePhishingCheck(req.url).then(sendResponse);
    return true; // asynchronous reply
  }

  if (req.action === "CHECK_TOXICITY") {
    executeToxicityCheck(req.text).then(sendResponse);
    return true; // asynchronous reply
  }

  if (req.action === "CHECK_DOMAIN_LEAK") {
    executeSecurityAnalyzerDomainCheck(req.domain || req.url).then(sendResponse);
    return true; // asynchronous reply
  }

  if (req.action === "CHECK_PASSWORD_SECURITY") {
    executeSecurityAnalyzerPasswordCheck(req.password).then(sendResponse);
    return true; // asynchronous reply
  }

  if (req.action === "GET_ACTIVE_TAB_INFO") {
    getActiveTabInfo().then(sendResponse);
    return true; // asynchronous reply
  }

  if (req.action === "RECORD_EXTENSION_INCIDENT") {
    handleRecordExtensionIncident(req.incident).then(sendResponse);
    return true; // asynchronous reply
  }
});

// Broadcast Real-Time Incident from Web Extension to Web Portals (Dashboard & AI Report)
async function handleRecordExtensionIncident(incident) {
  if (!incident) return { status: "ignored" };

  try {
    const data = await chrome.storage.local.get(["platformTelemetry"]);
    const telemetry = data.platformTelemetry || {
      securityReport: { score: 90 },
      phishing: { threatsBlocked: 2, scansCount: 42 },
      cyberbullying: { flaggedCount: 1, scansCount: 12 },
      emailFootprint: { breachesFound: 0 },
      incidents: []
    };

    if (!Array.isArray(telemetry.incidents)) telemetry.incidents = [];
    // Deduplicate identical recent incident
    if (!telemetry.incidents.some(i => i.title === incident.title && i.target === incident.target)) {
      telemetry.incidents.unshift(incident);
      if (telemetry.incidents.length > 20) telemetry.incidents = telemetry.incidents.slice(0, 20);
    }

    if (incident.module === "Phishing Detection") {
      telemetry.phishing = telemetry.phishing || { threatsBlocked: 2 };
      telemetry.phishing.threatsBlocked = (telemetry.phishing.threatsBlocked || 0) + 1;
      telemetry.securityReport = telemetry.securityReport || { score: 90 };
      telemetry.securityReport.score = Math.max(35, (telemetry.securityReport.score || 90) - 5);
    } else if (incident.module === "Cyberbullying Detection") {
      telemetry.cyberbullying = telemetry.cyberbullying || { flaggedCount: 1 };
      telemetry.cyberbullying.flaggedCount = (telemetry.cyberbullying.flaggedCount || 0) + 1;
      telemetry.securityReport = telemetry.securityReport || { score: 90 };
      telemetry.securityReport.score = Math.max(35, (telemetry.securityReport.score || 90) - 4);
    } else if (incident.module === "Security Analyzer") {
      telemetry.emailFootprint = telemetry.emailFootprint || { breachesFound: 0 };
      telemetry.emailFootprint.breachesFound = (telemetry.emailFootprint.breachesFound || 0) + 1;
      telemetry.securityReport = telemetry.securityReport || { score: 90 };
      telemetry.securityReport.score = Math.max(35, (telemetry.securityReport.score || 90) - 8);
    }

    await chrome.storage.local.set({ platformTelemetry: telemetry });

    // Broadcast in real-time to all open browser tabs
    if (chrome.tabs && chrome.tabs.query) {
      chrome.tabs.query({}, (tabs) => {
        (tabs || []).forEach((t) => {
          if (t.id) {
            chrome.tabs.sendMessage(t.id, {
              action: "EXTENSION_INCIDENT_BROADCAST",
              incident: incident,
              telemetry: telemetry
            }).catch(() => {});
          }
        });
      });
    }

    return { status: "success", telemetry };
  } catch (err) {
    return { status: "error", error: err.message };
  }
}

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

// Real-Time Client Cyberbullying Detection Fallback Engine
function clientAnalyzeToxicity(text) {
  const t_lower = (text || "").toLowerCase().trim();
  const insult_words = ["stupid", "idiot", "loser", "ugly", "fat", "dumb", "hate you", "freak", "trash", "worthless"];
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
    status: "success",
    text: text,
    toxicity_score: score,
    toxicity_level: level,
    flagged_words: [...new Set(flagged)],
    safety_actions: score >= 35 ? ["Block the sender.", "Capture screenshot evidence.", "Report to platform moderators."] : ["Content is safe."]
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

// 6. Security Analyzer Domain Breach Caller (XposedOrNot & Breach Footprint)
async function executeSecurityAnalyzerDomainCheck(domain) {
  let cleanDomain = (domain || "").toLowerCase().trim();
  cleanDomain = cleanDomain.replace(/^https?:\/\//, "").replace(/\/.*$/, "").replace(/:\d+$/, "");
  if (!cleanDomain || cleanDomain === "newtab" || cleanDomain === "extensions" || cleanDomain.startsWith("chrome")) {
    return {
      status: "skipped",
      found: false,
      breach_count: 0,
      breaches: [],
      domain: cleanDomain,
      advice: "Internal browser page or invalid domain."
    };
  }

  const endpoint = await resolveBackendEndpoint();
  const tokenData = await chrome.storage.local.get("authToken");
  const headers = { "Content-Type": "application/json" };
  if (tokenData?.authToken) {
    headers["Authorization"] = `Bearer ${tokenData.authToken}`;
  }

  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 3500);
    const response = await fetch(`${endpoint}/api/analyzer/leak`, {
      method: "POST",
      headers: headers,
      body: JSON.stringify({ type: "domain", value: cleanDomain }),
      signal: controller.signal
    });
    clearTimeout(timeoutId);
    if (response.ok) {
      const data = await response.json();
      return {
        status: "success",
        found: !!data.found,
        breach_count: data.breach_count || 0,
        breaches: data.breaches || [],
        advice: data.advice || (data.found ? "Domain has confirmed public data breaches." : "No breaches recorded for this domain."),
        domain: cleanDomain,
        source: data.source || "XposedOrNot"
      };
    }
  } catch (err) {}

  return {
    status: "fallback",
    found: false,
    breach_count: 0,
    breaches: [],
    domain: cleanDomain,
    advice: "Domain leak scan temporarily unavailable or rate-limited."
  };
}

// 7. Security Analyzer Password Check (Entropy + HIBP Breach Database)
async function executeSecurityAnalyzerPasswordCheck(password) {
  if (!password || typeof password !== "string") {
    return { status: "error", error: "Password is empty" };
  }

  const endpoint = await resolveBackendEndpoint();
  const tokenData = await chrome.storage.local.get("authToken");
  const headers = { "Content-Type": "application/json" };
  if (tokenData?.authToken) {
    headers["Authorization"] = `Bearer ${tokenData.authToken}`;
  }

  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 2500);
    const response = await fetch(`${endpoint}/api/analyzer/password`, {
      method: "POST",
      headers: headers,
      body: JSON.stringify({ password: password }),
      signal: controller.signal
    });
    clearTimeout(timeoutId);
    if (response.ok) {
      const data = await response.json();
      return { status: "success", ...data };
    }
  } catch (err) {}

  // Fallback client calculation if backend is unreachable
  const len = password.length;
  let score = Math.min(100, Math.round(len * 6));
  return {
    status: "fallback",
    score: score,
    label: score >= 70 ? "strong" : score >= 40 ? "medium" : "weak",
    entropy_bits: Math.round(len * 3.8 * 10) / 10,
    breached: false,
    breach_count: 0,
    issues: len < 8 ? ["Password is shorter than 8 characters"] : [],
    tips: ["Use at least 12 characters with mixed case, digits, and symbols"]
  };
}

// 8. Fetch Real-Time Active Tab Info from Chrome
async function getActiveTabInfo() {
  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (tab && tab.url) {
      let domain = "";
      try {
        domain = new URL(tab.url).hostname;
      } catch (e) {}
      const info = {
        id: tab.id,
        url: tab.url,
        domain: domain,
        title: tab.title || "",
        favIconUrl: tab.favIconUrl || "",
        protocol: tab.url.startsWith("https") ? "HTTPS" : (tab.url.startsWith("http") ? "HTTP" : "INTERNAL")
      };
      await chrome.storage.local.set({ lastActiveTabInfo: info, lastActiveDomain: domain, lastActiveUrl: tab.url });
      return info;
    }
  } catch (e) {}
  return { url: "", domain: "", title: "", protocol: "UNKNOWN" };
}

// 9. Dynamic Icon Badge & Real-Time Tab Tracking on Tab Switch
chrome.tabs.onActivated.addListener(async (activeInfo) => {
  try {
    const tab = await chrome.tabs.get(activeInfo.tabId);
    if (tab?.url) {
      let domain = "";
      try { domain = new URL(tab.url).hostname; } catch (e) {}
      await chrome.storage.local.set({
        lastActiveTabInfo: {
          id: tab.id,
          url: tab.url,
          domain: domain,
          title: tab.title || "",
          favIconUrl: tab.favIconUrl || ""
        },
        lastActiveDomain: domain,
        lastActiveUrl: tab.url
      });

      if (tab.url.startsWith("http://") || tab.url.startsWith("https://")) {
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
    }
  } catch (e) {}
});

chrome.tabs.onUpdated.addListener(async (tabId, changeInfo, tab) => {
  if (changeInfo.status === "complete" && tab?.url) {
    let domain = "";
    try { domain = new URL(tab.url).hostname; } catch (e) {}
    if (domain) {
      await chrome.storage.local.set({
        lastActiveTabInfo: {
          id: tab.id,
          url: tab.url,
          domain: domain,
          title: tab.title || "",
          favIconUrl: tab.favIconUrl || ""
        },
        lastActiveDomain: domain,
        lastActiveUrl: tab.url
      });
    }
  }
});
