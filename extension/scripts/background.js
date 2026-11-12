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
    const response = await fetch(`${endpoint}/api/detect/phishing`, {
      method: "POST",
      headers: headers,
      body: JSON.stringify({ target: url })
    });
    return await response.json();
  } catch (err) {
    // Offline heuristic fallback
    return {
      status: "success",
      target: url,
      risk_score: url.startsWith("http://") ? 25 : 0,
      risk_level: url.startsWith("http://") ? "MODERATE CAUTION" : "SAFE / LOW RISK",
      flags: url.startsWith("http://") ? ["Unencrypted HTTP connection"] : ["Standard URL syntax"]
    };
  }
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
    const response = await fetch(`${endpoint}/api/detect/cyberbullying`, {
      method: "POST",
      headers: headers,
      body: JSON.stringify({ text: text })
    });
    return await response.json();
  } catch (err) {
    return {
      status: "error",
      message: "Backend offline",
      toxicity_score: 0,
      toxicity_level: "SAFE"
    };
  }
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
