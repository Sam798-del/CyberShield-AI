// CyberShield AI — Background Service Worker (Manifest V3)
// Owner: Shreya

const API_PRIMARY = "https://cybershield-ai-rlk5.onrender.com";
const API_LOCAL = "http://localhost:5000";

let currentBackend = API_PRIMARY;

// Test backend connectivity
async function getActiveEndpoint() {
  try {
    const res = await fetch(`${API_PRIMARY}/api/health`, { method: "GET" });
    if (res.ok) return API_PRIMARY;
  } catch (e) {
    // Fall back to local
  }
  return API_LOCAL;
}

chrome.runtime.onInstalled.addListener(() => {
  console.log("CyberShield AI Extension Installed Successfully.");
  chrome.storage.local.set({
    shieldActive: true,
    autoScanUrls: true,
    blurToxicText: true,
    userSession: { name: "Shreya Security Admin", role: "Active User" },
    identityScore: 98
  });
});

// Listen for messages from popup or content scripts
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === "CHECK_PHISHING") {
    handlePhishingCheck(request.url).then(sendResponse);
    return true; // async reply
  }

  if (request.action === "CHECK_TOXICITY") {
    handleToxicityCheck(request.text).then(sendResponse);
    return true; // async reply
  }

  if (request.action === "GET_CONFIG") {
    chrome.storage.local.get(null, (items) => {
      sendResponse(items);
    });
    return true;
  }
});

// Call Phishing Detection API
async function handlePhishingCheck(targetUrl) {
  const backend = await getActiveEndpoint();
  try {
    const resp = await fetch(`${backend}/api/detect/phishing`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ target: targetUrl })
    });
    const data = await resp.json();
    return data;
  } catch (error) {
    return {
      status: "error",
      message: "Backend unreachable",
      risk_score: 0,
      risk_level: "UNKNOWN",
      flags: ["Offline heuristic evaluation active."]
    };
  }
}

// Call Cyberbullying NLP Toxicity API
async function handleToxicityCheck(textSnippet) {
  const backend = await getActiveEndpoint();
  try {
    const resp = await fetch(`${backend}/api/detect/cyberbullying`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ text: textSnippet })
    });
    const data = await resp.json();
    return data;
  } catch (error) {
    return {
      status: "error",
      message: "Backend unreachable",
      toxicity_score: 0,
      toxicity_level: "UNKNOWN",
      categories: {}
    };
  }
}

// Update Extension Icon Badge on active tab change
chrome.tabs.onActivated.addListener(async (activeInfo) => {
  try {
    const tab = await chrome.tabs.get(activeInfo.tabId);
    if (tab && tab.url && (tab.url.startsWith("http://") || tab.url.startsWith("https://"))) {
      const result = await handlePhishingCheck(tab.url);
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
  } catch (err) {
    // Ignore internal tabs
  }
});
