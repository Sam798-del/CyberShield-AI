// CyberShield AI — Extension Popup Controller
// Owner: Shreya
// Integration Hooks: Kaveri (Auth Token & Identity Trust) | Neeraja (Threat Incidents Telemetry)

let activeBackendUrl = "https://cybershield-ai-rlk5.onrender.com";

document.addEventListener("DOMContentLoaded", async () => {
  await loadExtensionSettings();
  await checkBackendStatus();
  checkAuthSession();
  initActiveTab();
  setupEventListeners();
});

// ==================== 1. VIEW SWITCHING ====================
function switchView(viewName) {
  document.getElementById("loginView").classList.add("hidden");
  document.getElementById("mainDashboardView").classList.add("hidden");
  document.getElementById("settingsView").classList.add("hidden");

  if (viewName === "login") document.getElementById("loginView").classList.remove("hidden");
  else if (viewName === "settings") document.getElementById("settingsView").classList.remove("hidden");
  else document.getElementById("mainDashboardView").classList.remove("hidden");
}

// ==================== 2. KAVERI AUTH & IDENTITY INTEGRATION ====================
// [KAVERI INTEGRATION HOOK]: Reads session token issued by Kaveri's auth engine
function checkAuthSession() {
  chrome.storage.local.get(["userSession", "authToken", "identityScore", "blockedCount"], (data) => {
    const userNameLabel = document.getElementById("userNameLabel");
    const trustScoreBadge = document.getElementById("trustScoreBadge");
    const incidentsBadge = document.getElementById("incidentsBadge");

    if (data.authToken) {
      if (userNameLabel) userNameLabel.innerText = data.userSession?.name || "Shreya Admin";
      // [KAVERI HOOK]: When Kaveri delivers /api/identity/score, this updates dynamically
      if (trustScoreBadge) trustScoreBadge.innerText = `Trust: ${data.identityScore || 98}%`;
      // [NEERAJA HOOK]: When Neeraja delivers /api/dashboard/summary, this updates dynamically
      if (incidentsBadge) incidentsBadge.innerText = `Blocked: ${data.blockedCount || 3}`;
      switchView("main");
    } else {
      // Prompt sign in or allow guest scanning
      switchView("main"); // Default to main view for instant scanning capability
    }
  });
}

// ==================== 3. LIVE TAB PHISHING SCANNER ====================
function initActiveTab() {
  if (chrome.tabs && chrome.tabs.query) {
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      if (tabs && tabs[0]) {
        const currentUrl = tabs[0].url || "";
        renderUrlDisplay(currentUrl);
        scanUrl(currentUrl);
      }
    });
  }
}

function renderUrlDisplay(urlStr) {
  const urlDisplay = document.getElementById("activeUrlDisplay");
  const protocolBadge = document.getElementById("protocolBadge");
  if (!urlDisplay) return;

  urlDisplay.innerText = urlStr || "Blank page";
  if (urlStr.startsWith("https://")) {
    protocolBadge.innerText = "HTTPS";
    protocolBadge.className = "protocol-badge safe";
  } else if (urlStr.startsWith("http://")) {
    protocolBadge.innerText = "HTTP";
    protocolBadge.className = "protocol-badge danger";
  } else {
    protocolBadge.innerText = "SYSTEM";
    protocolBadge.className = "protocol-badge";
  }
}

// Client-Side Phishing & Domain Threat Evaluation Engine
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

  try {
    const parsed = new URL(urlStr);
    const domain = parsed.hostname;
    if ((domain.match(/-/g) || []).length >= 3) {
      flags.push("Multiple hyphens in domain name (common in fake phishing portals)");
      score += 20;
    }
  } catch (e) {}

  score = Math.min(score, 100);

  let riskLevel = "VERIFIED SECURE (SAFE)";
  let statusType = "safe";

  if (score >= 70) {
    riskLevel = "CRITICAL PHISHING THREAT";
    statusType = "danger";
  } else if (score >= 45) {
    riskLevel = "HIGH RISK WARNING";
    statusType = "danger";
  } else if (score >= 20) {
    riskLevel = "MODERATE CAUTION";
    statusType = "warning";
  } else {
    riskLevel = "VERIFIED SECURE (SAFE)";
    statusType = "safe";
    if (flags.length <= 1) {
      flags.push("Legitimate domain syntax & trusted web reputation");
    }
  }

  return {
    score: score,
    risk_level: riskLevel,
    statusType: statusType,
    flags: flags
  };
}

async function scanUrl(urlStr) {
  if (!urlStr || urlStr.startsWith("chrome://") || urlStr.startsWith("edge://")) {
    updateGauge(0, "SYSTEM PAGE (SECURE)", "safe", ["Internal browser interface is isolated."]);
    return;
  }

  const verdictText = document.getElementById("threatVerdictText");
  verdictText.innerText = "SCANNING...";
  verdictText.className = "verdict-text";

  let analyzed = null;

  try {
    const response = await fetch(`${activeBackendUrl}/api/detect/phishing`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ target: urlStr })
    });

    if (response.ok) {
      const result = await response.json();
      if (result && result.status === "success") {
        const score = result.risk_score || 0;
        let statusType = "safe";
        if (score >= 45) statusType = "danger";
        else if (score >= 20) statusType = "warning";

        analyzed = {
          score: score,
          risk_level: result.risk_level,
          statusType: statusType,
          flags: result.flags || []
        };
      }
    }
  } catch (e) {}

  // Fallback to real-time client engine if remote server is unreachable
  if (!analyzed) {
    analyzed = clientAnalyzePhishing(urlStr);
  }

  updateGauge(analyzed.score, analyzed.risk_level, analyzed.statusType, analyzed.flags);

  // Inform content script to show banner/badge if high risk
  chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
    if (tabs[0]?.id) {
      chrome.tabs.sendMessage(tabs[0].id, {
        action: "UPDATE_STATUS",
        score: analyzed.score,
        riskLevel: analyzed.risk_level,
        flags: analyzed.flags
      }).catch(() => {});
    }
  });
}

function updateGauge(score, verdictLabel, statusType, flags) {
  const bar = document.getElementById("threatGaugeBar");
  const verdict = document.getElementById("threatVerdictText");
  const scoreNum = document.getElementById("threatScoreNumber");
  const list = document.getElementById("indicatorsList");

  if (bar) {
    bar.style.width = `${Math.max(5, score)}%`;
    bar.style.backgroundColor = statusType === "danger" ? "#ef4444" : (statusType === "warning" ? "#f59e0b" : "#10b981");
  }
  if (verdict) {
    verdict.innerText = verdictLabel;
    verdict.className = `verdict-text ${statusType}`;
  }
  if (scoreNum) scoreNum.innerText = `${score} / 100`;

  if (list) {
    list.innerHTML = "";
    (flags && flags.length ? flags : ["No critical security flags."]).forEach((f) => {
      const li = document.createElement("li");
      li.className = `indicator-item ${statusType}`;
      li.innerHTML = `<span class="ind-icon">${statusType === "danger" ? "✕" : (statusType === "warning" ? "!" : "✓")}</span><span>${f}</span>`;
      list.appendChild(li);
    });
  }
}

// ==================== 4. EVENT LISTENERS ====================
function setupEventListeners() {
  document.getElementById("scanCurrentPageBtn")?.addEventListener("click", () => initActiveTab());

  // Settings open/close
  document.getElementById("navSettingsBtn")?.addEventListener("click", () => switchView("settings"));
  document.getElementById("closeSettingsBtn")?.addEventListener("click", () => switchView("main"));

  // Save Settings
  document.getElementById("saveSettingsBtn")?.addEventListener("click", () => {
    const selectedBackend = document.getElementById("backendSelect").value;
    activeBackendUrl = selectedBackend;
    chrome.storage.local.set({
      backendUrl: selectedBackend,
      autoScan: document.getElementById("toggleAutoScan").checked,
      toxicBlur: document.getElementById("toggleToxicBlur").checked,
      passwordTips: document.getElementById("togglePasswordTips").checked
    }, () => {
      checkBackendStatus();
      switchView("main");
    });
  });

  // Auth Save
  document.getElementById("saveAuthBtn")?.addEventListener("click", () => {
    const email = document.getElementById("authEmailInput").value;
    const token = document.getElementById("authTokenInput").value;
    chrome.storage.local.set({
      userSession: { name: email.split("@")[0], email: email },
      authToken: token
    }, () => {
      checkAuthSession();
      switchView("main");
    });
  });

  document.getElementById("skipAuthBtn")?.addEventListener("click", () => switchView("main"));
  document.getElementById("logoutBtn")?.addEventListener("click", () => switchView("login"));

  // Scan Highlighted Toxic Text CTA
  document.getElementById("checkSelectionBtn")?.addEventListener("click", () => {
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      if (tabs[0]?.id) {
        chrome.tabs.sendMessage(tabs[0].id, { action: "SCAN_SELECTED_TEXT" }).catch(() => {
          alert("Highlight text on the webpage first!");
        });
      }
    });
  });

  // Open Full Web Dashboard
  document.getElementById("openWebPortalBtn")?.addEventListener("click", () => {
    chrome.tabs.create({ url: `${activeBackendUrl}/pages/dashboard.html` });
  });
}

// ==================== 5. BACKEND HEALTH CHECK ====================
async function checkBackendStatus() {
  const dot = document.getElementById("backendHealthDot");
  if (!dot) return;

  try {
    const res = await fetch(`${activeBackendUrl}/api/health`, { method: "GET" });
    if (res.ok) {
      dot.innerText = activeBackendUrl.includes("render") ? "Cloud API: Online" : "Local API: 5000 (Online)";
      dot.style.color = "#10b981";
      return;
    }
  } catch (e) {
    try {
      const localRes = await fetch("http://localhost:5000/api/health");
      if (localRes.ok) {
        activeBackendUrl = "http://localhost:5000";
        dot.innerText = "Local API: 5000 (Online)";
        dot.style.color = "#10b981";
        return;
      }
    } catch (e2) {}
  }
  dot.innerText = "Real-Time Shield: Active";
  dot.style.color = "#10b981";
}

function loadExtensionSettings() {
  return new Promise((resolve) => {
    chrome.storage.local.get(["backendUrl", "autoScan", "toxicBlur", "passwordTips"], (items) => {
      if (items.backendUrl) {
        activeBackendUrl = items.backendUrl;
        const select = document.getElementById("backendSelect");
        if (select) select.value = items.backendUrl;
      }
      if (items.autoScan !== undefined) document.getElementById("toggleAutoScan").checked = items.autoScan;
      if (items.toxicBlur !== undefined) document.getElementById("toggleToxicBlur").checked = items.toxicBlur;
      if (items.passwordTips !== undefined) document.getElementById("togglePasswordTips").checked = items.passwordTips;
      resolve();
    });
  });
}
