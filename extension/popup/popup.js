// CyberShield AI — Extension Popup Controller
// Owner: Shreya

const BACKEND_URLS = [
  "https://cybershield-ai-rlk5.onrender.com",
  "http://localhost:5000"
];

let activeBackendUrl = BACKEND_URLS[0];

document.addEventListener("DOMContentLoaded", async () => {
  await resolveBackend();
  initActiveTab();
  setupEventListeners();
  loadCachedState();
});

// Check if live cloud backend or local development backend is reachable
async function resolveBackend() {
  const healthDot = document.getElementById("backendHealthDot");
  for (const url of BACKEND_URLS) {
    try {
      const res = await fetch(`${url}/api/health`, { method: "GET" });
      if (res.ok) {
        activeBackendUrl = url;
        if (healthDot) {
          healthDot.innerText = url.includes("render") ? "API: Cloud Live" : "API: Local 5000";
          healthDot.style.color = "#10b981";
        }
        return;
      }
    } catch (e) {
      // Continue to fallback
    }
  }
  if (healthDot) {
    healthDot.innerText = "API: Offline";
    healthDot.style.color = "#f87171";
  }
}

// Read current active tab in Chrome
function initActiveTab() {
  if (typeof chrome !== "undefined" && chrome.tabs && chrome.tabs.query) {
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      if (tabs && tabs[0]) {
        const currentUrl = tabs[0].url || "";
        renderUrlInfo(currentUrl);
        scanUrl(currentUrl);
      }
    });
  } else {
    // Fallback for standalone preview
    const sampleUrl = window.location.href;
    renderUrlInfo(sampleUrl);
  }
}

function renderUrlInfo(urlStr) {
  const urlDisplay = document.getElementById("activeUrlDisplay");
  const protocolBadge = document.getElementById("protocolBadge");

  if (!urlDisplay) return;
  urlDisplay.innerText = urlStr || "Unknown URL";

  if (urlStr.startsWith("https://")) {
    protocolBadge.innerText = "HTTPS";
    protocolBadge.className = "protocol-badge safe";
  } else if (urlStr.startsWith("http://")) {
    protocolBadge.innerText = "HTTP";
    protocolBadge.className = "protocol-badge danger";
  } else {
    protocolBadge.innerText = "INTERNAL";
    protocolBadge.className = "protocol-badge";
  }
}

// Call Shreya's Phishing Detection API
async function scanUrl(urlStr) {
  if (!urlStr || urlStr.startsWith("chrome://") || urlStr.startsWith("edge://")) {
    updateGauge(0, "SYSTEM PAGE (SAFE)", "safe", ["Browser internal page is protected."]);
    return;
  }

  const verdictText = document.getElementById("threatVerdictText");
  verdictText.innerText = "SCANNING...";
  verdictText.className = "verdict-text";

  try {
    const response = await fetch(`${activeBackendUrl}/api/detect/phishing`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ target: urlStr })
    });

    const result = await response.json();

    if (result.status === "success") {
      const score = result.risk_score || 0;
      let statusType = "safe";
      if (score >= 45) statusType = "danger";
      else if (score >= 20) statusType = "warning";

      updateGauge(score, result.risk_level, statusType, result.flags || []);

      // Notify content script to inject alert banner if dangerous
      if (score >= 45 && typeof chrome !== "undefined" && chrome.tabs) {
        chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
          if (tabs[0]?.id) {
            chrome.tabs.sendMessage(tabs[0].id, {
              action: "SHOW_BANNER",
              threatLevel: result.risk_level,
              score: score,
              reason: result.flags[0] || "Suspicious domain detected"
            }).catch(() => {});
          }
        });
      }
    } else {
      updateGauge(0, "ERROR SCANNING", "warning", ["Could not complete scan."]);
    }
  } catch (err) {
    updateGauge(0, "OFFLINE CACHE", "warning", ["Using local heuristic cache; server unreachable."]);
  }
}

function updateGauge(score, verdictLabel, statusType, flags) {
  const bar = document.getElementById("threatGaugeBar");
  const verdictText = document.getElementById("threatVerdictText");
  const scoreNum = document.getElementById("threatScoreNumber");
  const list = document.getElementById("indicatorsList");

  if (bar) {
    bar.style.width = `${Math.max(5, score)}%`;
    bar.style.backgroundColor = statusType === "danger" ? "#ef4444" : (statusType === "warning" ? "#f59e0b" : "#10b981");
  }

  if (verdictText) {
    verdictText.innerText = verdictLabel;
    verdictText.className = `verdict-text ${statusType}`;
  }

  if (scoreNum) {
    scoreNum.innerText = `${score} / 100`;
  }

  if (list) {
    list.innerHTML = "";
    if (!flags || flags.length === 0) {
      flags = ["No critical security flags detected."];
    }
    flags.forEach((f) => {
      const li = document.createElement("li");
      li.className = `indicator-item ${statusType}`;
      li.innerHTML = `<span class="ind-icon">${statusType === "danger" ? "✕" : (statusType === "warning" ? "!" : "✓")}</span><span class="ind-text">${f}</span>`;
      list.appendChild(li);
    });
  }
}

function setupEventListeners() {
  // Re-scan button
  const scanBtn = document.getElementById("scanCurrentPageBtn");
  if (scanBtn) {
    scanBtn.addEventListener("click", () => {
      initActiveTab();
    });
  }

  // Toxic Text Check CTA
  const toxicBtn = document.getElementById("checkSelectionBtn");
  if (toxicBtn) {
    toxicBtn.addEventListener("click", () => {
      if (typeof chrome !== "undefined" && chrome.tabs) {
        chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
          if (tabs[0]?.id) {
            chrome.tabs.sendMessage(tabs[0].id, { action: "SCAN_SELECTED_TEXT" });
          }
        });
      }
    });
  }

  // Open Full Web Dashboard
  const dashBtn = document.getElementById("openDashboardBtn");
  if (dashBtn) {
    dashBtn.addEventListener("click", () => {
      const url = `${activeBackendUrl}/pages/dashboard.html`;
      if (typeof chrome !== "undefined" && chrome.tabs) {
        chrome.tabs.create({ url });
      } else {
        window.open(url, "_blank");
      }
    });
  }

  // Open Settings
  const setBtn = document.getElementById("openSettingsBtn");
  if (setBtn) {
    setBtn.addEventListener("click", () => {
      const url = `${activeBackendUrl}/pages/settings.html`;
      if (typeof chrome !== "undefined" && chrome.tabs) {
        chrome.tabs.create({ url });
      } else {
        window.open(url, "_blank");
      }
    });
  }
}

// Read persisted settings/session from chrome.storage
function loadCachedState() {
  if (typeof chrome !== "undefined" && chrome.storage && chrome.storage.local) {
    chrome.storage.local.get(["userSession", "identityScore"], (data) => {
      if (data.userSession?.name) {
        const nameLabel = document.getElementById("userNameLabel");
        if (nameLabel) nameLabel.innerText = data.userSession.name;
      }
      if (data.identityScore) {
        const trustPill = document.getElementById("identityTrustPill");
        if (trustPill) trustPill.innerText = `Trust: ${data.identityScore}%`;
      }
    });
  }
}
