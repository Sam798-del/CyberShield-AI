// CyberShield AI — Content Script (Injected DOM Guard)
// Owner: Shreya

(function () {
  console.log("CyberShield AI Content Script loaded on:", window.location.href);

  // 1. Automatic Live Page Check
  const pageUrl = window.location.href;
  if (pageUrl.startsWith("http://") || pageUrl.startsWith("https://")) {
    chrome.runtime.sendMessage(
      { action: "CHECK_PHISHING", url: pageUrl },
      (response) => {
        if (response && response.risk_score >= 45) {
          injectWarningBanner(response.risk_level, response.risk_score, response.flags);
        }
      }
    );
  }

  // 2. Listen for messages from Popup / Service Worker
  chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
    if (msg.action === "SHOW_BANNER") {
      injectWarningBanner(msg.threatLevel, msg.score, [msg.reason]);
    }

    if (msg.action === "SCAN_SELECTED_TEXT") {
      const selected = window.getSelection().toString().trim();
      if (!selected) {
        alert("CyberShield AI: Please highlight some text on this page first to scan for cyberbullying!");
        return;
      }
      chrome.runtime.sendMessage(
        { action: "CHECK_TOXICITY", text: selected },
        (res) => {
          if (res && res.status === "success") {
            showToxicityModal(selected, res);
          } else {
            alert("CyberShield AI: Text appears safe or backend offline.");
          }
        }
      );
    }
  });

  // 3. Inject Floating Warning Banner for Dangerous Sites
  function injectWarningBanner(threatLevel, score, flags) {
    if (document.getElementById("cybershield-warning-banner")) return;

    const banner = document.createElement("div");
    banner.id = "cybershield-warning-banner";
    banner.style.cssText = `
      position: fixed;
      top: 0;
      left: 0;
      width: 100%;
      background: linear-gradient(135deg, #7f1d1d, #991b1b);
      color: #ffffff;
      padding: 12px 20px;
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      font-size: 13px;
      font-weight: 600;
      z-index: 2147483647;
      display: flex;
      align-items: center;
      justify-content: space-between;
      box-shadow: 0 4px 12px rgba(0,0,0,0.4);
      border-bottom: 2px solid #ef4444;
    `;

    const mainText = document.createElement("div");
    mainText.innerHTML = `
      <span style="font-size:16px; margin-right:8px;">⚠️</span>
      <strong>CyberShield AI Alert:</strong> ${threatLevel} detected on this page! (Risk: ${score}/100) — <em>${flags && flags[0] ? flags[0] : "Deceptive domain parameters"}</em>
    `;

    const btnGroup = document.createElement("div");
    btnGroup.style.cssText = "display: flex; gap: 10px; align-items: center;";

    const dismissBtn = document.createElement("button");
    dismissBtn.innerText = "Dismiss Warning";
    dismissBtn.style.cssText = `
      background: rgba(255,255,255,0.2);
      border: 1px solid rgba(255,255,255,0.4);
      color: #fff;
      padding: 4px 10px;
      border-radius: 4px;
      cursor: pointer;
      font-size: 11px;
    `;
    dismissBtn.onclick = () => banner.remove();

    btnGroup.appendChild(dismissBtn);
    banner.appendChild(mainText);
    banner.appendChild(btnGroup);

    document.body.prepend(banner);
  }

  // 4. Toxicity Result Dialog
  function showToxicityModal(text, res) {
    const isToxic = res.toxicity_score >= 35;
    const alertColor = isToxic ? "#ef4444" : "#10b981";
    const statusTitle = isToxic ? "⚠️ Harmful / Toxic Content Detected" : "✓ Content Appears Safe";

    const modal = document.createElement("div");
    modal.style.cssText = `
      position: fixed;
      top: 20px;
      right: 20px;
      width: 320px;
      background: #0f172a;
      color: #f1f5f9;
      border: 1px solid ${alertColor};
      border-radius: 8px;
      padding: 16px;
      font-family: sans-serif;
      z-index: 2147483647;
      box-shadow: 0 8px 24px rgba(0,0,0,0.6);
      font-size: 12px;
    `;

    modal.innerHTML = `
      <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:8px;">
        <strong style="color:${alertColor}; font-size:13px;">${statusTitle}</strong>
        <span style="cursor:pointer; color:#94a3b8;" id="closeToxModal">✕</span>
      </div>
      <p style="color:#94a3b8; font-style:italic; margin-bottom:8px;">"${text.slice(0, 60)}..."</p>
      <div style="background:#1e293b; padding:8px; border-radius:6px; margin-bottom:10px;">
        <div>Toxicity Score: <strong>${res.toxicity_score}/100</strong></div>
        <div style="font-size:11px; color:#cbd5e1; margin-top:4px;">${res.toxicity_level}</div>
      </div>
      <div style="font-size:11px; color:#94a3b8;">
        <strong>Safety Action:</strong> ${res.safety_actions && res.safety_actions[0] ? res.safety_actions[0] : "Maintain regular safety."}
      </div>
    `;

    document.body.appendChild(modal);
    modal.querySelector("#closeToxModal").onclick = () => modal.remove();
    setTimeout(() => { if (modal.parentNode) modal.remove(); }, 8000);
  }

  // 5. Password Field Guard Trigger
  document.querySelectorAll('input[type="password"]').forEach((input) => {
    input.addEventListener("focus", () => {
      input.setAttribute("data-cybershield-protected", "true");
    });
  });
})();
