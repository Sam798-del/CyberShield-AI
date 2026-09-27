/* =========================================================
   CYBERSHIELD AI — APP BOOTSTRAP
   ========================================================= */

document.addEventListener("DOMContentLoaded", () => {
    const pageId = document.body.dataset.pageId || "dashboard";
    if (window.CyberShieldNav) {
        CyberShieldNav.init(pageId);
    }

    // Listen for state changes
    window.addEventListener("cybershield-state-changed", (e) => {
        console.log("CyberShield Shared State updated:", e.detail);
    });
});
