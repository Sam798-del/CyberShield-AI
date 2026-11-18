/* =========================================================
   CYBERSHIELD AI — APP BOOTSTRAP
   ========================================================= */

document.addEventListener("DOMContentLoaded", async () => {
    const pageId = document.body.dataset.pageId || "dashboard";
    if (window.CyberShieldNav) {
        CyberShieldNav.init(pageId);
    }

    // Listen for state changes
    window.addEventListener("cybershield-state-changed", (e) => {
        console.log("CyberShield Shared State updated:", e.detail);
    });

    // On non-login pages, try to restore state from the server
    // so the user picks up exactly where they left off.
    if (pageId !== "login" && window.CyberShieldState) {
        try {
            await CyberShieldState.loadFromServer();
        } catch (_) {}
    }
});
