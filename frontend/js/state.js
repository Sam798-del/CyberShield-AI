/* =========================================================
   CYBERSHIELD AI — SHARED CLIENT STATE SYSTEM
   ========================================================= */

const CS_STORAGE_KEY = "cybershield_shared_state_v1";
const CS_SESSION_KEY = "cs_active_user_email";

function getStorageKey(email) {
    if (!email) return CS_STORAGE_KEY;
    return "cybershield_state_" + email.toLowerCase().replace(/[^a-z0-9]/g, "_");
}

const DEFAULT_STATE = {
    user: {
        name: "",
        email: "",
        phone: "",
        role: "Security User",
        digitalId: "",
        identityVerified: false,
        avatarInitials: "?"
    },
    identity: {
        verified: false,
        lastVerified: null,
        score: 0,
        privacyControls: {
            showEmail: true,
            showPhone: false,
            personalizedServices: true
        }
    },
    passwordSecurity: {
        score: 0,
        healthLabel: "Not checked",
        crackTime: "—",
        weakCount: 0,
        reusedCount: 0
    },
    emailFootprint: {
        emailScanned: "",
        breachesFound: 0,
        accountsMonitored: 0,
        domainHealth: "Unknown",
        spfDkimStatus: "Unknown"
    },
    phishing: {
        scansCount: 0,
        threatsBlocked: 0,
        lastScan: null
    },
    cyberbullying: {
        scansCount: 0,
        flaggedCount: 0,
        lastScan: null
    },
    incidents: [],
    securityReport: {
        baseScore: 90,
        score: 90,
        fixedIssues: {
            outlook: false,
            weakpass: false,
            phishlink: false,
            cyberbully: false,
            "2fa": false
        }
    },
    settings: {
        sensitivity: "high",
        autoIsolation: true,
        deepScan: true,
        aiModel: "CyberShield-DeepSense-v2",
        autoSuggest: true,
        telemetryOpt: false,
        anonIp: true
    }
};

class StateManager {
    constructor() {
        this._email = sessionStorage.getItem(CS_SESSION_KEY) || localStorage.getItem(CS_SESSION_KEY) || null;
        this.state = this.loadState();
        try {
            if (typeof BroadcastChannel !== "undefined") {
                this.broadcastBus = new BroadcastChannel("cybershield_realtime_bus");
                this.broadcastBus.onmessage = (event) => {
                    if (event.data && event.data.type === "STATE_UPDATED" && event.data.state) {
                        this.state = event.data.state;
                        window.dispatchEvent(new CustomEvent("cybershield-state-changed", { detail: this.state }));
                    } else if (event.data && event.data.type === "EXTENSION_INCIDENT" && event.data.incident) {
                        this.recordExtensionIncident(event.data.incident, false);
                    }
                };
            }
        } catch (e) {}

        // Listen for extension postMessage bridge
        if (typeof window !== "undefined") {
            window.addEventListener("message", (event) => {
                if (event.data && event.data.type === "CYBERSHIELD_EXTENSION_INCIDENT" && event.data.incident) {
                    this.recordExtensionIncident(event.data.incident, true);
                }
            });
        }
    }

    _storageKey() {
        return getStorageKey(this._email);
    }

    loadState() {
        try {
            const raw = localStorage.getItem(this._storageKey());
            if (!raw) return JSON.parse(JSON.stringify(DEFAULT_STATE));
            const parsed = JSON.parse(raw);
            return {
                ...DEFAULT_STATE,
                ...parsed,
                user: { ...DEFAULT_STATE.user, ...parsed.user },
                securityReport: { ...DEFAULT_STATE.securityReport, ...parsed.securityReport }
            };
        } catch (e) {
            console.warn("Failed to load CyberShield state from localStorage, resetting to default.", e);
            return JSON.parse(JSON.stringify(DEFAULT_STATE));
        }
    }

    saveState(broadcastToBus = true) {
        try {
            localStorage.setItem(this._storageKey(), JSON.stringify(this.state));
            window.dispatchEvent(new CustomEvent("cybershield-state-changed", { detail: this.state }));
            if (broadcastToBus && this.broadcastBus) {
                try {
                    this.broadcastBus.postMessage({ type: "STATE_UPDATED", state: this.state });
                } catch (e) {}
            }
            // Debounced server sync (only when user is logged in via real account)
            if (this._email && this._email !== "demo@cybershield.ai") {
                clearTimeout(this._syncTimer);
                this._syncTimer = setTimeout(() => this._syncToServer(), 1500);
            }
        } catch (e) {
            console.error("Failed to save state to localStorage", e);
        }
    }

    async _syncToServer() {
        try {
            await fetch("/api/user-state", {
                method: "PUT",
                headers: { "Content-Type": "application/json", "X-Requested-With": "CyberShield" },
                credentials: "include",
                body: JSON.stringify({ state: this.state })
            });
        } catch (_) { /* silent – offline or not logged in */ }
    }

    async loadFromServer() {
        try {
            const res = await fetch("/api/user-state", { credentials: "include" });
            if (res.ok) {
                const json = await res.json();
                if (json.state && typeof json.state === "object" && Object.keys(json.state).length > 0) {
                    this.state = {
                        ...JSON.parse(JSON.stringify(DEFAULT_STATE)),
                        ...json.state,
                        user: { ...DEFAULT_STATE.user, ...(json.state.user || {}) },
                        securityReport: { ...DEFAULT_STATE.securityReport, ...(json.state.securityReport || {}) }
                    };
                    // Also update localStorage
                    localStorage.setItem(this._storageKey(), JSON.stringify(this.state));
                    window.dispatchEvent(new CustomEvent("cybershield-state-changed", { detail: this.state }));
                }
            }
        } catch (_) { /* silent */ }
    }

    getState() {
        return this.state;
    }

    updateUser(userData) {
        this.state.user = { ...this.state.user, ...userData };
        this.saveState();
    }

    updateSettings(settingsData) {
        this.state.settings = { ...(this.state.settings || {}), ...settingsData };
        this.saveState();
    }

    login(userData) {
        // Switch storage scope to this user's email
        const email = (userData && userData.email) ? userData.email.toLowerCase() : null;
        if (email && email !== this._email) {
            this._email = email;
            localStorage.setItem(CS_SESSION_KEY, email);
            sessionStorage.setItem(CS_SESSION_KEY, email);
            // Load this user's saved state (or fresh defaults)
            this.state = this.loadState();
        }
        if (userData) {
            this.updateUser(userData);
        }
        return this.state.user;
    }

    logout() {
        this._email = null;
        localStorage.removeItem(CS_SESSION_KEY);
        sessionStorage.removeItem(CS_SESSION_KEY);
    }

    verifyIdentity() {
        this.state.user.identityVerified = true;
        this.state.identity.verified = true;
        this.state.identity.lastVerified = new Date().toLocaleDateString("en-US", { month: "short", day: "2-digit", year: "numeric" });
        this.state.identity.score = 98;
        this.recalculateScore();
        this.saveState();
    }

    verifyUserIdentity() {
        return this.verifyIdentity();
    }

    recordPhishingScan(result) {
        if (!this.state.phishing) this.state.phishing = { scansCount: 0, threatsBlocked: 0 };
        this.state.phishing.scansCount = (this.state.phishing.scansCount || 0) + 1;
        this.state.phishing.lastScan = {
            ...result,
            timestamp: new Date().toISOString()
        };
        const isThreat = result.is_phishing || (result.risk_score && result.risk_score >= 45);
        if (isThreat) {
            this.state.phishing.threatsBlocked = (this.state.phishing.threatsBlocked || 0) + 1;
            this.addIncident({
                id: "phish_" + Date.now(),
                title: `Phishing Link Quarantined: ${result.target || result.url || 'Malicious URL'}`,
                module: "Phishing Detection",
                target: result.target || result.url || "Suspicious domain",
                date: "Just now",
                severity: result.risk_score >= 70 ? "Critical" : "High",
                status: "Quarantined",
                link: "phishing-detection.html"
            });
        }
        this.recalculateScore();
        this.saveState();
    }

    recordCyberbullyingScan(result) {
        if (!this.state.cyberbullying) this.state.cyberbullying = { scansCount: 0, flaggedCount: 0 };
        this.state.cyberbullying.scansCount = (this.state.cyberbullying.scansCount || 0) + 1;
        this.state.cyberbullying.lastScan = {
            ...result,
            timestamp: new Date().toISOString()
        };
        const isToxic = result.is_toxic || (result.toxicity_score && result.toxicity_score >= 35);
        if (isToxic) {
            this.state.cyberbullying.flaggedCount = (this.state.cyberbullying.flaggedCount || 0) + 1;
            this.addIncident({
                id: "bully_" + Date.now(),
                title: `Toxic Content Flagged (Score: ${result.toxicity_score || 70}/100)`,
                module: "Cyberbullying Detection",
                target: (result.text || "").slice(0, 35) + "...",
                date: "Just now",
                severity: (result.toxicity_score || 0) >= 70 ? "High" : "Medium",
                status: "Flagged",
                link: "cyberbullying-detection.html"
            });
        }
        this.recalculateScore();
        this.saveState();
    }

    recordPasswordScan(result) {
        const score = result.scoreNum !== undefined ? result.scoreNum : (result.score || 70);
        this.state.passwordSecurity = {
            ...this.state.passwordSecurity,
            score: score,
            healthLabel: result.label || (score >= 75 ? "Strong" : score >= 45 ? "Moderate" : "Weak"),
            crackTime: result.crackTime || result.estimated_crack_time || "N/A",
            breached: !!result.breached,
            breachCount: result.breachCount || result.breach_count || 0,
            entropyBits: result.entropyBits || result.entropy_bits || 50,
            lastScan: new Date().toISOString()
        };

        if (result.breached || score < 50) {
            this.state.passwordSecurity.weakCount = 1;
            this.addIncident({
                id: "pw_" + Date.now(),
                title: result.breached ? `Breached Password Detected (Seen in ${result.breachCount || result.breach_count || 0} breaches)` : `Weak Password Detected (Score: ${score}/100)`,
                module: "Security Analyzer",
                target: "Password input",
                date: "Just now",
                severity: result.breached ? "Critical" : "Medium",
                status: "Action Needed",
                link: "security-analyzer.html"
            });
        } else if (score >= 75) {
            this.state.passwordSecurity.weakCount = 0;
        }

        this.recalculateScore();
        this.saveState();
    }

    recordLeakScan(result) {
        if (!this.state.emailFootprint) this.state.emailFootprint = { breachesFound: 0, accountsMonitored: 6 };
        const found = !!result.found;
        const count = result.breachCount || (result.breaches ? result.breaches.length : 0);
        this.state.emailFootprint.emailScanned = result.target || this.state.emailFootprint.emailScanned;
        this.state.emailFootprint.breachesFound = count;
        this.state.emailFootprint.breachList = result.breachList || result.breaches || [];
        this.state.emailFootprint.domainHealth = found ? "Compromised" : "Clean";
        this.state.emailFootprint.lastScan = new Date().toISOString();

        if (found) {
            this.addIncident({
                id: "leak_" + Date.now(),
                title: `Data Breach Detected for ${result.target} (${count} incident${count > 1 ? 's' : ''})`,
                module: "Security Analyzer",
                target: result.target,
                date: "Just now",
                severity: "High",
                status: "Breach Found",
                link: `security-analyzer.html?domain=${encodeURIComponent(result.target)}&type=${result.type || 'domain'}`
            });
        }

        this.recalculateScore();
        this.saveState();
    }

    addIncident(inc, recalculate = true) {
        if (!Array.isArray(this.state.incidents)) {
            this.state.incidents = [];
        }
        // Avoid duplicate recent incidents with identical title
        if (this.state.incidents.length > 0 && this.state.incidents[0].title === inc.title) {
            return;
        }
        this.state.incidents.unshift(inc);
        if (this.state.incidents.length > 15) {
            this.state.incidents = this.state.incidents.slice(0, 15);
        }
        if (recalculate) {
            this.recalculateScore();
            this.saveState();
        }
    }

    recordExtensionIncident(inc, shouldBroadcast = true) {
        if (!inc) return;

        // Dynamic module metrics updates based on extension threat detection
        if (inc.module === "Phishing Detection") {
            if (!this.state.phishing) this.state.phishing = { scansCount: 42, threatsBlocked: 2 };
            this.state.phishing.scansCount++;
            if (inc.severity === "High" || inc.severity === "Critical") {
                this.state.phishing.threatsBlocked++;
                this.state.phishing.lastScan = {
                    is_phishing: true,
                    risk_score: inc.severity === "Critical" ? 90 : 75,
                    target: inc.target || "Malicious URL"
                };
            }
        } else if (inc.module === "Cyberbullying Detection") {
            if (!this.state.cyberbullying) this.state.cyberbullying = { scansCount: 12, flaggedCount: 1 };
            this.state.cyberbullying.scansCount++;
            this.state.cyberbullying.flaggedCount++;
            this.state.cyberbullying.lastScan = {
                is_toxic: true,
                toxicity_score: 85,
                target: inc.target || "Social comment"
            };
        } else if (inc.module === "Security Analyzer") {
            const tLower = (inc.title || "").toLowerCase();
            if (tLower.includes("breach") || tLower.includes("domain") || tLower.includes("leak")) {
                if (!this.state.emailFootprint) this.state.emailFootprint = { breachesFound: 0, accountsMonitored: 6 };
                this.state.emailFootprint.breachesFound = Math.max(1, (this.state.emailFootprint.breachesFound || 0) + 1);
                this.state.emailFootprint.domainHealth = "Compromised";
            }
            if (tLower.includes("password")) {
                if (!this.state.passwordSecurity) this.state.passwordSecurity = { score: 72, weakCount: 1, reusedCount: 1 };
                this.state.passwordSecurity.breached = true;
                this.state.passwordSecurity.score = 30;
                this.state.passwordSecurity.healthLabel = "Compromised";
                this.state.passwordSecurity.weakCount++;
            }
        }

        this.addIncident(inc, true);

        if (shouldBroadcast && this.broadcastBus) {
            try {
                this.broadcastBus.postMessage({ type: "EXTENSION_INCIDENT", incident: inc });
            } catch (e) {}
        }
    }

    resolveIssue(issueId) {
        if (!this.state.securityReport.fixedIssues) {
            this.state.securityReport.fixedIssues = {};
        }
        this.state.securityReport.fixedIssues[issueId] = true;

        if (issueId === "outlook" || issueId === "weakpass") {
            this.state.passwordSecurity.weakCount = 0;
            this.state.passwordSecurity.reusedCount = 0;
            this.state.passwordSecurity.score = 96;
            this.state.passwordSecurity.healthLabel = "Strong";
        }

        this.recalculateScore();
        this.saveState();
    }

    recalculateScore() {
        let score = 92;
        const fixed = this.state.securityReport?.fixedIssues || {};
        const pw = this.state.passwordSecurity || {};
        const phish = this.state.phishing || {};
        const bully = this.state.cyberbullying || {};
        const leak = this.state.emailFootprint || {};

        // Security Analyzer deductions / bonuses
        if (pw.breached) score -= 18;
        else if (pw.score < 45) score -= 12;
        else if (pw.score < 75) score -= 6;
        else score += 3;

        if (leak.breachesFound > 0) score -= Math.min(15, leak.breachesFound * 6);
        else score += 2;

        // Phishing detection deductions
        if (phish.lastScan && (phish.lastScan.is_phishing || phish.lastScan.risk_score >= 50)) {
            if (!fixed.phishlink) score -= 8;
        }

        // Cyberbullying detection deductions
        if (bully.lastScan && (bully.lastScan.is_toxic || bully.lastScan.toxicity_score >= 50)) {
            if (!fixed.cyberbully) score -= 6;
        }

        // Fixed issues bonuses
        if (fixed.outlook) score += 4;
        if (fixed.weakpass) score += 3;
        if (fixed.phishlink) score += 2;
        if (fixed.cyberbully) score += 2;
        if (fixed["2fa"]) score += 2;
        if (this.state.identity?.verified || this.state.user?.identityVerified) score += 3;

        score = Math.max(35, Math.min(100, Math.round(score)));
        if (!this.state.securityReport) this.state.securityReport = {};
        this.state.securityReport.score = score;
    }
}

const CyberShieldState = new StateManager();
window.CyberShieldState = CyberShieldState;
