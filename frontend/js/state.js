/* =========================================================
   CYBERSHIELD AI — SHARED CLIENT STATE SYSTEM
   ========================================================= */

const CS_STORAGE_KEY = "cybershield_shared_state_v1";

const DEFAULT_STATE = {
    user: {
        name: "Neeraja Shinde",
        email: "neeraja.shinde@cybershield.ai",
        phone: "+91 98765 43210",
        role: "Lead Security Administrator",
        digitalId: "CS-8F29-A91B",
        identityVerified: false,
        avatarInitials: "NS"
    },
    identity: {
        verified: false,
        lastVerified: null,
        score: 92,
        privacyControls: {
            showEmail: true,
            showPhone: false,
            personalizedServices: true
        }
    },
    passwordSecurity: {
        score: 72,
        healthLabel: "Moderate",
        crackTime: "~3 months",
        weakCount: 1,
        reusedCount: 1
    },
    emailFootprint: {
        emailScanned: "neeraja.shinde@cybershield.ai",
        breachesFound: 0,
        accountsMonitored: 6,
        domainHealth: "Clean",
        spfDkimStatus: "Valid"
    },
    phishing: {
        scansCount: 42,
        threatsBlocked: 2,
        lastScan: null
    },
    cyberbullying: {
        scansCount: 12,
        flaggedCount: 1,
        lastScan: null
    },
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
        this.state = this.loadState();
    }

    loadState() {
        try {
            const raw = localStorage.getItem(CS_STORAGE_KEY);
            if (!raw) return { ...DEFAULT_STATE };
            const parsed = JSON.parse(raw);
            // Ensure default structure merge
            return {
                ...DEFAULT_STATE,
                ...parsed,
                user: { ...DEFAULT_STATE.user, ...parsed.user },
                securityReport: { ...DEFAULT_STATE.securityReport, ...parsed.securityReport }
            };
        } catch (e) {
            console.warn("Failed to load CyberShield state from localStorage, resetting to default.", e);
            return { ...DEFAULT_STATE };
        }
    }

    saveState() {
        try {
            localStorage.setItem(CS_STORAGE_KEY, JSON.stringify(this.state));
            window.dispatchEvent(new CustomEvent("cybershield-state-changed", { detail: this.state }));
        } catch (e) {
            console.error("Failed to save state to localStorage", e);
        }
    }

    getState() {
        return this.state;
    }

    updateUser(userData) {
        this.state.user = { ...this.state.user, ...userData };
        this.saveState();
    }

    verifyIdentity() {
        this.state.user.identityVerified = true;
        this.state.identity.verified = true;
        this.state.identity.lastVerified = new Date().toLocaleDateString("en-US", { month: "short", day: "2-digit", year: "numeric" });
        this.state.identity.score = 98;
        this.recalculateScore();
        this.saveState();
    }

    recordPhishingScan(result) {
        this.state.phishing.scansCount++;
        this.state.phishing.lastScan = {
            ...result,
            timestamp: new Date().toISOString()
        };
        if (result.is_phishing) {
            this.state.phishing.threatsBlocked++;
        }
        this.recalculateScore();
        this.saveState();
    }

    recordCyberbullyingScan(result) {
        this.state.cyberbullying.scansCount++;
        this.state.cyberbullying.lastScan = {
            ...result,
            timestamp: new Date().toISOString()
        };
        if (result.toxicity_score >= 35) {
            this.state.cyberbullying.flaggedCount++;
        }
        this.recalculateScore();
        this.saveState();
    }

    recordPasswordScan(result) {
        this.state.passwordSecurity = {
            ...this.state.passwordSecurity,
            score: result.scoreNum,
            healthLabel: result.label,
            crackTime: result.crackTime,
            lastScan: new Date().toISOString()
        };
        this.recalculateScore();
        this.saveState();
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
        let score = 90;
        const fixed = this.state.securityReport.fixedIssues || {};
        
        if (fixed.outlook) score += 4;
        if (fixed.weakpass) score += 2;
        if (fixed.phishlink) score += 1;
        if (fixed.cyberbully) score += 2;
        if (fixed["2fa"]) score += 2;

        if (this.state.identity.verified) score += 2;

        this.state.securityReport.score = Math.min(score, 100);
    }
}

const CyberShieldState = new StateManager();
window.CyberShieldState = CyberShieldState;
