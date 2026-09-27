/* =========================================================
   CYBERSHIELD AI — UTILITIES & HEURISTIC ENGINES
   ========================================================= */

const CyberShieldUtils = {
    showToast(message, type = "success") {
        let container = document.getElementById("cs-toast-container");
        if (!container) {
            container = document.createElement("div");
            container.id = "cs-toast-container";
            container.className = "toast-container";
            document.body.appendChild(container);
        }

        const toast = document.createElement("div");
        toast.className = `toast toast-${type}`;
        toast.innerHTML = `<span>${type === "success" ? "✓" : "⚠"}</span> <span>${message}</span>`;
        container.appendChild(toast);

        setTimeout(() => {
            toast.style.opacity = "0";
            toast.style.transform = "translateY(10px)";
            setTimeout(() => toast.remove(), 300);
        }, 3000);
    },

    maskName(name) {
        if (!name) return "Neeraja Shinde";
        const parts = name.trim().split(/\s+/);
        return parts.map(p => p[0] + "*".repeat(Math.max(p.length - 1, 1))).join(" ");
    },

    maskEmail(email) {
        if (!email) return "n******@cybershield.ai";
        const [u, d] = email.split("@");
        if (!d) return email;
        return u.slice(0, 2) + "*".repeat(Math.max(u.length - 2, 1)) + "@" + d;
    },

    maskPhone(phone) {
        if (!phone) return "+91 ••••• ••210";
        const digits = phone.replace(/\D/g, "");
        if (digits.length < 4) return "•••• " + digits;
        return "+" + digits.slice(0, Math.max(digits.length - 10, 0)) + " " + "•".repeat(Math.max(digits.length - 4, 0)) + digits.slice(-4);
    },

    evaluatePassword(val) {
        let score = 0;
        if (!val) return { scoreNum: 0, label: "Very Weak", crackTime: "< 1 sec", color: "var(--danger)" };

        if (val.length >= 8) score += 0.25;
        if (val.length >= 12) score += 0.15;
        if (/[A-Z]/.test(val)) score += 0.15;
        if (/[0-9]/.test(val)) score += 0.15;
        if (/[!@#$%^&*(),.?":{}|<>]/.test(val)) score += 0.2;
        if (/[a-z]/.test(val)) score += 0.1;
        score = Math.min(score, 1);

        let label, crackTime, color;
        if (score >= 0.8) {
            label = "Strong"; crackTime = "~200+ years"; color = "var(--success)";
        } else if (score >= 0.5) {
            label = "Moderate"; crackTime = "~3 months"; color = "var(--warning)";
        } else {
            label = "Weak"; crackTime = "< 1 day"; color = "var(--danger)";
        }

        return {
            scoreNum: Math.round(score * 100),
            label,
            crackTime,
            color,
            checks: {
                length: val.length >= 8,
                upper: /[A-Z]/.test(val),
                lower: /[a-z]/.test(val),
                number: /[0-9]/.test(val),
                special: /[^A-Za-z0-9]/.test(val)
            }
        };
    },

    heuristicPhishingScan(input) {
        const text = (input || "").toLowerCase();
        const indicators = [];
        let riskScore = 15;

        if (text.includes("urgent") || text.includes("immediately") || text.includes("account suspended") || text.includes("access restricted")) {
            riskScore += 30;
            indicators.push("Urgent Panic / Pressure Phrasing");
        }

        if (text.includes("http://") || text.includes("bit.ly") || text.includes(".xyz") || text.includes("paypa1") || text.includes("verification")) {
            riskScore += 40;
            indicators.push("Deceptive or Shortened URL Domain");
        }

        if (text.includes("password") || text.includes("verify your identity") || text.includes("credit card") || text.includes("ssn")) {
            riskScore += 20;
            indicators.push("Credential Harvesting Request");
        }

        riskScore = Math.min(riskScore, 98);
        const isPhishing = riskScore >= 45;
        const riskLevel = riskScore >= 75 ? "Critical / High Risk" : (riskScore >= 45 ? "Medium Risk" : "Low Risk / Clean");

        return {
            is_phishing: isPhishing,
            risk_score: riskScore,
            risk_level: riskLevel,
            indicators: indicators.length > 0 ? indicators : ["Standard Communication Pattern"],
            recommendations: isPhishing ? [
                "Do NOT click links embedded in this message.",
                "Verify the sender address independently using official company channels.",
                "Report this email to your security administrator."
            ] : [
                "Message exhibits standard formatting, but always verify unfamiliar senders."
            ]
        };
    },

    heuristicCyberbullyingScan(textInput) {
        const text = (textInput || "").toLowerCase();
        const flaggedWords = [];
        let score = 10;

        const harassmentKeywords = ["hate", "die", "useless", "loser", "ugly", "stupid", "delete your account", "quit", "nobody likes you", "freak", "kill"];
        
        harassmentKeywords.forEach(word => {
            if (text.includes(word)) {
                score += 30;
                flaggedWords.push(word);
            }
        });

        score = Math.min(score, 99);
        const isToxic = score >= 35;
        const toxicityLevel = score >= 70 ? "🚨 HIGH TOXICITY / TARGETED HARASSMENT" : (score >= 35 ? "⚠ MODERATE TOXICITY DETECTED" : "✅ SAFE / LOW TOXICITY");

        return {
            toxicity_score: score,
            toxicity_level: toxicityLevel,
            flagged_words: flaggedWords.length > 0 ? flaggedWords : ["None"],
            safety_actions: isToxic ? [
                "Document evidence by taking full screenshots and chat logs.",
                "Do NOT respond to the harassment or engage with the sender.",
                "Block the sender and report the abusive content to platform moderators."
            ] : [
                "Text appears safe and non-harassing."
            ]
        };
    }
};

window.CyberShieldUtils = CyberShieldUtils;
