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
        const text = " " + (textInput || "").toLowerCase().trim() + " ";
        const flaggedWords = [];
        const detectedCategories = [];
        let score = 0;

        const categories = {
            threat: {
                weight: 60,
                patterns: [
                    "i will find you", "kill yourself", "kill you", "should kill you", "i will kill you",
                    "kill you with", "murder you", "shoot you", "stab you", "strangle you",
                    "with a hammer", "with a knife", "with a gun", "go die", "should die", "hope you die",
                    "deserve to die", "beat you", "hurt you", "destroy you", "slit your", "burn you",
                    "murder", "end your life"
                ]
            },
            intimidation: {
                weight: 45,
                patterns: [
                    "keep messaging you until", "to your reputation", "make your life miserable",
                    "delete your account", "can't escape", "disappear from this platform",
                    "watch your back", "track your ip", "you will pay for this", "ruin your life",
                    "ruin your future", "stalk"
                ]
            },
            defamation: {
                weight: 45,
                patterns: [
                    "spread this rumour", "spread this rumor", "embarrassing picture",
                    "fake account just to expose", "fake account to expose", "expose you",
                    "everyone should see this embarrassing", "share this post so everyone can laugh",
                    "leak your private", "dox you"
                ]
            },
            social_exclusion: {
                weight: 45,
                patterns: [
                    "don't invite her", "don't invite him", "don't invite them", "nobody wants her around",
                    "nobody wants him around", "nobody wants you around", "nobody wants you here",
                    "no one wants you around", "no one wants you here", "no one likes you", "nobody likes you",
                    "nobody cares about you", "no one cares about you", "nobody loves you", "no one loves you",
                    "make a group without", "ignore all his messages", "ignore all her messages",
                    "unfollow this person", "they don't belong here", "you don't belong here",
                    "nobody asked you", "leave this group"
                ]
            },
            body_shaming: {
                weight: 45,
                patterns: [
                    "looking like that", "look ridiculous", "look disgusting", "hide your face",
                    "wear clothes like that", "your appearance is the reason", "you look horrible",
                    "lose some weight", "so fat", "ugly face"
                ]
            },
            insult: {
                weight: 40,
                patterns: [
                    "stupid", "idiot", "loser", "ugly", "fat", "dumb", "dumbest", "hate you",
                    "freak", "trash", "worthless", "pathetic", "complete joke", "nobody takes you seriously",
                    "embarrassing", "laughs at you behind", "stop talking", "waste of space"
                ]
            },
            profanity: {
                weight: 25,
                patterns: ["bitch", "bastard", "fuck", "shit", "asshole", "crap"]
            }
        };

        Object.keys(categories).forEach(cat => {
            const data = categories[cat];
            let matched = false;
            data.patterns.forEach(w => {
                if (text.includes(w)) {
                    score += data.weight;
                    flaggedWords.push(w);
                    matched = true;
                }
            });
            if (matched) detectedCategories.push(cat);
        });

        // Combinatorial SVO Semantic Grammar Rules
        const svoGrammarRules = [
            { cat: 'threat', weight: 85, re: /\b(kill|murder|shoot|stab|choke|strangle|beat|smash|hit|cut|attack|destroy|hurt|burn|drown|torture|crush|punch|slap|slice|hang|slaughter|butcher)\s+(you|u|your\s+(head|face|throat|neck|body|chest)|her|him)\b/i, name: 'violent assault' },
            { cat: 'threat', weight: 80, re: /\b(i\s*('?ll|will|should|must|wanna|want\s+to|gonna|am\s+going\s+to|can))\s+.*(kill|murder|beat|hurt|destroy|stab|shoot|smash|slap|attack|burn|crush)\s+(you|u)\b/i, name: 'violent declaration' },
            { cat: 'threat', weight: 75, re: /\b(with\s+(a\s+)?(hammer|knife|gun|weapon|bat|blade|axe|acid|brick|pipe|crowbar|sword|rope|pistol|rifle))\b/i, name: 'weapon assault' },
            { cat: 'threat', weight: 85, re: /\b(you|u)\s+(should|must|need\s+to|deserve\s+to|ought\s+to|better)\s+(die|perish|burn|suffer|rot|hang\s+yourself|kill\s+(yourself|urself)|end\s+your\s+life)\b/i, name: 'death wish' },
            { cat: 'threat', weight: 75, re: /\b(should|hope|wish|want|deserve|pray)\s+(you|u)\s+(die|perish|rot|suffer|burn|get\s+killed)\b/i, name: 'fatality wish' },
            { cat: 'threat', weight: 75, re: /\b(go|better|just)\s+die\b/i, name: 'death incitement' },
            { cat: 'threat', weight: 85, re: /\b(kill|hang)\s+(yourself|urself)\b/i, name: 'suicide incitement' },
            { cat: 'social_exclusion', weight: 55, re: /\b(no\s*one|nobody|not\s+a\s+single\s+person|none\s+of\s+us)\s+(likes?|wants?|cares?\s+about|cares?|loves?|needs?|trusts?|respects?|talks?\s+to)\s+(you|u|her|him|them)\b/i, name: 'universal rejection' },
            { cat: 'social_exclusion', weight: 50, re: /\b(don\'?t|do\s+not|never)\s+(invite|talk\s+to|speak\s+to|hang\s+out\s+with|message)\s+(her|him|them|you|u)\b/i, name: 'relational ostracization' },
            { cat: 'social_exclusion', weight: 50, re: /\b(make\s+a\s+group|group\s+chat)\s+without\s+(him|her|them|you|u)\b/i, name: 'exclusion group' },
            { cat: 'social_exclusion', weight: 50, re: /\b(ignore|block|mute)\s+(all\s+)?(his|her|their|your)\s+(messages|texts|calls|posts)\b/i, name: 'communication blocking' },
            { cat: 'social_exclusion', weight: 50, re: /\b(they|you|u|she|he)\s+(don\'?t|does\s+not|doesn\'?t)\s+belong\s+(here|with\s+us|in\s+this\s+group)\b/i, name: 'exclusion alienation' },
            { cat: 'body_shaming', weight: 55, re: /\b(look|looking|looks)\s+(so\s+)?(ridiculous|disgusting|horrible|repulsive|ugly|fat|gross|hideous|repugnant|like\s+a\s+(clown|joke|pig|cow|whale|freak))\b/i, name: 'appearance denigration' },
            { cat: 'body_shaming', weight: 55, re: /\b(appearance|face|weight|body|figure|skin)\s+(is\s+the\s+reason|makes\s+me\s+sick|is\s+disgusting|looks\s+terrible)\b/i, name: 'body shaming' },
            { cat: 'body_shaming', weight: 50, re: /\b(upload|post|take)\s+(a\s+)?(picture|photo)\s+looking\s+like\s+that\b/i, name: 'aesthetic mockery' },
            { cat: 'intimidation', weight: 55, re: /\b(keep|continue)\s+(messaging|texting|calling|harassing|stalking|following)\s+(you|u)\s+(until|forever)\b/i, name: 'stalking pressure' },
            { cat: 'intimidation', weight: 55, re: /\b(make\s+your\s+life|ruin\s+your|destroy\s+your)\s+(miserable|life|reputation|future|career|family)\b/i, name: 'intimidation threat' },
            { cat: 'intimidation', weight: 50, re: /\b(delete|deactivate|remove)\s+(your\s+)?(account|profile|channel|post)\b/i, name: 'account silencing' },
            { cat: 'intimidation', weight: 50, re: /\b(can\'?t|cannot|won\'?t)\s+escape\s+(me|what\s+i|this)\b/i, name: 'coercive entrapment' },
            { cat: 'defamation', weight: 55, re: /\b(spread|share|leak|post|circulate)\s+(this\s+)?(rumour|rumor|lie|lies|photo|picture|screenshot|chat|video|private|secret)\b/i, name: 'rumour spread' },
            { cat: 'defamation', weight: 55, re: /\b(fake\s+account|alt\s+account)\s+(just\s+)?to\s+expose\s+(you|her|him)\b/i, name: 'smear campaign' },
            { cat: 'insult', weight: 50, re: /\b(you(\'re|\s+are)|u\s+r)\s+(literally\s+)?(a\s+|an\s+|the\s+)?(dumbest|stupidest|biggest\s+loser|complete\s+joke|joke|laughing\s+stock|waste\s+of\s+space|brainless|moron|idiot|imbecile|retard|failure|clown|freak|loser)\b/i, name: 'direct insult' },
            { cat: 'insult', weight: 45, re: /\b(nobody|no\s*one)\s+takes\s+you\s+seriously\b/i, name: 'intellectual ridicule' }
        ];

        svoGrammarRules.forEach(rule => {
            if (rule.re.test(text)) {
                score = Math.max(score, rule.weight);
                flaggedWords.push(rule.name);
                if (!detectedCategories.includes(rule.cat)) detectedCategories.push(rule.cat);
            }
        });

        score = Math.min(score, 100);
        const isToxic = score >= 35;
        const toxicityLevel = score >= 65 
            ? "🚨 HIGH TOXICITY / TARGETED HARASSMENT" 
            : (score >= 35 ? "⚠️ MODERATE TOXICITY DETECTED" : "✅ SAFE / NON-TOXIC CONTENT");

        return {
            toxicity_score: score,
            toxicity_level: toxicityLevel,
            flagged_words: flaggedWords.length > 0 ? [...new Set(flaggedWords)] : ["None"],
            categories: detectedCategories,
            safety_actions: isToxic ? [
                "Document evidence by taking full screenshots and chat logs.",
                "Do NOT respond to the harassment or engage with the sender.",
                "Block the sender and report the abusive content to platform moderators (or cybercrime.gov.in / 1930 for threats)."
            ] : [
                "Text appears safe and non-harassing."
            ]
        };
    }
};

window.CyberShieldUtils = CyberShieldUtils;
