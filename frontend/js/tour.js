/**
 * CyberShield AI — Dynamic Interactive Feature Tour & Onboarding Guide
 * Provides an interactive step-by-step walkthrough of every core platform capability.
 */

(function () {
    const TOUR_FEATURES = [
        {
            id: "dashboard",
            badge: "COMMAND CENTER",
            title: "Security Command Dashboard",
            icon: "📊",
            tagline: "Centralized Real-Time Threat Intelligence & Security Health Score",
            description: "Your primary command console that aggregates real-time diagnostics across every attack vector on the web and in your browser.",
            highlights: [
                "Dynamic Cyber Threat Score (0–100) calculated live from system telemetry",
                "Four active protection shields: Phishing, Dark Web Identity, Passwords, and Cyberbullying",
                "Real-time threat feed broadcasting incidents directly from the Chrome Extension",
                "One-click resolution buttons to instantly mitigate identified security vulnerabilities"
            ],
            link: "dashboard.html",
            linkText: "Explore Dashboard ↗"
        },
        {
            id: "identity",
            badge: "IDENTITY VAULT",
            title: "Zero-Trust Digital Identity",
            icon: "🔑",
            tagline: "Dark Web Credential Exposure Monitoring & Digital Footprint Tracking",
            description: "Guards your personal data against dark web broker dumps, credential stuffing attacks, and identity impersonation.",
            highlights: [
                "Real-time monitoring of linked email addresses, phone numbers, and corporate credentials",
                "Identity Exposure Rank categorizing threats from Clean to Critical",
                "Digital Footprint mapping of all online services associated with your identity",
                "Actionable identity hardening recommendations to minimize your public attack surface"
            ],
            link: "digital-identity.html",
            linkText: "Check Digital Identity ↗"
        },
        {
            id: "analyzer",
            badge: "BREACH & ENTROPY ENGINE",
            title: "Security & Password Analyzer",
            icon: "🔍",
            tagline: "Live Shannon Entropy, Breach Audits & One-by-One Account Remediation",
            description: "Deep diagnostic tool that evaluates password entropy, scans billions of compromised accounts, and provides step-by-step incident response.",
            highlights: [
                "Live Shannon entropy and crack-time evaluation with HaveIBeenPwned k-anonymity checks",
                "Smart High-Strength Variations generated dynamically from your own letters and numbers",
                "Domain leak scanner identifying compromised corporate databases (Facebook, Canva, Adobe, etc.)",
                "Official step-by-step account recovery protocols with direct links to security settings"
            ],
            link: "security-analyzer.html",
            linkText: "Run Security Diagnostics ↗"
        },
        {
            id: "phishing",
            badge: "ACTIVE WEB SHIELD",
            title: "Phishing Detection & URL Scanner",
            icon: "📧",
            tagline: "Real-Time URL Heuristics, Typosquatting Detection & Social Engineering Scanner",
            description: "Protects against fake login portals, malicious lookalike domains, and urgent phishing emails designed to steal credentials.",
            highlights: [
                "Inspects URLs for punycode spoofing, unencrypted HTTP, and deceptive high-risk TLDs",
                "Natural language analysis identifying urgency, wire requests, and credential solicitation triggers",
                "Four-tier risk classification: Critical Phishing Threat, High Risk, Moderate Caution, and Safe",
                "Instant quarantine recommendations and reporting protocols for fraudulent domains"
            ],
            link: "phishing-detection.html",
            linkText: "Inspect URLs & Emails ↗"
        },
        {
            id: "cyberbullying",
            badge: "NLP CONTENT DEFENSE",
            title: "Cyberbullying & Toxicity Defense",
            icon: "💬",
            tagline: "In-Page Toxic Blurring & 'Think Before You Post' Outbound Send Blocker",
            description: "Advanced natural language processing engine that detects online harassment, hate speech, body shaming, and intimidation across the web.",
            highlights: [
                "Automatic In-Page Blurring: Hides incoming toxic comments with a click-to-reveal shield",
                "Outbound Send Blocker: Intercepts abusive messages before posting with an interactive [ ✏️ Edit Message ] prompt",
                "Multi-category SVO grammar engine tracking insults, relational bullying, threats, and defamation",
                "Built-in legal protection citations under Indian IT Act Sec 66D/66E and IPC Sec 500/506/507"
            ],
            link: "cyberbullying-detection.html",
            linkText: "Test Toxicity Engine ↗"
        },
        {
            id: "report",
            badge: "FORENSIC AUDITING",
            title: "AI Security Report & Audit Export",
            icon: "📈",
            tagline: "Automated Threat Timeline, Forensic Telemetry & Printable Security Briefing",
            description: "Synthesizes every intercepted threat, breach scan, and system event into an executive cybersecurity audit report.",
            highlights: [
                "Executive security risk grading from A+ (Optimal Defense) down to F (Critical Vulnerability)",
                "Chronological forensic timeline of incidents across both web platform and Chrome Extension",
                "Comprehensive category breakdowns with exposure scores and resolved issue logs",
                "Printable official audit report for personal records or enterprise compliance"
            ],
            link: "security-report.html",
            linkText: "View AI Security Report ↗"
        },
        {
            id: "extension",
            badge: "BROWSER DEFENSE",
            title: "Chrome Extension Real-Time Guard",
            icon: "🛡️",
            tagline: "Floating Corner Badges, Breach Warning Banners & Live Telemetry Sync",
            description: "Brings the full power of CyberShield AI directly into your browsing experience across YouTube, Twitter, Reddit, and every website you visit.",
            highlights: [
                "Floating Safe/Threat pill badge in the corner of every webpage for instant security status",
                "Top-of-screen Warning Banners that alert you when visiting historically breached websites",
                "In-field password strength tooltips that offer 1-click fortified password substitutions",
                "Seamless two-way bridge syncing incident alerts with the central Dashboard in real time"
            ],
            link: "dashboard.html",
            linkText: "Explore Platform ↗"
        }
    ];

    let currentStep = 0;

    function renderTourModal() {
        const existing = document.getElementById("cybershield-tour-overlay");
        if (existing) existing.remove();

        const feat = TOUR_FEATURES[currentStep];
        const total = TOUR_FEATURES.length;
        const progressPct = Math.round(((currentStep + 1) / total) * 100);

        const overlay = document.createElement("div");
        overlay.id = "cybershield-tour-overlay";
        overlay.style.cssText = `
            position: fixed;
            top: 0;
            left: 0;
            width: 100vw;
            height: 100vh;
            background: rgba(3, 7, 18, 0.88);
            backdrop-filter: blur(10px);
            -webkit-backdrop-filter: blur(10px);
            display: flex;
            align-items: center;
            justify-content: center;
            z-index: 2147483647;
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
            color: #f8fafc;
            animation: csTourFadeIn 0.25s cubic-bezier(0.16, 1, 0.3, 1);
            padding: 16px;
            box-sizing: border-box;
        `;

        overlay.innerHTML = `
            <style>
                @keyframes csTourFadeIn {
                    from { opacity: 0; transform: scale(0.96); }
                    to { opacity: 1; transform: scale(1); }
                }
                .cs-tour-dot {
                    width: 8px;
                    height: 8px;
                    border-radius: 50%;
                    background: #334155;
                    transition: all 0.2s ease;
                    cursor: pointer;
                }
                .cs-tour-dot.active {
                    width: 24px;
                    border-radius: 6px;
                    background: #38bdf8;
                    box-shadow: 0 0 10px rgba(56, 189, 248, 0.5);
                }
                .cs-tour-btn-primary {
                    background: linear-gradient(135deg, #0284c7, #0369a1);
                    border: 1px solid #38bdf8;
                    color: #ffffff;
                    padding: 9px 20px;
                    border-radius: 8px;
                    font-size: 13.5px;
                    font-weight: 700;
                    cursor: pointer;
                    display: inline-flex;
                    align-items: center;
                    gap: 6px;
                    transition: all 0.15s ease;
                    box-shadow: 0 4px 14px rgba(2, 132, 199, 0.35);
                }
                .cs-tour-btn-primary:hover {
                    background: linear-gradient(135deg, #0369a1, #075985);
                    transform: translateY(-1px);
                }
                .cs-tour-btn-secondary {
                    background: rgba(255, 255, 255, 0.06);
                    border: 1px solid rgba(255, 255, 255, 0.15);
                    color: #cbd5e1;
                    padding: 9px 16px;
                    border-radius: 8px;
                    font-size: 13px;
                    font-weight: 600;
                    cursor: pointer;
                    transition: all 0.15s ease;
                }
                .cs-tour-btn-secondary:hover {
                    background: rgba(255, 255, 255, 0.12);
                    color: #ffffff;
                }
            </style>

            <div style="
                background: linear-gradient(145deg, #0f172a, #0b1120);
                border: 1.5px solid #38bdf8;
                border-radius: 18px;
                width: 100%;
                max-width: 600px;
                padding: 26px 28px;
                box-shadow: 0 25px 70px -15px rgba(0, 0, 0, 0.95), 0 0 40px -10px rgba(56, 189, 248, 0.3);
                position: relative;
                box-sizing: border-box;
            ">
                <!-- Top Header Bar -->
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 16px;">
                    <div style="display: flex; align-items: center; gap: 8px;">
                        <span style="background: rgba(56, 189, 248, 0.15); color: #38bdf8; border: 1px solid rgba(56, 189, 248, 0.4); padding: 3px 10px; border-radius: 20px; font-size: 10.5px; font-weight: 800; letter-spacing: 0.6px;">
                            ${feat.badge}
                        </span>
                        <span style="font-size: 12px; color: #94a3b8; font-weight: 600;">
                            Feature ${currentStep + 1} of ${total}
                        </span>
                    </div>
                    <button id="csTourCloseBtn" style="background: transparent; border: none; color: #94a3b8; font-size: 18px; cursor: pointer; padding: 4px 8px; border-radius: 6px; line-height: 1;" title="Close Tour">✕</button>
                </div>

                <!-- Progress Bar -->
                <div style="width: 100%; height: 4px; background: rgba(255, 255, 255, 0.08); border-radius: 2px; margin-bottom: 20px; overflow: hidden;">
                    <div style="width: ${progressPct}%; height: 100%; background: linear-gradient(90deg, #38bdf8, #818cf8); transition: width 0.3s ease;"></div>
                </div>

                <!-- Feature Hero Info -->
                <div style="display: flex; align-items: flex-start; gap: 14px; margin-bottom: 14px;">
                    <div style="width: 50px; height: 50px; border-radius: 12px; background: rgba(56, 189, 248, 0.12); border: 1.5px solid rgba(56, 189, 248, 0.35); display: flex; align-items: center; justify-content: center; font-size: 26px; flex-shrink: 0; box-shadow: 0 0 20px rgba(56, 189, 248, 0.2);">
                        ${feat.icon}
                    </div>
                    <div>
                        <h2 style="margin: 0 0 4px 0; font-size: 19px; font-weight: 800; color: #ffffff; letter-spacing: -0.3px;">
                            ${feat.title}
                        </h2>
                        <div style="font-size: 12.5px; color: #38bdf8; font-weight: 600; line-height: 1.4;">
                            ${feat.tagline}
                        </div>
                    </div>
                </div>

                <!-- Feature Narrative -->
                <p style="margin: 0 0 16px 0; font-size: 13px; color: #cbd5e1; line-height: 1.55;">
                    ${feat.description}
                </p>

                <!-- Key Capabilities Box -->
                <div style="background: rgba(2, 6, 23, 0.65); border: 1px solid rgba(255, 255, 255, 0.08); border-radius: 12px; padding: 14px 16px; margin-bottom: 22px;">
                    <div style="font-size: 11px; font-weight: 800; color: #94a3b8; text-transform: uppercase; letter-spacing: 0.6px; margin-bottom: 10px;">
                        ✦ Core Capabilities Included:
                    </div>
                    <ul style="margin: 0; padding: 0 0 0 18px; display: flex; flex-direction: column; gap: 7px;">
                        ${feat.highlights.map(h => `
                            <li style="font-size: 12.5px; color: #e2e8f0; line-height: 1.4;">
                                ${h}
                            </li>
                        `).join("")}
                    </ul>
                </div>

                <!-- Footer Action Bar -->
                <div style="display: flex; justify-content: space-between; align-items: center; gap: 12px; flex-wrap: wrap;">
                    <!-- Step Dots -->
                    <div style="display: flex; align-items: center; gap: 6px;">
                        ${TOUR_FEATURES.map((_, idx) => `
                            <div class="cs-tour-dot ${idx === currentStep ? 'active' : ''}" onclick="CyberShieldTour.goToStep(${idx})" title="Go to feature ${idx + 1}"></div>
                        `).join("")}
                    </div>

                    <!-- Navigation Controls -->
                    <div style="display: flex; align-items: center; gap: 8px;">
                        <a href="${feat.link}" target="_self" class="cs-tour-btn-secondary" style="text-decoration: none; font-size: 12px; padding: 7px 12px;">
                            ${feat.linkText}
                        </a>
                        ${currentStep > 0 ? `
                            <button id="csTourPrevBtn" class="cs-tour-btn-secondary" style="padding: 7px 12px; font-size: 12px;">
                                ◀ Back
                            </button>
                        ` : ''}
                        ${currentStep < total - 1 ? `
                            <button id="csTourNextBtn" class="cs-tour-btn-primary" style="padding: 8px 16px; font-size: 13px;">
                                Next Feature ▶
                            </button>
                        ` : `
                            <button id="csTourFinishBtn" class="cs-tour-btn-primary" style="background: linear-gradient(135deg, #10b981, #059669); border-color: #34d399; padding: 8px 18px; font-size: 13px;">
                                🎉 Get Started
                            </button>
                        `}
                    </div>
                </div>
            </div>
        `;

        document.body.appendChild(overlay);

        // Attach Event Listeners
        document.getElementById("csTourCloseBtn")?.addEventListener("click", closeTour);
        document.getElementById("csTourPrevBtn")?.addEventListener("click", prevStep);
        document.getElementById("csTourNextBtn")?.addEventListener("click", nextStep);
        document.getElementById("csTourFinishBtn")?.addEventListener("click", finishTour);
    }

    function nextStep() {
        if (currentStep < TOUR_FEATURES.length - 1) {
            currentStep++;
            renderTourModal();
        }
    }

    function prevStep() {
        if (currentStep > 0) {
            currentStep--;
            renderTourModal();
        }
    }

    function goToStep(idx) {
        if (idx >= 0 && idx < TOUR_FEATURES.length) {
            currentStep = idx;
            renderTourModal();
        }
    }

    function closeTour() {
        const overlay = document.getElementById("cybershield-tour-overlay");
        if (overlay) overlay.remove();
        cleanUrlParams();
    }

    function finishTour() {
        try {
            localStorage.setItem("cybershield_onboarding_completed", "true");
        } catch (e) {}
        closeTour();
        if (window.CyberShieldUtils) {
            CyberShieldUtils.showToast("Welcome to CyberShield AI! All security shields are active.", "success");
        }
    }

    function cleanUrlParams() {
        if (window.location.search.includes("onboarding=true")) {
            const url = new URL(window.location.href);
            url.searchParams.delete("onboarding");
            window.history.replaceState({}, document.title, url.pathname + (url.search ? url.search : ""));
        }
    }

    function startTour(initialStep = 0) {
        currentStep = initialStep;
        renderTourModal();
    }

    // Auto-launch if ?onboarding=true is present in the URL
    document.addEventListener("DOMContentLoaded", () => {
        const params = new URLSearchParams(window.location.search);
        if (params.get("onboarding") === "true") {
            setTimeout(() => {
                startTour(0);
            }, 300);
        }
    });

    window.CyberShieldTour = {
        startTour,
        nextStep,
        prevStep,
        goToStep,
        closeTour,
        finishTour,
        features: TOUR_FEATURES
    };
})();
