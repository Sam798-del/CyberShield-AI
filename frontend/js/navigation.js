/* =========================================================
   CYBERSHIELD AI — UNIFIED NAVIGATION & APP SHELL
   ========================================================= */

const CyberShieldNav = {
    icons: {
        grid: '<svg viewBox="0 0 24 24"><rect x="4" y="4" width="6" height="6"/><rect x="14" y="4" width="6" height="6"/><rect x="4" y="14" width="6" height="6"/><rect x="14" y="14" width="6" height="6"/></svg>',
        fingerprint: '<svg viewBox="0 0 24 24"><path d="M12 11a2 2 0 0 1 2 2c0 4-1 6-2 8M8 13c0-2.2 1.8-4 4-4s4 1.8 4 4c0 3.1-.6 5.4-1.3 7M4 13a8 8 0 0 1 16 0c0 3.2-.6 5.7-1.4 8M12 5a8 8 0 0 0-8 8"/></svg>',
        shield: '<svg viewBox="0 0 24 24"><path d="M12 3 20 6v5c0 5-3.3 8.7-8 10-4.7-1.3-8-5-8-10V6l8-3Z"/></svg>',
        triangle: '<svg viewBox="0 0 24 24"><path d="m12 3 10 18H2L12 3Z"/><path d="M12 9v4M12 17h.01"/></svg>',
        database: '<svg viewBox="0 0 24 24"><ellipse cx="12" cy="5" rx="8" ry="3"/><path d="M4 5v7c0 1.7 3.6 3 8 3s8-1.3 8-3V5M4 12v7c0 1.7 3.6 3 8 3s8-1.3 8-3v-7"/></svg>',
        user: '<svg viewBox="0 0 24 24"><circle cx="12" cy="8" r="3"/><path d="M5 20a7 7 0 0 1 14 0"/></svg>',
        bell: '<svg viewBox="0 0 24 24"><path d="M18 8a6 6 0 0 0-12 0c0 7-3 7-3 9h18c0-2-3-2-3-9M10 21h4"/></svg>',
        book: '<svg viewBox="0 0 24 24"><path d="M4 19.5A2.5 2.5 0 0 1 6.5 17H20"/><path d="M6.5 2H20v20H6.5A2.5 2.5 0 0 1 4 19.5v-15A2.5 2.5 0 0 1 6.5 2z"/></svg>'
    },

    init(activePageId) {
        this.renderSidebar(activePageId);
        this.renderTopHeader();
        this.renderMobileBottomNav(activePageId);
    },

    renderSidebar(activePageId) {
        const sidebarContainer = document.getElementById("cs-sidebar-container");
        if (!sidebarContainer) return;

        const navItems = [
            { id: "dashboard", label: "Dashboard", icon: "grid", href: "dashboard.html" },
            { id: "digital-identity", label: "Digital Identity", icon: "fingerprint", href: "digital-identity.html" },
            { id: "security-analyzer", label: "Security Analyzer", icon: "shield", href: "security-analyzer.html" },
            { id: "phishing-detection", label: "Phishing Detection", icon: "triangle", href: "phishing-detection.html" },
            { id: "cyberbullying-detection", label: "Cyberbullying Detection", icon: "shield", href: "cyberbullying-detection.html" },
            { id: "security-report", label: "AI Security Report", icon: "database", href: "security-report.html" },
            { id: "settings", label: "Profile / Settings", icon: "user", href: "settings.html" }
        ];

        const navHtml = navItems.map(item => `
            <a href="${item.href}" class="nav-item ${item.id === activePageId ? 'active' : ''}">
                ${this.icons[item.icon] || this.icons.shield}
                <span>${item.label}</span>
            </a>
        `).join("");

        sidebarContainer.innerHTML = `
            <aside class="sidebar">
                <a href="dashboard.html" class="brand">
                    ${this.icons.shield}
                    <div>
                        <div class="brand-name">CyberShield AI</div>
                        <div class="brand-tagline">Think. Detect. Stay Safe.</div>
                    </div>
                </a>
                <div class="nav-label">Workspace</div>
                <nav class="nav">
                    ${navHtml}
                </nav>
                <div class="sidebar-spacer"></div>
                <div class="sidebar-promo">
                    ${this.icons.shield}
                    <strong>Stronger<br>Passwords. Safer You.</strong>
                    <span>Protected by CyberShield AI</span>
                </div>
            </aside>
        `;
    },

    renderTopHeader() {
        const headerContainer = document.getElementById("cs-header-container");
        if (!headerContainer) return;

        let initials = 'NS';
        let userName = 'Neeraja Shinde';
        if (window.CyberShieldState) {
            const state = CyberShieldState.getState();
            if (state.user) {
                if (state.user.avatarInitials) initials = state.user.avatarInitials;
                if (state.user.name) userName = state.user.name;
            }
        }

        headerContainer.innerHTML = `
            <header class="topbar">
                <div class="top-actions">
                    <a href="guide.html" class="icon-button" title="Guide & Security Center">
                        ${this.icons.book}
                    </a>
                    <button class="icon-button" title="Alerts" onclick="if(window.CyberShieldUtils) CyberShieldUtils.showToast('Workspace is secure and up to date','success'); else alert('Workspace is secure');">
                        ${this.icons.bell}
                    </button>
                    <a href="settings.html" class="avatar" title="${userName}">${initials}</a>
                </div>
            </header>
        `;
    },

    renderMobileBottomNav(activePageId) {
        let bottomNav = document.getElementById("cs-mobile-bottom-nav");
        if (!bottomNav) {
            bottomNav = document.createElement("div");
            bottomNav.id = "cs-mobile-bottom-nav";
            bottomNav.className = "bottom-nav";
            document.body.appendChild(bottomNav);
        }

        bottomNav.innerHTML = `
            <a href="dashboard.html" class="nav-item ${activePageId === 'dashboard' ? 'active' : ''}">
                ${this.icons.grid} <span>Home</span>
            </a>
            <a href="security-analyzer.html" class="nav-item ${activePageId === 'security-analyzer' ? 'active' : ''}">
                ${this.icons.shield} <span>Analyzer</span>
            </a>
            <a href="phishing-detection.html" class="nav-item ${activePageId === 'phishing-detection' ? 'active' : ''}">
                ${this.icons.triangle} <span>Phishing</span>
            </a>
            <a href="security-report.html" class="nav-item ${activePageId === 'security-report' ? 'active' : ''}">
                ${this.icons.database} <span>Report</span>
            </a>
        `;
    }
};

window.CyberShieldNav = CyberShieldNav;
