/* =========================================================
   CYBERSHIELD AI — MOBILE ANDROID-LIKE EXPERIENCE
   ========================================================= */

const CyberShieldMobile = {

  isMobile() {
    return window.innerWidth <= 768;
  },

  /* ── Splash Screen ───────────────────────────────────── */
  initSplash() {
    // Only show splash on first visit per session
    if (sessionStorage.getItem('cs_splash_shown')) return;
    if (!this.isMobile()) return;

    sessionStorage.setItem('cs_splash_shown', '1');

    const splash = document.createElement('div');
    splash.id = 'cs-splash';
    splash.innerHTML = `
      <div class="splash-logo">
        <img src="../assets/icon-48.png" alt="CyberShield" onerror="this.style.display='none'; this.parentElement.innerHTML='🛡️';">
      </div>
      <div class="splash-title">CyberShield AI</div>
      <div class="splash-subtitle">Think · Detect · Stay Safe</div>
      <div class="splash-loader">
        <div class="splash-loader-bar"></div>
      </div>
    `;
    document.body.prepend(splash);

    // Auto-dismiss after 2.5s
    setTimeout(() => {
      splash.classList.add('hidden');
      setTimeout(() => splash.remove(), 700);
    }, 2500);
  },

  /* ── Bottom Navigation ───────────────────────────────── */
  initBottomNav(activePageId) {
    if (!this.isMobile()) return;

    // Remove any existing bottom nav
    const existing = document.getElementById('cs-bottom-nav');
    if (existing) existing.remove();

    const navItems = [
      {
        id: 'dashboard',
        label: 'Home',
        href: 'dashboard.html',
        icon: `<svg viewBox="0 0 24 24"><rect x="3" y="3" width="7" height="7" rx="1"/><rect x="14" y="3" width="7" height="7" rx="1"/><rect x="3" y="14" width="7" height="7" rx="1"/><rect x="14" y="14" width="7" height="7" rx="1"/></svg>`
      },
      {
        id: 'digital-identity',
        label: 'Identity',
        href: 'digital-identity.html',
        icon: `<svg viewBox="0 0 24 24"><path d="M12 11a2 2 0 0 1 2 2c0 4-1 6-2 8M8 13c0-2.2 1.8-4 4-4s4 1.8 4 4c0 3.1-.6 5.4-1.3 7M4 13a8 8 0 0 1 16 0c0 3.2-.6 5.7-1.4 8M12 5a8 8 0 0 0-8 8"/></svg>`
      },
      {
        id: 'security-analyzer',
        label: 'Scanner',
        href: 'security-analyzer.html',
        icon: `<svg viewBox="0 0 24 24"><path d="M12 3 20 6v5c0 5-3.3 8.7-8 10-4.7-1.3-8-5-8-10V6l8-3Z"/></svg>`
      },
      {
        id: 'security-report',
        label: 'Report',
        href: 'security-report.html',
        icon: `<svg viewBox="0 0 24 24"><ellipse cx="12" cy="5" rx="8" ry="3"/><path d="M4 5v7c0 1.7 3.6 3 8 3s8-1.3 8-3V5M4 12v7c0 1.7 3.6 3 8 3s8-1.3 8-3v-7"/></svg>`
      },
      {
        id: 'settings',
        label: 'Profile',
        href: 'settings.html',
        icon: `<svg viewBox="0 0 24 24"><circle cx="12" cy="8" r="3"/><path d="M5 20a7 7 0 0 1 14 0"/></svg>`
      }
    ];

    const nav = document.createElement('nav');
    nav.id = 'cs-bottom-nav';
    nav.setAttribute('role', 'navigation');
    nav.setAttribute('aria-label', 'Main navigation');

    const inner = document.createElement('div');
    inner.className = 'bottom-nav-inner';

    navItems.forEach(item => {
      const isActive = item.id === activePageId;
      const link = document.createElement('a');
      link.href = item.href;
      link.className = 'bottom-nav-item' + (isActive ? ' active' : '');
      link.setAttribute('aria-label', item.label);
      link.setAttribute('aria-current', isActive ? 'page' : 'false');
      link.innerHTML = `
        <div class="bottom-nav-pill">${item.icon}</div>
        <span class="bottom-nav-label">${item.label}</span>
      `;

      // Ripple on tap
      link.addEventListener('click', (e) => {
        if (navigator.vibrate) navigator.vibrate(10);
      });

      inner.appendChild(link);
    });

    nav.appendChild(inner);
    document.body.appendChild(nav);
  },

  /* ── Mobile Header ───────────────────────────────────── */
  initMobileHeader() {
    if (!this.isMobile()) return;

    const headerContainer = document.getElementById('cs-header-container');
    if (!headerContainer) return;

    let initials = 'CS';
    let userName = 'User';
    if (window.CyberShieldState) {
      const state = CyberShieldState.getState();
      if (state && state.user) {
        if (state.user.avatarInitials) initials = state.user.avatarInitials;
        if (state.user.name) userName = state.user.name;
      }
    }

    // Insert mobile header before the topbar
    const mobileHeader = document.createElement('div');
    mobileHeader.className = 'cs-mobile-header';
    mobileHeader.innerHTML = `
      <a href="dashboard.html" class="cs-mobile-header-brand">
        <img src="../assets/icon-48.png" alt="CyberShield" onerror="this.style.display='none'">
        <span>CyberShield AI</span>
      </a>
      <div class="cs-mobile-header-actions">
        <a href="settings.html" class="cs-mobile-avatar" title="${userName}">${initials}</a>
      </div>
    `;
    headerContainer.insertBefore(mobileHeader, headerContainer.firstChild);
  },

  /* ── Android-style Toast ─────────────────────────────── */
  showToast(message, duration = 3000) {
    // Remove existing toast
    const existing = document.querySelector('.cs-toast');
    if (existing) existing.remove();

    const toast = document.createElement('div');
    toast.className = 'cs-toast';
    toast.textContent = message;
    document.body.appendChild(toast);

    requestAnimationFrame(() => {
      requestAnimationFrame(() => {
        toast.classList.add('show');
      });
    });

    setTimeout(() => {
      toast.classList.remove('show');
      setTimeout(() => toast.remove(), 400);
    }, duration);
  },

  /* ── Ripple Effect on Cards ──────────────────────────── */
  initRipples() {
    if (!this.isMobile()) return;
    document.querySelectorAll('.panel, .card, .gauge-card').forEach(el => {
      el.classList.add('cs-ripple');
    });
  },

  /* ── PWA Install Prompt ──────────────────────────────── */
  initPWA() {
    let deferredPrompt = null;

    window.addEventListener('beforeinstallprompt', (e) => {
      e.preventDefault();
      deferredPrompt = e;

      // Show install toast after 3s on mobile
      if (this.isMobile()) {
        setTimeout(() => {
          this.showToast('📲 Add to Home Screen for the best experience!', 5000);
        }, 3000);
      }
    });

    window.addEventListener('appinstalled', () => {
      deferredPrompt = null;
      this.showToast('✅ CyberShield AI installed!', 3000);
    });
  },

  /* ── Main Init ───────────────────────────────────────── */
  init(activePageId) {
    if (!this.isMobile()) return;

    this.initSplash();
    this.initBottomNav(activePageId);
    this.initMobileHeader();
    this.initRipples();
    this.initPWA();

    // Add page entrance animation
    const main = document.querySelector('.main, .main-content');
    if (main) {
      main.style.animation = 'slideInUp 0.3s ease both';
    }
  }
};

window.CyberShieldMobile = CyberShieldMobile;
