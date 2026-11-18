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

    const morePages = ['phishing-detection', 'cyberbullying-detection', 'settings', 'guide'];
    const isMoreActive = morePages.includes(activePageId);

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
        id: 'more',
        label: 'Features',
        isAction: true,
        icon: `<svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="1.5"/><circle cx="19" cy="12" r="1.5"/><circle cx="5" cy="12" r="1.5"/><circle cx="12" cy="5" r="1.5"/><circle cx="12" cy="19" r="1.5"/></svg>`
      }
    ];

    const nav = document.createElement('nav');
    nav.id = 'cs-bottom-nav';
    nav.setAttribute('role', 'navigation');
    nav.setAttribute('aria-label', 'Main navigation');

    const inner = document.createElement('div');
    inner.className = 'bottom-nav-inner';

    navItems.forEach(item => {
      const isActive = item.isAction ? isMoreActive : item.id === activePageId;
      const link = document.createElement(item.isAction ? 'button' : 'a');
      if (!item.isAction) link.href = item.href;
      link.className = 'bottom-nav-item' + (isActive ? ' active' : '');
      link.setAttribute('aria-label', item.label);
      link.setAttribute('aria-current', isActive ? 'page' : 'false');
      link.innerHTML = `
        <div class="bottom-nav-pill">${item.icon}</div>
        <span class="bottom-nav-label">${item.label}</span>
      `;

      if (item.isAction) {
        link.addEventListener('click', (e) => {
          e.preventDefault();
          if (navigator.vibrate) navigator.vibrate(10);
          CyberShieldMobile.toggleBottomSheet();
        });
      } else {
        link.addEventListener('click', () => {
          if (navigator.vibrate) navigator.vibrate(10);
        });
      }

      inner.appendChild(link);
    });

    nav.appendChild(inner);
    document.body.appendChild(nav);
    this.initBottomSheet(activePageId);
  },

  /* ── Android Bottom Sheet (More Features) ────────────── */
  initBottomSheet(activePageId) {
    const existing = document.getElementById('cs-sheet-wrap');
    if (existing) existing.remove();

    const wrap = document.createElement('div');
    wrap.id = 'cs-sheet-wrap';
    wrap.innerHTML = `
      <div class="cs-bottom-sheet-overlay" id="csSheetOverlay" onclick="CyberShieldMobile.toggleBottomSheet(false)"></div>
      <div class="cs-bottom-sheet" id="csBottomSheet">
        <div class="cs-sheet-handle"></div>
        <div class="cs-sheet-header">
          <div class="cs-sheet-title">🛡️ All CyberShield AI Features</div>
          <button type="button" onclick="CyberShieldMobile.toggleBottomSheet(false)" style="background:transparent; border:none; color:#8494be; font-size:16px; cursor:pointer;">✕</button>
        </div>
        <div class="cs-sheet-grid">
          <a href="dashboard.html" class="cs-sheet-item ${activePageId === 'dashboard' ? 'active' : ''}">
            <div class="cs-sheet-icon">📊</div>
            <div class="cs-sheet-label">Dashboard</div>
          </a>
          <a href="digital-identity.html" class="cs-sheet-item ${activePageId === 'digital-identity' ? 'active' : ''}">
            <div class="cs-sheet-icon">🔑</div>
            <div class="cs-sheet-label">Identity Vault</div>
          </a>
          <a href="security-analyzer.html" class="cs-sheet-item ${activePageId === 'security-analyzer' ? 'active' : ''}">
            <div class="cs-sheet-icon">🔍</div>
            <div class="cs-sheet-label">Analyzer</div>
          </a>
          <a href="phishing-detection.html" class="cs-sheet-item ${activePageId === 'phishing-detection' ? 'active' : ''}">
            <div class="cs-sheet-icon">📧</div>
            <div class="cs-sheet-label">Phishing</div>
          </a>
          <a href="cyberbullying-detection.html" class="cs-sheet-item ${activePageId === 'cyberbullying-detection' ? 'active' : ''}">
            <div class="cs-sheet-icon">💬</div>
            <div class="cs-sheet-label">Cyberbullying</div>
          </a>
          <a href="security-report.html" class="cs-sheet-item ${activePageId === 'security-report' ? 'active' : ''}">
            <div class="cs-sheet-icon">📈</div>
            <div class="cs-sheet-label">Reports</div>
          </a>
          <a href="guide.html" class="cs-sheet-item ${activePageId === 'guide' ? 'active' : ''}">
            <div class="cs-sheet-icon">📖</div>
            <div class="cs-sheet-label">User Guide</div>
          </a>
          <a href="javascript:void(0)" onclick="CyberShieldMobile.toggleBottomSheet(false); if(window.CyberShieldTour) CyberShieldTour.startTour();" class="cs-sheet-item">
            <div class="cs-sheet-icon">✦</div>
            <div class="cs-sheet-label">Feature Tour</div>
          </a>
          <a href="settings.html" class="cs-sheet-item ${activePageId === 'settings' ? 'active' : ''}">
            <div class="cs-sheet-icon">⚙️</div>
            <div class="cs-sheet-label">Settings</div>
          </a>
        </div>
        <div style="border-top: 1px solid rgba(239,68,68,0.2); padding-top: 12px; display: flex; justify-content: center;">
          <button onclick="if(window.CyberShieldNav) CyberShieldNav.logout();" style="background: rgba(239,68,68,0.15); border: 1px solid rgba(239,68,68,0.4); color: #fca5a5; font-size: 13px; font-weight: 700; padding: 10px 24px; border-radius: 10px; display: flex; align-items: center; gap: 8px; cursor: pointer; width: 100%; justify-content: center;">
            <span>🚪</span> Log Out
          </button>
        </div>
      </div>
    `;
    document.body.appendChild(wrap);
  },

  toggleBottomSheet(force) {
    const overlay = document.getElementById('csSheetOverlay');
    const sheet = document.getElementById('csBottomSheet');
    if (!overlay || !sheet) return;

    const isOpen = overlay.classList.contains('open');
    const nextState = typeof force === 'boolean' ? force : !isOpen;

    if (nextState) {
      overlay.classList.add('open');
      sheet.classList.add('open');
    } else {
      overlay.classList.remove('open');
      sheet.classList.remove('open');
    }
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
