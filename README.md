# CyberShield-AI Platform

**CyberShield-AI** is an intelligent cybersecurity & threat defense platform featuring real-time phishing detection, cyberbullying & toxicity analysis, digital identity protection, domain vulnerability diagnostics, and interactive threat guidance.

---

## 🌐 Live Cloud Deployment (Render)

CyberShield-AI is actively deployed and hosted on **Render**:
- **Production URL:** [https://cybershield-ai-rlk5.onrender.com](https://cybershield-ai-rlk5.onrender.com)
- **API Health Endpoint:** [https://cybershield-ai-rlk5.onrender.com/api/health](https://cybershield-ai-rlk5.onrender.com/api/health)
- **Cyberbullying & Toxicity NLP Analyzer:** [https://cybershield-ai-rlk5.onrender.com/pages/cyberbullying-detection.html](https://cybershield-ai-rlk5.onrender.com/pages/cyberbullying-detection.html)
- **Security Command Dashboard:** [https://cybershield-ai-rlk5.onrender.com/pages/dashboard.html](https://cybershield-ai-rlk5.onrender.com/pages/dashboard.html)
- **Guidance & Education Hub:** [https://cybershield-ai-rlk5.onrender.com/pages/guide.html](https://cybershield-ai-rlk5.onrender.com/pages/guide.html)
- **Digital Identity Vault:** [https://cybershield-ai-rlk5.onrender.com/pages/digital-identity.html](https://cybershield-ai-rlk5.onrender.com/pages/digital-identity.html)
- **Settings & Zero-Trust Preferences:** [https://cybershield-ai-rlk5.onrender.com/pages/settings.html](https://cybershield-ai-rlk5.onrender.com/pages/settings.html)

---

## 📁 Repository Directory Structure

```text
CyberShield-AI/
│
├── README.md                          # Project documentation & live links
├── app.py                             # Flask REST API backend server & static router
├── test_backend.py                    # Backend & integration unit test suite
├── requirements.txt                   # Python dependencies (Flask, Flask-CORS, etc.)
├── run_server.bat                     # One-click deployment launch script
├── cybershield.db                     # SQLite database for progress & settings persistence
│
├── modules/                           # Core AI & Detection modules
│   ├── toxicity_engine.py             # SVO Grammar & Jigsaw Cyberbullying Classifier
│   └── datasets/                      # Benchmark toxicity corpora
│
├── extension/                         # Chrome Browser Security Extension (Manifest V3)
│   ├── manifest.json                  # Extension permissions & entrypoints
│   ├── popup/                         # Real-time defense popup UI
│   ├── scripts/                       # Background service worker & content guard
│   └── test_playground.html           # Interactive 5-stage extension test suite
│
└── frontend/                          # Web application frontend
    │
    ├── index.html                     # Portal landing page & feature launcher
    │
    └── pages/                         # Core web application feature pages
        ├── guide.html                 # Guidance Hub & Interactive Security Assistant
        ├── dashboard.html             # Security Command Dashboard & Threat Telemetry
        ├── digital-identity.html      # Digital Identity Vault & Breach Monitor
        ├── security-analyzer.html     # System & Domain Vulnerability Diagnostics
        ├── phishing-detection.html    # Live Phishing & Email Header Scanner
        ├── cyberbullying-detection.html # Cyberbullying & Toxicity NLP Analyzer
        ├── security-report.html       # Security Compliance & Audit Report Generator
        ├── settings.html              # System Preferences & Zero-Trust Configuration
        └── login.html                 # Sign In & Account Registration
```

---

## 🛡️ Chrome Browser Defense Extension

The CyberShield AI Extension (`extension/`) injects real-time client guards into web browsing sessions:
- **Domain Phishing Radar:** Checks visited URLs against typosquatting, homoglyph lookalikes, and IP hostnames.
- **In-Page Toxic Content Blurring:** Automatically hides severe harassment and relational bullying comments with red alert shields.
- **Outbound Message Blocker ("Think Before You Post"):** Intercepts toxic comments before they can be posted, preventing cyberbullying transmission and prompting the user with an interactive `[ ✏️ Edit Message ]` action.
- **In-Field Password Entropy Tips:** Live feedback inside password inputs calculating entropy and character complexity.
- **Interactive Verification Suite:** Test all extension features on [http://localhost:5000/test-playground](http://localhost:5000/test-playground).

---

## 🚀 Local Deployment & Development

### 1. One-Click Launch Script
Double-click `run_server.bat` inside the root directory.

### 2. Manual Launch
```bash
pip install -r requirements.txt
python app.py
```

Access the frontend pages in your browser:
- **Portal Landing Page**: [http://127.0.0.1:5000/index.html](http://127.0.0.1:5000/index.html)
- **Guidance Hub**: [http://127.0.0.1:5000/pages/guide.html](http://127.0.0.1:5000/pages/guide.html)
- **Security Dashboard**: [http://127.0.0.1:5000/pages/dashboard.html](http://127.0.0.1:5000/pages/dashboard.html)
- **Cyberbullying Analyzer**: [http://127.0.0.1:5000/pages/cyberbullying-detection.html](http://127.0.0.1:5000/pages/cyberbullying-detection.html)
- **Extension Test Playground**: [http://127.0.0.1:5000/test-playground](http://127.0.0.1:5000/test-playground)
- **Digital Identity Vault**: [http://127.0.0.1:5000/pages/digital-identity.html](http://127.0.0.1:5000/pages/digital-identity.html)
- **Sign In / Registration**: [http://127.0.0.1:5000/pages/login.html](http://127.0.0.1:5000/pages/login.html)
- **Settings Page**: [http://127.0.0.1:5000/pages/settings.html](http://127.0.0.1:5000/pages/settings.html)

### 3. Run Unit Tests
```bash
python test_backend.py
```
