# CyberShield-AI Platform

**CyberShield-AI** is an intelligent cybersecurity & threat defense platform featuring real-time phishing detection, cyberbullying & toxicity analysis, digital identity protection, domain vulnerability diagnostics, and interactive threat guidance.

---

## 📁 Repository Directory Structure

```text
CyberShield-AI/
│
├── README.md                          # Project documentation
├── vercel.json                        # Direct Vercel deployment configuration
├── app.py                             # Flask REST API backend server & static router
├── test_backend.py                    # Backend & integration unit test suite
├── requirements.txt                   # Python dependencies (Flask, Flask-CORS, etc.)
├── run_server.bat                     # One-click deployment launch script
├── cybershield.db                     # SQLite database for progress & settings persistence
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

## ⚡ Direct Vercel Deployment

### Option A: Import GitHub Repo to Vercel (Recommended)
1. Go to [vercel.com/new](https://vercel.com/new).
2. Select and import your GitHub repository: `Sam798-del/CyberShield-AI`.
3. Vercel automatically reads `vercel.json`, deploys `@vercel/python` backend and static frontend.
4. Your application is live at `https://cybershield-ai.vercel.app`.

### Option B: Deploy via Vercel CLI
```bash
npx vercel
npx vercel --prod
```

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
- **Digital Identity Vault**: [http://127.0.0.1:5000/pages/digital-identity.html](http://127.0.0.1:5000/pages/digital-identity.html)
- **Sign In / Registration**: [http://127.0.0.1:5000/pages/login.html](http://127.0.0.1:5000/pages/login.html)
- **Settings Page**: [http://127.0.0.1:5000/pages/settings.html](http://127.0.0.1:5000/pages/settings.html)

### 3. Run Unit Tests
```bash
python test_backend.py
```
