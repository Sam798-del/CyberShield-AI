# CyberShield-AI Platform

**CyberShield-AI** is an intelligent cybersecurity & threat defense platform featuring real-time phishing detection, cyberbullying & toxicity analysis, digital identity protection, domain vulnerability diagnostics, and interactive threat guidance.

---

## 📁 Repository Directory Structure

```text
CyberShield-AI/
│
├── README.md                          # Project documentation
├── app.py                             # Flask REST API backend server & static router
├── test_backend.py                    # Backend & integration unit test suite
├── requirements.txt                   # Python dependencies (Flask, Flask-CORS, etc.)
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
        └── settings.html              # System Preferences & Zero-Trust Configuration
```

---

## 🚀 Getting Started

### 1. Install Dependencies
```bash
pip install -r requirements.txt
```

### 2. Run Backend Server
```bash
python app.py
```

Access the frontend pages in your browser:
- **Portal Landing Page**: [http://127.0.0.1:5000/index.html](http://127.0.0.1:5000/index.html)
- **Guidance Hub**: [http://127.0.0.1:5000/pages/guide.html](http://127.0.0.1:5000/pages/guide.html)
- **Security Dashboard**: [http://127.0.0.1:5000/pages/dashboard.html](http://127.0.0.1:5000/pages/dashboard.html)
- **Settings Page**: [http://127.0.0.1:5000/pages/settings.html](http://127.0.0.1:5000/pages/settings.html)

### 3. Run Unit Tests
```bash
python test_backend.py
```
