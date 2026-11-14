# 🛡️ CyberShield-AI — Intelligent Cyber Defense & Threat Intelligence Platform

> **"Think. Detect. Stay Safe."**  
> CyberShield-AI is an end-to-end, AI-powered cybersecurity suite that protects individuals and organizations from modern digital threats in real time — including phishing campaigns, social media toxicity & cyberbullying, compromised credentials, and vulnerable domains.

🌐 **Live Web Application**: [https://cybershield-ai-rlk5.onrender.com](https://cybershield-ai-rlk5.onrender.com)  
💻 **GitHub Repository**: [https://github.com/Sam798-del/CyberShield-AI](https://github.com/Sam798-del/CyberShield-AI)

---

## 🌟 Key Features

| Feature | Description |
|---|---|
| 🎣 **Phishing & Scam Detection** | Real-time URL and email header scanner that identifies typosquatting, zero-day phishing heuristics, spoofed domains, and deceptive links. |
| 🔑 **Password Shield & Entropy Analyzer** | Real-time evaluation of password entropy, brute-force crack time estimates, and Have-I-Been-Pwned breach checks with zero typing lag. |
| 💬 **Cyberbullying & Toxicity Shield** | NLP-powered harassment detection that scans text and social interactions, flagging toxic, abusive, or threatening language. |
| 🛡️ **Digital Identity Vault** | Centralized credential exposure and cross-service breach monitoring powered by breach footprint mapping (Have I Been Pwned & XposedOrNot). |
| 📊 **Unified Security Command Center** | Real-time aggregate telemetry score, threat quarantine logs, compliance posture, and downloadable security audit reports. |
| 🧩 **Browser Defense Extension** | Manifest V3 Chrome Extension providing active in-browser URL auto-scanning, domain leak alerts, and one-click access to all defense tools. |

---

## 🚀 Quick Start: Running the Main Web Platform

### Option 1: Live Deployment (Instant Access)
Open directly in your web browser — no installation needed:  
👉 **[https://cybershield-ai-rlk5.onrender.com](https://cybershield-ai-rlk5.onrender.com)**

---

### Option 2: Run Locally on Your Machine

#### Prerequisites
- **Python 3.10+** installed
- **Git** installed

#### 1. Clone the Repository
```bash
git clone https://github.com/Sam798-del/CyberShield-AI.git
cd CyberShield-AI
```

#### 2. Install Dependencies
```bash
pip install -r requirements.txt
```

#### 3. Start the Server
- **Windows (One-Click)**: Double-click `run_server.bat`
- **Or via Command Line**:
```bash
python app.py
```

The application will be live at: **[http://127.0.0.1:5000](http://127.0.0.1:5000)**

#### 4. Access Platform Modules
- 🏠 **Portal Home**: [http://127.0.0.1:5000/index.html](http://127.0.0.1:5000/index.html)
- 📊 **Security Dashboard**: [http://127.0.0.1:5000/pages/dashboard.html](http://127.0.0.1:5000/pages/dashboard.html)
- 🎣 **Phishing Scanner**: [http://127.0.0.1:5000/pages/phishing-detection.html](http://127.0.0.1:5000/pages/phishing-detection.html)
- 🔍 **Security & Password Analyzer**: [http://127.0.0.1:5000/pages/security-analyzer.html](http://127.0.0.1:5000/pages/security-analyzer.html)
- 🛡️ **Digital Identity Vault**: [http://127.0.0.1:5000/pages/digital-identity.html](http://127.0.0.1:5000/pages/digital-identity.html)
- 💬 **Cyberbullying Detection**: [http://127.0.0.1:5000/pages/cyberbullying-detection.html](http://127.0.0.1:5000/pages/cyberbullying-detection.html)
- 📖 **Guidance Hub**: [http://127.0.0.1:5000/pages/guide.html](http://127.0.0.1:5000/pages/guide.html)
- 📄 **AI Security Report**: [http://127.0.0.1:5000/pages/security-report.html](http://127.0.0.1:5000/pages/security-report.html)

---

## 🧩 Installing & Using the Chrome Browser Extension

The Chrome extension delivers real-time protection directly in your browser as you browse the web.

### Step-by-Step Installation:

1. Open Google Chrome and navigate to:
   ```
   chrome://extensions
   ```
2. Enable **Developer mode** using the toggle switch in the top-right corner.
3. Click the **"Load unpacked"** button in the top-left corner.
4. Browse to and select the **`extension`** subfolder inside the project:
   ```
   CyberShield-AI/extension
   ```
   > ⚠️ **Important**: Do **not** select the root project folder. Make sure you select the `extension` folder which directly contains `manifest.json`.
5. The **CyberShield AI — Real-Time Browser Defense** extension is now active! Pin it to your Chrome toolbar for easy access.

### Using the Extension:
- **Auto-Protection**: Automatically evaluates the security, SSL certificates, and typosquatting risk of any website you visit.
- **Check Breaches**: Click **⚡ Check Breaches** to verify if the active domain has documented data leaks.
- **Direct Navigation**: Click on any feature button in the quick action grid (**Analyzer**, **Phishing**, **Identity**, **Dashboard**, **AI Report**, **Guide**, or **Bullying**) to launch the full web interface.
- **Cloud vs. Local Mode**: Click ⚙️ Settings inside the popup to toggle between the **Live Render Cloud** (`https://cybershield-ai-rlk5.onrender.com`) or **Localhost:5000**.

---

## 📁 Repository Structure

```text
CyberShield-AI/
├── app.py                             # Unified Flask REST API backend & static file server
├── requirements.txt                   # Backend Python dependencies
├── run_server.bat                     # Windows one-click local server launcher
├── test_backend.py                    # Automated test suite (7/7 unit tests)
├── vercel.json                        # Serverless cloud deployment config
│
├── extension/                         # Chrome Extension (Manifest V3)
│   ├── manifest.json                  # Extension configuration & permissions
│   ├── popup/                         # Extension UI (popup.html, popup.js, popup.css)
│   ├── scripts/                       # Background service worker & content scripts
│   └── assets/                        # Extension icons & graphics
│
├── frontend/                          # Web Application Interface
│   ├── index.html                     # Portal home landing page
│   ├── css/ & js/                     # Shared styles, themes, and client utilities
│   └── pages/                         # Feature-specific platform modules
│       ├── dashboard.html             # Command Center Dashboard
│       ├── phishing-detection.html    # Live Phishing & Scam URL Scanner
│       ├── security-analyzer.html     # Password Strength & Domain Breach Analyzer
│       ├── digital-identity.html      # Digital Identity Vault & Exposure Tracking
│       ├── cyberbullying-detection.html # NLP Toxic Text & Harassment Detection
│       ├── guide.html                 # Interactive Guidance Assistant
│       ├── security-report.html       # Automated Audit & Compliance Report
│       ├── settings.html              # System & Zero-Trust Configuration
│       └── login.html                 # Authentication & Registration
│
└── security-analyzer/                 # Security analyzer microservice module
```

---

## 🧪 Testing

To run the automated backend test suite:
```bash
python test_backend.py
```
Expected output:
```text
Ran 7 tests in 0.073s
OK
```

---

## 🛡️ License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.
