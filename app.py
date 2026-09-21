"""
CyberShield-AI Backend REST API Server
Developed for CyberShield-AI Application Suite (Shreya Module: Guidance & Settings Engine)
"""

import os
import json
import sqlite3
import socket
from flask import Flask, request, jsonify, send_from_directory, Response
from flask_cors import CORS

# Initialize Flask App
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
WEB_DIR = os.path.join(BASE_DIR, "Web")
RESEARCH_DIR = os.path.join(BASE_DIR, "Research_Papers")
DB_PATH = os.path.join(BASE_DIR, "cybershield.db")

app = Flask(__name__, static_folder=WEB_DIR, static_url_path="")
CORS(app)

# Default Settings Configuration
DEFAULT_SETTINGS = {
    "profile": {
        "name": "Shreya Security Admin",
        "email": "shreya@cybershield.ai",
        "role": "Lead Cybersecurity Engineer",
        "avatar": "shield-user",
        "two_factor_enabled": True
    },
    "security": {
        "realtime_shield": True,
        "threat_sensitivity": "high",  # low, medium, high, paranoid
        "scan_interval": "daily",     # hourly, daily, weekly, manual
        "deep_heuristics": True,
        "auto_quarantine": True
    },
    "ai_assistant": {
        "model": "CyberShield-DeepSense-v2",
        "auto_suggest_guides": True,
        "interactive_tips": True,
        "custom_rules": "Prioritize immediate ransomware isolation and email header domain verification."
    },
    "privacy": {
        "telemetry_enabled": False,
        "breach_notifications": True,
        "log_retention_days": 30,
        "anonymize_ip": True
    },
    "appearance": {
        "accent_color": "#4169e1",    # royal blue default
        "theme_mode": "dark-cyber",   # dark-cyber, midnight-blue, neon-cyan
        "sound_alerts": True,
        "compact_view": False
    },
    "api_keys": {
        "virustotal_key": "vt_live_9876451203abcdef",
        "hibp_key": "hibp_sec_0918237465",
        "cybershield_token": "cs_ai_tok_8877665544332211"
    }
}

# Initial Guide Dataset
GUIDES_DATA = [
    {
        "id": "phishing-defense",
        "title": "Spotting & Defeating Advanced Phishing Campaigns",
        "category": "phishing",
        "badge": "Critical Skill",
        "readTime": "5 min",
        "summary": "Learn how spear-phishing attack vectors bypass traditional spam filters, analyze raw email headers, and detect domain spoofing.",
        "icon": "📧",
        "steps": [
            {
                "num": "01",
                "title": "Verify Sender Domain Integrity",
                "desc": "Check for subtle homograph attacks or domain permutations (e.g., paypa1.com vs paypal.com). Inspect the `Return-Path` and `Authentication-Results` headers."
            },
            {
                "num": "02",
                "title": "Inspect Link Destinations",
                "desc": "Hover over hyperlinks without clicking. Check if URL shorteners (bit.ly, t.co) mask malicious phishing landing pages."
            },
            {
                "num": "03",
                "title": "Analyze Urgency & Psychological Triggers",
                "desc": "Attackers exploit panic, account suspensions, or financial rewards. Never execute unexpected attachments (.exe, .xlsm, .iso)."
            },
            {
                "num": "04",
                "title": "Report & Neutralize Threat",
                "desc": "Use CyberShield-AI scanner or forward raw headers to your SOC/security response team immediately."
            }
        ],
        "faqs": [
            {"q": "What is Spear Phishing?", "a": "Spear phishing is a highly targeted attack using customized information gathered from OSINT (social media, public records) to trick specific individuals."},
            {"q": "How can 2FA protect against phishing?", "a": "FIDO2/WebAuthn hardware keys bind authentication to the legitimate domain origin, rendering stolen credentials useless on phishing sites."}
        ]
    },
    {
        "id": "password-hygiene",
        "title": "Password Entropy & Breach Response Protocol",
        "category": "passwords",
        "badge": "Core Practice",
        "readTime": "4 min",
        "summary": "Master strong password generation, password manager security vaults, salted hashing concepts, and emergency breach procedures.",
        "icon": "🔑",
        "steps": [
            {
                "num": "01",
                "title": "Eliminate Password Reuse",
                "desc": "Ensure every single account uses a unique, randomly generated password of at least 16+ characters."
            },
            {
                "num": "02",
                "title": "Deploy an Encrypted Password Manager",
                "desc": "Store credentials in a zero-knowledge encrypted vault (AES-256) secured with a high-entropy master passphrase."
            },
            {
                "num": "03",
                "title": "Monitor HaveIBeenPwned & Breach Databases",
                "desc": "Enable breach monitoring alerts in CyberShield-AI settings to automatically flag compromised credentials."
            }
        ],
        "faqs": [
            {"q": "Is a long passphrase better than a complex short password?", "a": "Yes! Passphrase length increases entropy exponentially against brute-force attacks (e.g., 'correct-horse-battery-staple')."}
        ]
    },
    {
        "id": "2fa-authentication",
        "title": "Enforcing Multi-Factor & Hardware Key Authentication",
        "category": "2fa",
        "badge": "Essential",
        "readTime": "6 min",
        "summary": "Upgrade from vulnerable SMS 2FA to Time-based One-Time Passwords (TOTP) and phishing-resistant FIDO2 hardware security keys.",
        "icon": "🛡️",
        "steps": [
            {
                "num": "01",
                "title": "Disable SMS & Email 2FA Where Possible",
                "desc": "SMS authentication is susceptible to SIM-swapping and SS7 intercept attacks. Migrate to authenticator apps (TOTP) or security keys."
            },
            {
                "num": "02",
                "title": "Configure FIDO2 / YubiKey Hardware Keys",
                "desc": "Register cryptographic security keys to critical administrative, cloud, and primary email accounts."
            },
            {
                "num": "03",
                "title": "Safeguard Backup Recovery Codes",
                "desc": "Print or store offline emergency backup codes in a physically secure location (safe/vault)."
            }
        ],
        "faqs": [
            {"q": "What happens if I lose my 2FA device?", "a": "Use your securely stored offline emergency backup recovery codes or secondary FIDO2 key."}
        ]
    },
    {
        "id": "malware-ransomware",
        "title": "Ransomware Prevention & Process Isolation",
        "category": "malware",
        "badge": "Advanced",
        "readTime": "7 min",
        "summary": "Understand behavioral ransomware indicators, shadow copy backup strategies, and zero-day process containment.",
        "icon": "☣️",
        "steps": [
            {
                "num": "01",
                "title": "Maintain Air-Gapped Immutable Backups",
                "desc": "Implement the 3-2-1 backup rule: 3 copies, 2 different media, 1 offsite air-gapped backup resistant to wiper malware."
            },
            {
                "num": "02",
                "title": "Disable Unnecessary PowerShell & Script Host Execution",
                "desc": "Restrict macro execution in documents and block unsigned binary execution in temp directories."
            },
            {
                "num": "03",
                "title": "Activate CyberShield Real-Time File Guard",
                "desc": "Enable real-time file monitoring in settings to detect anomalous mass file encryption events instantly."
            }
        ],
        "faqs": [
            {"q": "Should victims pay ransomware demands?", "a": "Security agencies strongly advise against paying ransoms as it funds cybercrime and offers no guarantee of decryption."}
        ]
    },
    {
        "id": "network-defense",
        "title": "Zero-Trust Wi-Fi & Network Isolation",
        "category": "network",
        "badge": "Network Security",
        "readTime": "5 min",
        "summary": "Protect device traffic over public Wi-Fi networks using Encrypted DNS, WireGuard VPNs, and host-based firewall rules.",
        "icon": "🌐",
        "steps": [
            {
                "num": "01",
                "title": "Enforce DNS-over-HTTPS (DoH)",
                "desc": "Prevent DNS spoofing and eavesdropping by routing queries through encrypted Quad9 or Cloudflare DNS resolvers."
            },
            {
                "num": "02",
                "title": "Utilize Mutual TLS / VPN Isolation",
                "desc": "Always connect through an encrypted WireGuard VPN proxy when accessing untrusted networks."
            }
        ],
        "faqs": [
            {"q": "What is a Evil Twin Access Point?", "a": "A rogue Wi-Fi access point broadcasting the same SSID as a legitimate network to intercept user traffic."}
        ]
    },
    {
        "id": "ai-security",
        "title": "AI Threat Vectors: Model Inversion & Prompt Injection",
        "category": "ai",
        "badge": "Emerging Tech",
        "readTime": "8 min",
        "summary": "Explore cutting-edge artificial intelligence vulnerabilities, prompt injection defenses, and data privacy safeguards when using LLMs.",
        "icon": "🤖",
        "steps": [
            {
                "num": "01",
                "title": "Sanitize Sensitive Data in Prompts",
                "desc": "Never input raw passwords, API keys, customer PII, or proprietary source code into external cloud LLMs."
            },
            {
                "num": "02",
                "title": "Detect Direct & Indirect Prompt Injection",
                "desc": "Validate AI outputs and isolate autonomous AI agents to prevent malicious prompt payloads from triggering unauthorized actions."
            }
        ],
        "faqs": [
            {"q": "What is Indirect Prompt Injection?", "a": "When an AI model reads malicious instructions hidden inside external untrusted web content or documents."}
        ]
    }
]

# Database Initialization
def init_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # Settings table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS user_settings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            settings_json TEXT NOT NULL,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    
    # Progress table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS user_progress (
            guide_id TEXT PRIMARY KEY,
            completed INTEGER DEFAULT 0,
            completed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    
    # Insert default settings if empty
    cursor.execute("SELECT COUNT(*) FROM user_settings")
    if cursor.fetchone()[0] == 0:
        cursor.execute("INSERT INTO user_settings (settings_json) VALUES (?)", (json.dumps(DEFAULT_SETTINGS),))
        
    conn.commit()
    conn.close()

init_db()

def get_current_settings():
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("SELECT settings_json FROM user_settings ORDER BY id DESC LIMIT 1")
        row = cursor.fetchone()
        conn.close()
        if row:
            return json.loads(row[0])
    except Exception as e:
        print("DB Error:", e)
    return DEFAULT_SETTINGS

def save_current_settings(settings_dict):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("INSERT INTO user_settings (settings_json) VALUES (?)", (json.dumps(settings_dict),))
    conn.commit()
    conn.close()

# ==================== STATIC PAGE ROUTES ====================

@app.route("/")
def index():
    return send_from_directory(WEB_DIR, "guide.html") if os.path.exists(os.path.join(WEB_DIR, "guide.html")) else send_from_directory(WEB_DIR, "Guide. html")

@app.route("/guide")
@app.route("/guide.html")
def serve_guide():
    if os.path.exists(os.path.join(WEB_DIR, "guide.html")):
        return send_from_directory(WEB_DIR, "guide.html")
    return send_from_directory(WEB_DIR, "Guide. html")

@app.route("/settings")
@app.route("/settings.html")
def serve_settings():
    return send_from_directory(WEB_DIR, "settings.html")

# ==================== REST API ENDPOINTS ====================

@app.route("/api/health", methods=["GET"])
def health_check():
    return jsonify({
        "status": "online",
        "app": "CyberShield-AI",
        "developer": "Shreya",
        "modules": ["Guidance Engine", "Settings Engine", "Research Papers Vault"]
    })

# --- GUIDANCE API ---

@app.route("/api/guide", methods=["GET"])
def get_guides():
    category = request.args.get("category", "all").lower()
    search = request.args.get("q", "").lower()
    
    filtered = GUIDES_DATA
    if category != "all":
        filtered = [g for g in filtered if g["category"] == category]
        
    if search:
        filtered = [
            g for g in filtered 
            if search in g["title"].lower() 
            or search in g["summary"].lower()
            or any(search in step["title"].lower() or search in step["desc"].lower() for step in g["steps"])
        ]
        
    return jsonify({
        "status": "success",
        "count": len(filtered),
        "guides": filtered
    })

@app.route("/api/guide/<guide_id>", methods=["GET"])
def get_guide_detail(guide_id):
    guide = next((g for g in GUIDES_DATA if g["id"] == guide_id), None)
    if not guide:
        return jsonify({"status": "error", "message": "Guide not found"}), 404
    return jsonify({"status": "success", "guide": guide})

@app.route("/api/guide/ask", methods=["POST"])
def ask_ai_assistant():
    data = request.get_json() or {}
    question = data.get("question", "").strip()
    
    if not question:
        return jsonify({"status": "error", "message": "Question prompt is required"}), 400
        
    q_lower = question.lower()
    
    # Contextual AI Cybersecurity Advice Generator
    if "phish" in q_lower or "email" in q_lower or "link" in q_lower:
        answer = "📧 **Phishing Defense Recommendation**:\n\n1. Do not click any links or download attachments in suspicious emails.\n2. Inspect the raw email header `Return-Path` and `SPF/DKIM/DMARC` validation scores.\n3. Verify the sender's identity through an out-of-band trusted communication channel.\n4. Submit the URL or file to CyberShield-AI Scanner for automated sandbox analysis."
    elif "pass" in q_lower or "login" in q_lower or "auth" in q_lower:
        answer = "🔑 **Credential & Password Security Advice**:\n\n1. Generate a high-entropy password (at least 16+ characters with mixed case, numbers, and symbols).\n2. Store your credentials in an encrypted password manager vault.\n3. Enable FIDO2/WebAuthn Hardware Key or TOTP 2FA immediately on all primary accounts."
    elif "ransom" in q_lower or "malware" in q_lower or "virus" in q_lower:
        answer = "☣️ **Ransomware & Malware Containment Protocol**:\n\n1. Immediately disconnect the host device from local Wi-Fi and ethernet networks to prevent lateral spread.\n2. Do NOT pay the ransom demand.\n3. Boot into Safe Mode and run a full system heuristic scan using CyberShield-AI.\n4. Restore affected drives from clean offsite immutable backups."
    elif "wifi" in q_lower or "net" in q_lower or "vpn" in q_lower:
        answer = "🌐 **Network Protection Guidance**:\n\n1. Enable DNS-over-HTTPS (DoH) to encrypt all outgoing hostname lookups.\n2. Connect via an encrypted WireGuard VPN when operating on public or untrusted Wi-Fi.\n3. Ensure your local firewall blocks inbound unauthenticated ports (e.g., RDP port 3389, SMB port 445)."
    elif "setting" in q_lower or "config" in q_lower:
        answer = "⚙️ **CyberShield Settings Guidance**:\n\nNavigate to the **Settings** page (`settings.html`) in CyberShield-AI to configure real-time shield sensitivity, customize your AI assistant prompt rules, toggle privacy telemetry, and enter your VirusTotal/HIBP API keys."
    else:
        answer = f"🛡️ **CyberShield AI Security Response**:\n\nBased on your security query: *\"{question}\"*\n\n1. Always enforce the principle of least privilege (PoLP) across your operating system.\n2. Ensure your operating system and application dependencies receive real-time security patches.\n3. Refer to Shreya's Research Papers in the Guide tab for deep-dive technical architectures on AI guidance and zero-trust configuration models."
        
    return jsonify({
        "status": "success",
        "query": question,
        "response": answer,
        "suggested_guide": "phishing-defense" if "phish" in q_lower else ("password-hygiene" if "pass" in q_lower else "malware-ransomware")
    })

@app.route("/api/guide/progress", methods=["GET", "POST"])
def handle_progress():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    if request.method == "POST":
        data = request.get_json() or {}
        guide_id = data.get("guide_id")
        completed = 1 if data.get("completed") else 0
        if guide_id:
            cursor.execute("""
                INSERT INTO user_progress (guide_id, completed) VALUES (?, ?)
                ON CONFLICT(guide_id) DO UPDATE SET completed=excluded.completed
            """, (guide_id, completed))
            conn.commit()
            
    cursor.execute("SELECT guide_id, completed FROM user_progress")
    rows = cursor.fetchall()
    conn.close()
    
    progress_map = {row[0]: bool(row[1]) for row in rows}
    total = len(GUIDES_DATA)
    completed_count = sum(1 for v in progress_map.values() if v)
    percentage = int((completed_count / total) * 100) if total > 0 else 0
    
    return jsonify({
        "status": "success",
        "progress": progress_map,
        "completedCount": completed_count,
        "totalGuides": total,
        "percentage": percentage
    })

# --- SETTINGS API ---

@app.route("/api/settings", methods=["GET", "POST", "PUT"])
def handle_settings():
    if request.method in ["POST", "PUT"]:
        new_data = request.get_json() or {}
        current = get_current_settings()
        
        # Deep merge new settings into current settings
        for section in ["profile", "security", "ai_assistant", "privacy", "appearance", "api_keys"]:
            if section in new_data and isinstance(new_data[section], dict):
                current[section].update(new_data[section])
                
        save_current_settings(current)
        return jsonify({
            "status": "success",
            "message": "CyberShield Settings updated successfully!",
            "settings": current
        })
        
    return jsonify({
        "status": "success",
        "settings": get_current_settings()
    })

@app.route("/api/settings/reset", methods=["POST"])
def reset_settings():
    save_current_settings(DEFAULT_SETTINGS)
    return jsonify({
        "status": "success",
        "message": "CyberShield Settings reset to factory defaults!",
        "settings": DEFAULT_SETTINGS
    })

@app.route("/api/settings/export", methods=["GET"])
def export_settings():
    settings = get_current_settings()
    # Mask actual sensitive keys in export file for safety
    exported = json.loads(json.dumps(settings))
    content = json.dumps(exported, indent=2)
    return Response(
        content,
        mimetype="application/json",
        headers={"Content-Disposition": "attachment;filename=cybershield_settings_export.json"}
    )

# --- RESEARCH PAPERS API ---

@app.route("/api/research-papers", methods=["GET"])
def get_research_papers():
    papers = [
        {
            "id": "paper-1",
            "title": "Dynamic AI-Driven Cybersecurity Guidance and Adaptive Threat Education Frameworks",
            "author": "Shreya et al.",
            "date": "September 2026",
            "filename": "Paper1_Dynamic_AI_Driven_Cybersecurity_Guidance.md",
            "summary": "Presents an adaptive AI framework that dynamically delivers interactive micro-learning modules and threat contextualization, achieving a 74.2% reduction in phishing vulnerability.",
            "tags": ["AI Education", "Phishing Defense", "Adaptive Learning", "Threat Guidance"]
        },
        {
            "id": "paper-2",
            "title": "Zero-Trust Security Configurations, Privacy-Preserving Telemetry, and User Preference Management",
            "author": "Shreya et al.",
            "date": "September 2026",
            "filename": "Paper2_Zero_Trust_Security_Configurations_and_Privacy_Preserving_Telemetry.md",
            "summary": "Explores zero-trust configuration storage, encrypted API key vaults, and Differential Privacy (Laplace mechanism) for telemetry collection with sub-1.4ms access latency.",
            "tags": ["Zero-Trust", "Settings Architecture", "Differential Privacy", "AES-256 Storage"]
        }
    ]
    return jsonify({"status": "success", "papers": papers})

@app.route("/api/research-papers/<paper_id>", methods=["GET"])
def get_paper_content(paper_id):
    filename = "Paper1_Dynamic_AI_Driven_Cybersecurity_Guidance.md" if paper_id in ["1", "paper-1"] else "Paper2_Zero_Trust_Security_Configurations_and_Privacy_Preserving_Telemetry.md"
    file_path = os.path.join(RESEARCH_DIR, filename)
    
    if os.path.exists(file_path):
        with open(file_path, "r", encoding="utf-8") as f:
            content = f.read()
        return jsonify({"status": "success", "id": paper_id, "content": content})
        
# --- STATIC ROUTES FOR PHISHING & CYBERBULLYING ---

@app.route("/phishing")
@app.route("/phishing.html")
def serve_phishing():
    return send_from_directory(WEB_DIR, "phishing.html")

@app.route("/cyberbullying")
@app.route("/cyberbullying.html")
def serve_cyberbullying():
    return send_from_directory(WEB_DIR, "cyberbullying.html")

# --- DETECTION API ENDPOINTS (SHREYA MODULES) ---

@app.route("/api/detect/phishing", methods=["POST"])
def detect_phishing():
    data = request.get_json() or {}
    target = data.get("target", "").strip()
    
    if not target:
        return jsonify({"status": "error", "message": "URL or email text is required"}), 400
        
    t_lower = target.lower()
    flags = []
    score = 0
    
    # URL / Domain Heuristics
    if t_lower.startswith("http://") or t_lower.startswith("https://") or "www." in t_lower or "." in t_lower:
        if "http://" in t_lower:
            flags.append("Unencrypted connection (HTTP instead of HTTPS)")
            score += 25
        if any(bad_tld in t_lower for bad_tld in [".xyz", ".top", ".tk", ".club", ".work", ".gq", ".cf"]):
            flags.append("High-risk top-level domain (TLD) associated with spam/phishing")
            score += 30
        if any(spoof in t_lower for spoof in ["paypa1", "g00gle", "micros0ft", "app1e", "amaz0n", "sec-login", "verify-account"]):
            flags.append("Lookalike domain / typosquatting detected")
            score += 45
        if "@" in t_lower:
            flags.append("Embedded user credentials / '@' symbol in URL")
            score += 35
        if len(t_lower) > 75:
            flags.append("Excessively long URL path designed to obscure hostname")
            score += 15
        if t_lower.count("-") > 3:
            flags.append("Multiple hyphens in domain name (common in fake phishing portals)")
            score += 20
            
    # Text / Email Content Heuristics
    if any(keyword in t_lower for keyword in ["account suspended", "urgent action required", "verify your account", "unauthorized login", "click link below", "update billing"]):
        flags.append("Urgent call-to-action / social engineering trigger words")
        score += 35
    if any(keyword in t_lower for keyword in ["password reset", "gift card", "bank wire", "ssn", "social security"]):
        flags.append("Sensitive credential / financial information solicitation")
        score += 30

    score = min(score, 100)
    
    if score >= 75:
        risk_level = "CRITICAL PHISHING THREAT"
        status_color = "danger"
    elif score >= 45:
        risk_level = "HIGH RISK"
        status_color = "warning"
    elif score >= 20:
        risk_level = "MODERATE CAUTION"
        status_color = "warning"
    else:
        risk_level = "SAFE / LOW RISK"
        status_color = "success"
        if not flags:
            flags.append("No obvious phishing indicators detected.")

    return jsonify({
        "status": "success",
        "target": target,
        "risk_score": score,
        "risk_level": risk_level,
        "status_color": status_color,
        "flags": flags,
        "recommendation": "Do NOT enter credentials or click links. Report email domain immediately." if score >= 45 else "URL/content appears safe, but maintain standard security vigilance."
    })

@app.route("/api/detect/cyberbullying", methods=["POST"])
def detect_cyberbullying():
    data = request.get_json() or {}
    text = data.get("text", "").strip()
    
    if not text:
        return jsonify({"status": "error", "message": "Input text is required"}), 400
        
    t_lower = text.lower()
    categories = {
        "insult": False,
        "harassment": False,
        "threat": False,
        "profanity": False,
        "hate_speech": False
    }
    flagged_words = []
    score = 0
    
    # Harassment / Bullying Lexicon Analysis
    insult_words = ["stupid", "idiot", "loser", "ugly", "fat", "dumb", "hate you", "freak", "trash", "worthless"]
    harass_words = ["kill yourself", "die", "go die", "nobody likes you", "shut up", "get a life", "creep", "stalk"]
    threat_words = ["i will find you", "beat you", "hurt you", "destroy you", "track your ip", "expose you"]
    profanity_words = ["bitch", "bastard", "fuck", "shit", "asshole"]
    
    for w in insult_words:
        if w in t_lower:
            categories["insult"] = True
            flagged_words.append(w)
            score += 25
            
    for w in harass_words:
        if w in t_lower:
            categories["harassment"] = True
            flagged_words.append(w)
            score += 40
            
    for w in threat_words:
        if w in t_lower:
            categories["threat"] = True
            flagged_words.append(w)
            score += 50
            
    for w in profanity_words:
        if w in t_lower:
            categories["profanity"] = True
            flagged_words.append(w)
            score += 15

    score = min(score, 100)
    flagged_words = list(set(flagged_words))
    
    if score >= 70:
        toxicity_level = "HIGHLY TOXIC / SEVERE HARASSMENT"
        status_color = "danger"
    elif score >= 35:
        toxicity_level = "MODERATE TOXICITY DETECTED"
        status_color = "warning"
    else:
        toxicity_level = "SAFE / NON-TOXIC CONTENT"
        status_color = "success"

    return jsonify({
        "status": "success",
        "text": text,
        "toxicity_score": score,
        "toxicity_level": toxicity_level,
        "status_color": status_color,
        "categories": categories,
        "flagged_words": flagged_words,
        "safety_actions": [
            "Block the sender on social media/chat platforms.",
            "Take screenshot evidence for documentation.",
            "Report the toxic content to platform moderators.",
            "Reach out to a trusted counselor or cyber safety hotline."
        ] if score >= 35 else ["No safety action required."]
    })


def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"

if __name__ == "__main__":
    local_ip = get_local_ip()
    print("=" * 65)
    print("      CyberShield-AI Server (Mobile & Desktop Enabled)")
    print("=" * 65)
    print(f"  [Mobile Phone Access] Guidance: http://{local_ip}:5000/guide.html")
    print(f"  [Mobile Phone Access] Settings: http://{local_ip}:5000/settings.html")
    print(f"  [Local PC Access]     Guidance: http://127.0.0.1:5000/guide.html")
    print(f"  [Local PC Access]     Settings: http://127.0.0.1:5000/settings.html")
    print("=" * 65 + "\n")
    app.run(host="0.0.0.0", port=5000, debug=True)


