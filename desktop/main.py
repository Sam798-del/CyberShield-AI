"""
CyberShield AI Desktop Application - Main Entry Point
Integrates Guidance Center, Settings Engine, and Backend REST Service.

"""

import sys
import os
import time
import threading
import webbrowser

# Add parent dir to path to import app.py
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

def start_backend_server():
    """Runs the Flask REST API server in a background thread."""
    try:
        from app import app
        print("[CyberShield-AI Desktop] Starting Flask API Backend server...")
        app.run(host="127.0.0.1", port=5000, debug=False, use_reloader=False)
    except Exception as e:
        print(f"[CyberShield-AI Desktop] Backend server error: {e}")

def main():
    print("=" * 60)
    print("      CyberShield AI Desktop Application (Shreya Module)")
    print("=" * 60)
    
    # Launch backend server thread
    server_thread = threading.Thread(target=start_backend_server, daemon=True)
    server_thread.start()
    
    # Wait briefly for server initialization
    time.sleep(1.5)
    
    print("\nSelect Desktop Module to Launch:")
    print("1. 🛡️  CyberShield Guidance & Research Center (Shreya)")
    print("2. ⚙️  CyberShield Settings & System Configuration (Shreya)")
    print("3. 🏠  Launch Full Web Platform (http://127.0.0.1:5000)")
    
    # If headless or script run, default open guide
    url = "http://127.0.0.1:5000/guide.html"
    print(f"\n[Desktop App] Automatically launching Guidance Center at {url}...")
    webbrowser.open(url)

if __name__ == "__main__":
    main()
