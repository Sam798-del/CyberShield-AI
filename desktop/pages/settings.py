"""
CyberShield AI Desktop Module - Settings Page

"""

import webbrowser

def open_settings_page(host="127.0.0.1", port=5000):
    """Opens the CyberShield-AI Settings & Configuration page in default browser or desktop window."""
    url = f"http://{host}:{port}/settings.html"
    print(f"[CyberShield-Desktop] Navigating to Settings Center: {url}")
    webbrowser.open(url)
    return url

if __name__ == "__main__":
    open_settings_page()
