"""
CyberShield AI Desktop Module - Guide Page

"""

import webbrowser

def open_guide_page(host="127.0.0.1", port=5000):
    """Opens the CyberShield-AI Guidance & Research page in default browser or desktop window."""
    url = f"http://{host}:{port}/guide.html"
    print(f"[CyberShield-Desktop] Navigating to Guidance Center: {url}")
    webbrowser.open(url)
    return url

if __name__ == "__main__":
    open_guide_page()
