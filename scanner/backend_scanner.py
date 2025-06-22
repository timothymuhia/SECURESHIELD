# backend_scanner.py

import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse
import re

def is_suspicious_link(link):
    suspicious_patterns = [".exe", ".scr", ".zip", ".php", ".rar"]
    if any(link.lower().endswith(ext) for ext in suspicious_patterns):
        return True
    if re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", link):  # raw IP address
        return True
    if len(link) > 100:
        return True
    if re.search(r"(login|secure|update|verify|account)", link, re.IGNORECASE) and "://" in link:
        return True
    return False

def scan_website(url):
    result = []

    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    parsed_url = urlparse(url)

    result.append(f"\n🔍 Scanning URL: {url}\n")

    # HTTPS check
    if parsed_url.scheme != "https":
        result.append("⚠️ WARNING: Connection is not secure (HTTPS is missing)\n")
    else:
        result.append("✅ HTTPS is enabled\n")

    # Try connecting to site
    try:
        response = requests.get(url, timeout=10)
        result.append(f"✅ Status Code: {response.status_code}\n")
    except requests.exceptions.RequestException as e:
        return f"❌ Error connecting to site:\n{str(e)}"

    # Security header check
    headers = response.headers
    missing_headers = []

    for header in [
        "X-Content-Type-Options",
        "X-Frame-Options",
        "Content-Security-Policy",
        "Strict-Transport-Security"
    ]:
        if header not in headers:
            missing_headers.append(header)

    if missing_headers:
        result.append("⚠️ Missing Security Headers:\n")
        for h in missing_headers:
            result.append(f"   - {h}\n")
    else:
        result.append("✅ All key security headers are present\n")

    # Suspicious link detection
    soup = BeautifulSoup(response.text, "html.parser")
    links = soup.find_all("a", href=True)
    result.append(f"\n🔗 Found {len(links)} links on the page\n")

    suspicious_links = []
    for link in links:
        href = link['href']
        if href.startswith("http") and is_suspicious_link(href):
            suspicious_links.append(href)

    if suspicious_links:
        result.append("\n🚨 Suspicious/Malicious Links Detected:\n")
        for s_link in suspicious_links:
            result.append(f"   - {s_link}\n")
    else:
        result.append("\n✅ No suspicious links found\n")

    return ''.join(result)
