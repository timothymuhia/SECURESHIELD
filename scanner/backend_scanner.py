import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse
import re

def is_malicious_link(link):
    """Detect potentially malicious links"""
    malicious_patterns = [
        r"\.(exe|scr|zip|rar|php|jar|bat|cmd|sh)\b",  # Suspicious extensions
        r"\b(?:\d{1,3}\.){3}\d{1,3}\b",  # Raw IP addresses
        r"(login|signin|secure|update|verify|account|admin)\b",  # Sensitive pages
        r"(@|javascript:|data:text|vbscript:)",  # Dangerous protocols
        r"\?.*(cmd|exec|shutdown|reboot|pwd|ls)\=",  # Suspicious parameters
    ]
    return any(re.search(pattern, link, re.IGNORECASE) for pattern in malicious_patterns)

def scan_website(url):
    """Main scanning function"""
    result = []
    
    # Validate and normalize URL
    if not url.startswith(('http://', 'https://')):
        url = f'http://{url}'
    
    try:
        parsed = urlparse(url)
        if not parsed.netloc:
            return "❌ Invalid URL format"
        
        result.append(f"\n🔍 Scanning: {url}\n")
        result.append(f"🌐 Domain: {parsed.netloc}\n")

        # HTTPS check
        if parsed.scheme != 'https':
            result.append("⚠️ WARNING: No HTTPS (connection not encrypted)\n")
        else:
            result.append("✅ HTTPS enabled (secure connection)\n")

        # Make request
        try:
            response = requests.get(
                url,
                headers={'User-Agent': 'SecurityScanner/1.0'},
                timeout=10,
                allow_redirects=True
            )
            result.append(f"✅ Connected (Status: {response.status_code})\n")
        except requests.RequestException as e:
            return f"❌ Connection failed: {str(e)}"

        # Security headers check
        result.append("\n🔒 Security Headers:\n")
        required_headers = {
            'X-XSS-Protection': '1; mode=block',
            'Content-Security-Policy': None,
            'Strict-Transport-Security': None,
            'X-Frame-Options': 'DENY',
            'X-Content-Type-Options': 'nosniff'
        }
        
        missing = []
        for header, expected in required_headers.items():
            if header not in response.headers:
                missing.append(header)
                result.append(f"⚠️ Missing: {header}\n")
            else:
                status = f"✅ Present: {header}"
                if expected and expected not in response.headers[header]:
                    status += f" (Expected: {expected})"
                result.append(status + "\n")

        if missing:
            result.append("\n🚨 Critical security headers missing!\n")

        # Link analysis
        result.append("\n📎 Link Analysis:\n")
        soup = BeautifulSoup(response.text, 'html.parser')
        links = [a.get('href', '') for a in soup.find_all('a') if a.get('href')]
        result.append(f"• Total links found: {len(links)}\n")
        
        malicious = [link for link in links if is_malicious_link(link)]
        if malicious:
            result.append("\n🚨 Potentially malicious links:\n")
            for bad in malicious[:5]:  # Show first 5 examples
                result.append(f"• {bad}\n")
            if len(malicious) > 5:
                result.append(f"• Plus {len(malicious)-5} more...\n")
        else:
            result.append("✅ No obvious malicious links found\n")

        return ''.join(result)

    except Exception as e:
        return f"❌ Scan error: {str(e)}"