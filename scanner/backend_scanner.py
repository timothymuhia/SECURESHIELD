import requests
import socket
import re
import time
from urllib.parse import urlparse
from bs4 import BeautifulSoup

HEADERS = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
    'Accept-Language': 'en-US,en;q=0.5',
    'Connection': 'keep-alive',
    'Upgrade-Insecure-Requests': '1'
}

def check_security_headers(url):
    """Check for the 4 most crucial security headers in HTTP response"""
    result = "🔒 Security Headers Check (Critical Headers Only):\n"
    try:
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
            
        response = requests.get(url, headers=HEADERS, timeout=10, allow_redirects=True)
        final_url = response.url
        result += f"Scanning: {final_url}\n\n"
        
        headers = response.headers
        
        # Only check these 4 critical security headers
        security_headers = {
            "Content-Security-Policy": "Prevents XSS attacks by controlling resource loading",
            "Strict-Transport-Security": "Enforces HTTPS connections",
            "X-Frame-Options": "Prevents clickjacking attacks",
            "X-Content-Type-Options": "Prevents MIME type sniffing"
        }
        
        for header, description in security_headers.items():
            if header in headers:
                result += f"✅ {header}: {headers[header]}\n"
            else:
                result += f"❌ {header}: Missing\n"
                result += f"   ⚠️ Risk: {description.split(':')[0]} vulnerability\n"
                
        # Add a summary of critical security
        missing_headers = [h for h in security_headers if h not in headers]
        if missing_headers:
            result += "\n🔴 CRITICAL WARNING:\n"
            result += f"   Missing {len(missing_headers)} crucial security headers:\n"
            for header in missing_headers:
                result += f"      • {header}\n"
            result += "   This significantly increases vulnerability to attacks!\n"
        else:
            result += "\n🟢 All critical security headers present!\n"
                
        return result
        
    except Exception as e:
        return f"❌ Header check failed: {str(e)}"

def extract_and_check_links(url):
    """Extract and analyze links from a webpage"""
    result = "\n🔗 Link Analysis:\n"
    try:
        response = requests.get(url, headers=HEADERS, timeout=10)
        soup = BeautifulSoup(response.content, 'html.parser')
        links = [a.get('href') for a in soup.find_all('a', href=True)]
        
        result += f"Found {len(links)} links\n"
        
        suspicious_links = []
        patterns = [
            r'javascript:',
            r'data:',
            r'vbscript:',
            r'about:blank',
            r'\.exe$',
            r'\.zip$',
            r'\.dmg$',
            r'\.bat$',
            r'\.sh$'
        ]
        
        for link in links:
            if link and any(re.search(pattern, link, re.IGNORECASE) for pattern in patterns):
                suspicious_links.append(link)
        
        if suspicious_links:
            result += "⚠️ Suspicious links found:\n"
            for slink in suspicious_links[:5]:
                result += f"   • {slink}\n"
            result += f"Total suspicious: {len(suspicious_links)}\n"
        else:
            result += "✅ No obviously suspicious links found\n"
            
        return result
        
    except Exception as e:
        return f"\n❌ Link analysis failed: {str(e)}"

def basic_port_scan(target):
    """Scan top 10 security-critical ports"""
    result = "\n🚪 Port Scan Results (Top 10 Critical Ports):\n"
    try:
        domain = urlparse(target).netloc.split(':')[0]
        if not domain:
            return "❌ Invalid domain for port scan"
            
        # Top 10 most common and security-critical ports
        ports = [
            21,   # FTP - File Transfer Protocol
            22,   # SSH - Secure Shell
            25,   # SMTP - Simple Mail Transfer Protocol
            53,   # DNS - Domain Name System
            80,   # HTTP - Hypertext Transfer Protocol
            110,  # POP3 - Post Office Protocol
            143,  # IMAP - Internet Message Access Protocol
            443,  # HTTPS - HTTP Secure
            3389, # RDP - Remote Desktop Protocol
            8080  # HTTP Alternate
        ]
        
        ip = socket.gethostbyname(domain)
        result += f"Target: {domain} ({ip})\n"
        
        open_ports = []
        for port in ports:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                    sock.settimeout(1)
                    res = sock.connect_ex((ip, port))
                    if res == 0:
                        try:
                            service = socket.getservbyport(port, 'tcp')
                        except:
                            service = "unknown"
                        open_ports.append(port)
                        result += f"   🔓 Port {port} ({service}): OPEN\n"
                    else:
                        result += f"   🔒 Port {port}: Closed\n"
            except:
                pass
            time.sleep(0.1)
        
        # Security assessment for critical ports
        risky_ports = [21, 22, 25, 80, 143, 3389]
        found_risky = [port for port in open_ports if port in risky_ports]
        
        if found_risky:
            result += "\n⚠️ WARNING: Potentially risky ports open!\n"
            port_names = {
                21: "FTP (File Transfer) - Vulnerable to brute force attacks",
                22: "SSH (Secure Shell) - Can be exploited if weak credentials",
                25: "SMTP (Email) - Can be abused for spam/phishing",
                80: "HTTP (Web) - Unencrypted traffic, vulnerable to snooping",
                143: "IMAP (Email) - Unencrypted email access",
                3389: "RDP (Remote Desktop) - Vulnerable to brute force attacks"
            }
            for port in found_risky:
                result += f"   • Port {port}: {port_names.get(port, 'Unknown service')}\n"
            result += "   Recommendation: Close or secure these ports\n"
        
        return result
        
    except Exception as e:
        return f"\n❌ Port scan failed: {str(e)}"