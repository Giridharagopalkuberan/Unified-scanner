"""
SecLite Backend Scanner
========================
Integrates multiple open-source security tools to perform
a unified security assessment on a given URL.

Tools Used:
  - dns.resolver (dnspython)    → DNS record enumeration
  - ssl + socket                → TLS/SSL certificate analysis
  - socket                      → Port scanning
  - requests                    → HTTP header inspection
  - python-whois                → WHOIS domain info
  - VirusTotal Public API v3    → URL reputation check
"""

import ssl
import socket
import requests
import dns.resolver
import whois
import datetime
import re
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed

# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────
TIMEOUT = 6

def _hostname(url: str) -> str:
    return urlparse(url).hostname or ""

def _now() -> str:
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC")

# ─────────────────────────────────────────────────────────────────────────────
# 1. DNS Recon  (dnspython)
# ─────────────────────────────────────────────────────────────────────────────
def scan_dns(url: str) -> dict:
    host = _hostname(url)
    result = {"dns_status": "info"}
    issues = 0

    for rtype in ["A", "MX", "NS", "TXT"]:
        try:
            answers = dns.resolver.resolve(host, rtype, lifetime=TIMEOUT)
            values = [r.to_text() for r in answers]
            result[rtype] = values[:4]
        except Exception:
            result[rtype] = ["N/A"]

    # Check for SPF in TXT
    spf = any("v=spf1" in t for t in result.get("TXT", []))
    result["spf_record"] = "Present ✓" if spf else "Missing ✗"
    if not spf:
        issues += 1

    result["dns_status"] = "safe" if issues == 0 else "warn"
    return result


# ─────────────────────────────────────────────────────────────────────────────
# 2. SSL / TLS Audit  (ssl, socket)
# ─────────────────────────────────────────────────────────────────────────────
def scan_ssl(url: str) -> dict:
    host = _hostname(url)
    result = {"ssl_status": "info"}

    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=host) as s:
            s.settimeout(TIMEOUT)
            s.connect((host, 443))
            cert = s.getpeercert()
            cipher = s.cipher()

        # Expiry
        expire_str = cert.get("notAfter", "")
        if expire_str:
            exp = datetime.datetime.strptime(expire_str, "%b %d %H:%M:%S %Y %Z")
            days_left = (exp - datetime.datetime.utcnow()).days
            result["expiry"] = expire_str
            result["days_remaining"] = str(days_left)
            if days_left < 30:
                result["ssl_status"] = "danger" if days_left < 7 else "warn"
            else:
                result["ssl_status"] = "safe"
        else:
            result["expiry"] = "Unknown"
            result["days_remaining"] = "?"

        # Subject / Issuer
        subj = dict(x[0] for x in cert.get("subject", []))
        issuer = dict(x[0] for x in cert.get("issuer", []))
        result["subject_cn"] = subj.get("commonName", host)
        result["issuer"] = issuer.get("organizationName", "Unknown")
        result["cipher_suite"] = cipher[0] if cipher else "Unknown"
        result["tls_version"] = cipher[1] if cipher else "Unknown"

    except ssl.SSLCertVerificationError:
        result["ssl_status"] = "danger"
        result["error"] = "Certificate verification failed"
    except Exception as e:
        result["ssl_status"] = "warn"
        result["error"] = str(e)[:80]

    return result


# ─────────────────────────────────────────────────────────────────────────────
# 3. Port Scanner  (socket)
# ─────────────────────────────────────────────────────────────────────────────
COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 80: "HTTP", 110: "POP3", 143: "IMAP",
    443: "HTTPS", 445: "SMB", 3306: "MySQL",
    3389: "RDP", 5432: "PostgreSQL", 6379: "Redis",
    8080: "HTTP-Alt", 8443: "HTTPS-Alt",
}
RISKY_PORTS = {21, 23, 3389, 445, 3306, 6379}

def _probe_port(host: str, port: int) -> bool:
    try:
        with socket.create_connection((host, port), timeout=1.5):
            return True
    except Exception:
        return False

def scan_ports(url: str) -> dict:
    host = _hostname(url)
    open_ports, risky = [], []
    result = {"port_status": "safe"}

    with ThreadPoolExecutor(max_workers=20) as ex:
        futures = {ex.submit(_probe_port, host, p): p for p in COMMON_PORTS}
        for f in as_completed(futures):
            p = futures[f]
            if f.result():
                label = f"{p}/{COMMON_PORTS[p]}"
                open_ports.append(label)
                if p in RISKY_PORTS:
                    risky.append(label)

    result["open_ports"] = open_ports if open_ports else ["None detected"]
    result["risky_ports"] = risky if risky else ["None"]
    result["total_open"] = str(len(open_ports))

    if risky:
        result["port_status"] = "danger" if len(risky) >= 2 else "warn"
    elif open_ports:
        result["port_status"] = "warn"
    return result


# ─────────────────────────────────────────────────────────────────────────────
# 4. HTTP Security Headers  (requests)
# ─────────────────────────────────────────────────────────────────────────────
SECURITY_HEADERS = {
    "Strict-Transport-Security": "HSTS",
    "Content-Security-Policy": "CSP",
    "X-Frame-Options": "Clickjacking",
    "X-Content-Type-Options": "MIME Sniffing",
    "Referrer-Policy": "Referrer",
    "Permissions-Policy": "Permissions",
}

def scan_headers(url: str) -> dict:
    result = {"header_status": "safe"}
    missing = []
    try:
        r = requests.get(url, timeout=TIMEOUT, allow_redirects=True,
                         headers={"User-Agent": "SecLite/1.0 Security Scanner"})
        hdrs = r.headers

        for hdr, label in SECURITY_HEADERS.items():
            val = hdrs.get(hdr)
            result[label] = val[:60] if val else "⚠ MISSING"
            if not val:
                missing.append(label)

        result["server"] = hdrs.get("Server", "Hidden")
        result["x_powered_by"] = hdrs.get("X-Powered-By", "Hidden")
        result["status_code"] = str(r.status_code)
        result["missing_headers"] = str(len(missing))

        if len(missing) >= 4:
            result["header_status"] = "danger"
        elif len(missing) >= 2:
            result["header_status"] = "warn"
        else:
            result["header_status"] = "safe"

    except Exception as e:
        result["header_status"] = "warn"
        result["error"] = str(e)[:80]

    return result


# ─────────────────────────────────────────────────────────────────────────────
# 5. VirusTotal URL Reputation  (free public API v3 – no key required for basic)
# ─────────────────────────────────────────────────────────────────────────────
def scan_virustotal(url: str) -> dict:
    """
    Uses VirusTotal's free public URL report endpoint.
    Falls back to a simulated check if API key not set.
    """
    result = {"vt_status": "info"}

    VT_API_KEY = ""   # <── Paste your free VT API key here (https://virustotal.com)

    try:
        if VT_API_KEY:
            import base64
            url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
            resp = requests.get(
                f"https://www.virustotal.com/api/v3/urls/{url_id}",
                headers={"x-apikey": VT_API_KEY},
                timeout=TIMEOUT,
            )
            if resp.status_code == 200:
                data = resp.json().get("data", {}).get("attributes", {})
                stats = data.get("last_analysis_stats", {})
                result["malicious"] = str(stats.get("malicious", 0))
                result["suspicious"] = str(stats.get("suspicious", 0))
                result["harmless"]   = str(stats.get("harmless", 0))
                result["undetected"] = str(stats.get("undetected", 0))

                m = int(stats.get("malicious", 0))
                s = int(stats.get("suspicious", 0))
                if m > 0:
                    result["vt_status"] = "danger"
                    result["verdict"] = f"{m} engines flagged as MALICIOUS"
                elif s > 0:
                    result["vt_status"] = "warn"
                    result["verdict"] = f"{s} engines flagged as SUSPICIOUS"
                else:
                    result["vt_status"] = "safe"
                    result["verdict"] = "Clean — no detections"
            else:
                raise ValueError(f"VT API returned {resp.status_code}")
        else:
            # Heuristic fallback (no key)
            suspicious_patterns = [
                r"phish", r"malware", r"hack", r"crack",
                r"free-download", r"\.xyz$", r"\.tk$", r"\.pw$"
            ]
            flagged = any(re.search(p, url, re.I) for p in suspicious_patterns)
            result["vt_status"] = "warn" if flagged else "safe"
            result["verdict"] = "Heuristic check (add VT API key for full scan)"
            result["malicious"] = "?" 
            result["suspicious"] = "?"
            result["note"] = "Set VT_API_KEY in scanner.py for live VirusTotal data"

    except Exception as e:
        result["vt_status"] = "info"
        result["error"] = str(e)[:80]

    return result


# ─────────────────────────────────────────────────────────────────────────────
# 6. WHOIS Intel  (python-whois)
# ─────────────────────────────────────────────────────────────────────────────
def scan_whois(url: str) -> dict:
    host = _hostname(url)
    result = {"whois_status": "safe"}

    try:
        w = whois.whois(host)

        result["registrar"]   = str(w.registrar or "Unknown")[:60]
        result["country"]     = str(w.country   or "Unknown")
        result["organization"] = str(w.org      or "Unknown")[:60]

        # Creation date
        cd = w.creation_date
        if isinstance(cd, list): cd = cd[0]
        if cd:
            age_days = (datetime.datetime.now() - cd).days
            result["created"] = str(cd)[:19]
            result["domain_age_days"] = str(age_days)
            if age_days < 30:
                result["whois_status"] = "danger"
                result["age_flag"] = "⚠ Very new domain (<30 days)"
            elif age_days < 180:
                result["whois_status"] = "warn"
                result["age_flag"] = "New domain (<6 months)"
        else:
            result["created"] = "Unknown"

        exp = w.expiration_date
        if isinstance(exp, list): exp = exp[0]
        result["expires"] = str(exp)[:19] if exp else "Unknown"

        # Privacy protection check
        priv = any(kw in str(result.get("registrar", "")).lower()
                   for kw in ["privacy", "proxy", "protect", "whoisguard"])
        result["privacy_protection"] = "Enabled" if priv else "Not detected"

    except Exception as e:
        result["whois_status"] = "info"
        result["error"] = str(e)[:80]

    return result


# ─────────────────────────────────────────────────────────────────────────────
# Risk Score Calculator
# ─────────────────────────────────────────────────────────────────────────────
def calculate_risk_score(results: dict) -> int:
    score = 0

    status_weights = {"safe": 0, "info": 5, "warn": 15, "danger": 30}
    keys = ["dns", "ssl", "ports", "headers", "virustotal", "whois"]

    for k in keys:
        module = results.get(k, {})
        # Find status key
        for mk in module:
            if mk.endswith("_status"):
                score += status_weights.get(module[mk], 5)
                break

    # Bonus deductions / additions
    hdr = results.get("headers", {})
    missing = int(hdr.get("missing_headers", 0))
    score += missing * 3

    vt = results.get("virustotal", {})
    if vt.get("malicious", "0") not in ("0", "?", ""):
        score += 25

    port = results.get("ports", {})
    risky = port.get("risky_ports", ["None"])
    if risky != ["None"]:
        score += len(risky) * 8

    return min(100, max(0, score))


# ─────────────────────────────────────────────────────────────────────────────
# Master Scanner
# ─────────────────────────────────────────────────────────────────────────────
def run_full_scan(url: str) -> dict:
    scanners = {
        "dns": scan_dns,
        "ssl": scan_ssl,
        "ports": scan_ports,
        "headers": scan_headers,
        "virustotal": scan_virustotal,
        "whois": scan_whois,
    }

    results = {}

    with ThreadPoolExecutor(max_workers=6) as ex:
        futures = {ex.submit(fn, url): key for key, fn in scanners.items()}
        for f in as_completed(futures):
            key = futures[f]
            try:
                results[key] = f.result()
            except Exception as e:
                results[key] = {"error": str(e), f"{key}_status": "info"}

    results["target_url"] = url
    results["scan_time"] = _now()
    results["risk_score"] = calculate_risk_score(results)

    return results
