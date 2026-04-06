# 🛡️ SecLite — Unified Security Scanner

> MCA Mini Project | Web Security Assessment Tool

---

## 📌 Overview

SecLite is a lightweight, automated security scanner for web applications. Built using **Streamlit** for the frontend and a **Python backend** that integrates multiple open-source security tools.

---

## 🚀 Quick Start

### 1. Clone / Copy the project
```
seclite/
├── app.py          ← Streamlit UI
├── scanner.py      ← Backend scanning engine
├── requirements.txt
└── README.md
```

### 2. Install dependencies
```bash
pip install -r requirements.txt
```

### 3. Run the app
```bash
streamlit run app.py
```

---

## 🔧 Scan Modules

| Module | Library | What it checks |
|---|---|---|
| DNS Recon | `dnspython` | A, MX, NS, TXT records; SPF |
| SSL/TLS Audit | `ssl`, `socket` | Certificate validity, expiry, cipher |
| Port Scanner | `socket` (threaded) | 16 common ports for exposure |
| Header Inspector | `requests` | 6 critical HTTP security headers |
| VirusTotal | `requests` (API v3) | URL reputation, malware detection |
| WHOIS Intel | `python-whois` | Domain age, registrar, privacy |

---

## 🔑 VirusTotal API Key (Optional but Recommended)

1. Register free at https://virustotal.com
2. Get your API key from your profile
3. Open `scanner.py` and set:
```python
VT_API_KEY = "your_api_key_here"
```

Without a key, a heuristic URL pattern check is used as fallback.

---

## 📊 Risk Score

The unified risk score (0–100) is calculated by:
- Aggregating status of each module (safe / warn / danger)
- Missing HTTP security headers count
- Risky open ports detected
- VirusTotal malicious detections
- Domain age flags

| Score | Level |
|---|---|
| 0–30 | 🟢 LOW RISK |
| 31–60 | 🟡 MEDIUM RISK |
| 61–80 | 🟠 HIGH RISK |
| 81–100 | 🔴 CRITICAL |

---

## ⚠️ Disclaimer

SecLite is built for **educational and demonstration purposes only** as part of an MCA mini project. It is not intended to replace professional security tools. Only scan websites you own or have permission to test.

---

## 🏫 Project Info

- **Title**: Unified Security Scanner
- **Application**: SecLite
- **Course**: MCA Mini Project
- **Tech Stack**: Python 3.10+, Streamlit, dnspython, requests, python-whois
