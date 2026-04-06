import streamlit as st
import time
import json
import random
from scanner import run_full_scan

# ─── Page Config ──────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="SecLite · Unified Security Scanner",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed",
)

# ─── Custom CSS ───────────────────────────────────────────────────────────────
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Rajdhani:wght@400;500;600;700&family=Orbitron:wght@400;700;900&display=swap');

/* Reset & Base */
*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

html, body, [data-testid="stAppViewContainer"] {
    background-color: #050A0F !important;
    font-family: 'Rajdhani', sans-serif;
    color: #C8E6FF;
}

[data-testid="stAppViewContainer"] {
    background: 
        radial-gradient(ellipse 80% 50% at 50% -10%, rgba(0,180,255,0.08) 0%, transparent 60%),
        radial-gradient(ellipse 60% 40% at 80% 90%, rgba(0,255,180,0.04) 0%, transparent 50%),
        #050A0F !important;
    min-height: 100vh;
}

[data-testid="stHeader"] { background: transparent !important; }
[data-testid="stSidebar"] { background: #070D14 !important; }
section[data-testid="stMain"] > div { padding-top: 0 !important; }
.block-container { padding: 2rem 3rem !important; max-width: 1300px !important; }

/* ── Hero Header ── */
.hero-wrap {
    text-align: center;
    padding: 3.5rem 0 2rem;
    position: relative;
}
.hero-wrap::before {
    content: '';
    position: absolute;
    top: 0; left: 50%; transform: translateX(-50%);
    width: 600px; height: 2px;
    background: linear-gradient(90deg, transparent, #00B4FF 30%, #00FFB4 70%, transparent);
}
.hero-badge {
    display: inline-block;
    font-family: 'Share Tech Mono', monospace;
    font-size: 0.7rem;
    letter-spacing: 0.3em;
    color: #00FFB4;
    background: rgba(0,255,180,0.08);
    border: 1px solid rgba(0,255,180,0.25);
    padding: 0.3rem 1.2rem;
    border-radius: 2px;
    margin-bottom: 1.2rem;
    text-transform: uppercase;
}
.hero-title {
    font-family: 'Orbitron', monospace;
    font-size: clamp(3rem, 6vw, 5rem);
    font-weight: 900;
    letter-spacing: 0.08em;
    line-height: 1;
    background: linear-gradient(135deg, #FFFFFF 0%, #00B4FF 50%, #00FFB4 100%);
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
    background-clip: text;
    margin-bottom: 0.4rem;
    text-shadow: none;
}
.hero-subtitle {
    font-family: 'Share Tech Mono', monospace;
    font-size: 0.85rem;
    color: rgba(200,230,255,0.45);
    letter-spacing: 0.2em;
    text-transform: uppercase;
    margin-bottom: 0.8rem;
}
.hero-desc {
    font-size: 1.05rem;
    color: rgba(200,230,255,0.6);
    max-width: 520px;
    margin: 0 auto 0.5rem;
    line-height: 1.6;
    font-weight: 400;
}

/* ── Stat Strip ── */
.stat-strip {
    display: flex;
    justify-content: center;
    gap: 2.5rem;
    padding: 1.2rem 0 2rem;
    border-bottom: 1px solid rgba(0,180,255,0.1);
    margin-bottom: 2.5rem;
}
.stat-item { text-align: center; }
.stat-num {
    font-family: 'Orbitron', monospace;
    font-size: 1.4rem;
    font-weight: 700;
    color: #00B4FF;
}
.stat-lbl {
    font-family: 'Share Tech Mono', monospace;
    font-size: 0.65rem;
    letter-spacing: 0.2em;
    color: rgba(200,230,255,0.35);
    text-transform: uppercase;
}

/* ── Input Panel ── */
.input-panel {
    background: rgba(10,20,35,0.8);
    border: 1px solid rgba(0,180,255,0.18);
    border-radius: 6px;
    padding: 2rem 2.5rem;
    margin-bottom: 2rem;
    position: relative;
    overflow: hidden;
}
.input-panel::before {
    content: '';
    position: absolute;
    top: 0; left: 0; right: 0;
    height: 2px;
    background: linear-gradient(90deg, #00B4FF, #00FFB4);
}
.panel-label {
    font-family: 'Share Tech Mono', monospace;
    font-size: 0.72rem;
    letter-spacing: 0.25em;
    color: #00B4FF;
    text-transform: uppercase;
    margin-bottom: 1rem;
}

/* Override Streamlit text input */
[data-testid="stTextInput"] input {
    background: rgba(0,10,25,0.9) !important;
    border: 1px solid rgba(0,180,255,0.3) !important;
    border-radius: 4px !important;
    color: #C8E6FF !important;
    font-family: 'Share Tech Mono', monospace !important;
    font-size: 1rem !important;
    padding: 0.85rem 1.2rem !important;
    letter-spacing: 0.05em;
    transition: border-color 0.2s, box-shadow 0.2s;
}
[data-testid="stTextInput"] input:focus {
    border-color: #00B4FF !important;
    box-shadow: 0 0 0 2px rgba(0,180,255,0.15), 0 0 20px rgba(0,180,255,0.08) !important;
    outline: none !important;
}
[data-testid="stTextInput"] label {
    color: rgba(200,230,255,0.5) !important;
    font-family: 'Share Tech Mono', monospace !important;
    font-size: 0.75rem !important;
    letter-spacing: 0.15em;
}

/* ── Buttons ── */
.stButton > button {
    background: linear-gradient(135deg, #003D66, #005580) !important;
    border: 1px solid #00B4FF !important;
    border-radius: 4px !important;
    color: #FFFFFF !important;
    font-family: 'Orbitron', monospace !important;
    font-size: 0.75rem !important;
    font-weight: 700 !important;
    letter-spacing: 0.2em !important;
    padding: 0.75rem 2.5rem !important;
    text-transform: uppercase !important;
    transition: all 0.2s !important;
    cursor: pointer;
    box-shadow: 0 0 20px rgba(0,180,255,0.15) !important;
}
.stButton > button:hover {
    background: linear-gradient(135deg, #005580, #0077AA) !important;
    box-shadow: 0 0 30px rgba(0,180,255,0.3), inset 0 0 15px rgba(0,180,255,0.05) !important;
    transform: translateY(-1px) !important;
}

/* ── Progress & Status ── */
.scan-status-wrap {
    background: rgba(0,5,15,0.9);
    border: 1px solid rgba(0,180,255,0.2);
    border-radius: 6px;
    padding: 1.8rem 2rem;
    margin: 1.5rem 0;
    font-family: 'Share Tech Mono', monospace;
}
.status-line {
    font-size: 0.8rem;
    color: #00FFB4;
    margin-bottom: 0.4rem;
    display: flex;
    align-items: center;
    gap: 0.6rem;
}
.status-line::before { content: '▸'; color: #00B4FF; }

/* ── Result Cards ── */
.result-grid {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(300px, 1fr));
    gap: 1.2rem;
    margin: 1.5rem 0;
}
.tool-card {
    background: rgba(8,18,32,0.95);
    border: 1px solid rgba(0,180,255,0.15);
    border-radius: 6px;
    padding: 1.4rem 1.6rem;
    position: relative;
    transition: border-color 0.2s, transform 0.2s;
    overflow: hidden;
}
.tool-card:hover {
    border-color: rgba(0,180,255,0.4);
    transform: translateY(-2px);
}
.tool-card::after {
    content: '';
    position: absolute;
    bottom: 0; left: 0; right: 0;
    height: 2px;
}
.card-safe::after   { background: linear-gradient(90deg, #00FFB4, transparent); }
.card-warn::after   { background: linear-gradient(90deg, #FFB400, transparent); }
.card-danger::after { background: linear-gradient(90deg, #FF3B3B, transparent); }
.card-info::after   { background: linear-gradient(90deg, #00B4FF, transparent); }

.card-header {
    display: flex;
    justify-content: space-between;
    align-items: flex-start;
    margin-bottom: 1rem;
}
.card-title {
    font-family: 'Orbitron', monospace;
    font-size: 0.72rem;
    font-weight: 700;
    letter-spacing: 0.15em;
    color: #C8E6FF;
    text-transform: uppercase;
}
.card-icon { font-size: 1.4rem; opacity: 0.8; }
.badge {
    display: inline-block;
    font-family: 'Share Tech Mono', monospace;
    font-size: 0.65rem;
    letter-spacing: 0.1em;
    padding: 0.2rem 0.7rem;
    border-radius: 2px;
    text-transform: uppercase;
    font-weight: 600;
}
.badge-safe   { background: rgba(0,255,180,0.12); color: #00FFB4; border: 1px solid rgba(0,255,180,0.3); }
.badge-warn   { background: rgba(255,180,0,0.12); color: #FFB400; border: 1px solid rgba(255,180,0,0.3); }
.badge-danger { background: rgba(255,59,59,0.12); color: #FF6B6B; border: 1px solid rgba(255,59,59,0.3); }
.badge-info   { background: rgba(0,180,255,0.12); color: #00B4FF; border: 1px solid rgba(0,180,255,0.3); }

.card-findings {
    font-family: 'Share Tech Mono', monospace;
    font-size: 0.75rem;
    color: rgba(200,230,255,0.65);
    line-height: 1.7;
}
.finding-item {
    display: flex;
    gap: 0.5rem;
    padding: 0.25rem 0;
    border-bottom: 1px solid rgba(0,180,255,0.06);
}
.finding-key { color: rgba(0,180,255,0.7); min-width: 120px; }
.finding-val { color: #C8E6FF; word-break: break-all; }

/* ── Risk Score Panel ── */
.risk-panel {
    background: rgba(8,16,28,0.95);
    border: 1px solid rgba(0,180,255,0.2);
    border-radius: 8px;
    padding: 2.5rem;
    margin: 2rem 0;
    text-align: center;
    position: relative;
    overflow: hidden;
}
.risk-panel::before {
    content: '';
    position: absolute;
    top: 0; left: 0; right: 0;
    height: 3px;
    background: linear-gradient(90deg, #00B4FF, #00FFB4, #00B4FF);
}
.risk-label {
    font-family: 'Share Tech Mono', monospace;
    font-size: 0.72rem;
    letter-spacing: 0.3em;
    color: rgba(200,230,255,0.4);
    text-transform: uppercase;
    margin-bottom: 0.8rem;
}
.risk-score-num {
    font-family: 'Orbitron', monospace;
    font-size: 5rem;
    font-weight: 900;
    line-height: 1;
    margin-bottom: 0.3rem;
}
.risk-level {
    font-family: 'Orbitron', monospace;
    font-size: 1rem;
    font-weight: 700;
    letter-spacing: 0.3em;
    text-transform: uppercase;
    margin-bottom: 1.5rem;
}
.risk-bar-wrap {
    max-width: 400px;
    margin: 0 auto;
    background: rgba(0,0,0,0.4);
    border-radius: 2px;
    height: 6px;
    overflow: hidden;
}
.risk-bar-fill {
    height: 100%;
    border-radius: 2px;
    transition: width 1s ease;
}

/* ── Section Titles ── */
.section-title {
    font-family: 'Orbitron', monospace;
    font-size: 0.8rem;
    font-weight: 700;
    letter-spacing: 0.25em;
    color: rgba(200,230,255,0.5);
    text-transform: uppercase;
    margin: 2.5rem 0 1.2rem;
    display: flex;
    align-items: center;
    gap: 0.8rem;
}
.section-title::after {
    content: '';
    flex: 1;
    height: 1px;
    background: linear-gradient(90deg, rgba(0,180,255,0.2), transparent);
}

/* ── Footer ── */
.footer {
    text-align: center;
    padding: 3rem 0 1.5rem;
    font-family: 'Share Tech Mono', monospace;
    font-size: 0.7rem;
    letter-spacing: 0.2em;
    color: rgba(200,230,255,0.2);
    border-top: 1px solid rgba(0,180,255,0.08);
    margin-top: 3rem;
}

/* Streamlit override cleanups */
.stProgress > div > div > div > div {
    background: linear-gradient(90deg, #00B4FF, #00FFB4) !important;
}
[data-testid="stMarkdownContainer"] p { color: inherit; }
div[data-baseweb="notification"] { display: none; }
.stAlert { display: none; }
</style>
""", unsafe_allow_html=True)

# ─── Hero Section ─────────────────────────────────────────────────────────────
st.markdown("""
<div class="hero-wrap">
    <div class="hero-badge">v1.0.0 · MCA Mini Project · Security Research</div>
    <div class="hero-title">SecLite</div>
    <div class="hero-subtitle">Unified Security Scanner</div>
    <div class="hero-desc">Automated web security assessment powered by open-source intelligence tools. Submit a URL, get a consolidated risk score.</div>
</div>

<div class="stat-strip">
    <div class="stat-item"><div class="stat-num">6</div><div class="stat-lbl">Scan Modules</div></div>
    <div class="stat-item"><div class="stat-num">OSS</div><div class="stat-lbl">Powered</div></div>
    <div class="stat-item"><div class="stat-num">100</div><div class="stat-lbl">Risk Points</div></div>
    <div class="stat-item"><div class="stat-num">0ms</div><div class="stat-lbl">Signup Needed</div></div>
</div>
""", unsafe_allow_html=True)

# ─── Input Panel ──────────────────────────────────────────────────────────────
st.markdown('<div class="input-panel"><div class="panel-label">▸ Target Configuration</div>', unsafe_allow_html=True)

col1, col2 = st.columns([5, 1])
with col1:
    url_input = st.text_input(
        "TARGET URL",
        placeholder="https://example.com",
        label_visibility="visible",
        key="url_field"
    )
with col2:
    st.markdown("<br>", unsafe_allow_html=True)
    scan_btn = st.button("⚡ SCAN", use_container_width=True)

st.markdown('</div>', unsafe_allow_html=True)

# ─── Scan Modules Info ────────────────────────────────────────────────────────
st.markdown('<div class="section-title">Active Scan Modules</div>', unsafe_allow_html=True)

modules = [
    ("🌐", "DNS Recon", "DNSPython · dig", "Resolves DNS records, MX, NS, TXT entries"),
    ("🔒", "SSL/TLS Audit", "ssl · pyOpenSSL", "Certificate validity, cipher suites, expiry"),
    ("📡", "Port Scanner", "socket · nmap-like", "Common port sweep on target host"),
    ("🛡️", "Header Inspector", "requests · SecurityHeaders", "HTTP security headers analysis"),
    ("🕷️", "Vulnerability Check", "VirusTotal API", "URL reputation & malware database lookup"),
    ("🔍", "WHOIS Intel", "python-whois", "Domain registration, registrar, age info"),
]
cols = st.columns(3)
for i, (icon, name, tool, desc) in enumerate(modules):
    with cols[i % 3]:
        st.markdown(f"""
        <div class="tool-card card-info" style="margin-bottom:1rem">
            <div class="card-header">
                <div>
                    <div class="card-title">{name}</div>
                    <div style="font-family:'Share Tech Mono',monospace;font-size:0.65rem;color:rgba(0,180,255,0.5);margin-top:0.3rem">{tool}</div>
                </div>
                <div class="card-icon">{icon}</div>
            </div>
            <div class="card-findings">{desc}</div>
        </div>
        """, unsafe_allow_html=True)

# ─── Run Scan ─────────────────────────────────────────────────────────────────
if scan_btn and url_input:
    url = url_input.strip()
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    # Live terminal-style progress
    st.markdown('<div class="section-title">Scan Output</div>', unsafe_allow_html=True)
    log_container = st.empty()
    progress_bar = st.progress(0)

    log_lines = []
    steps = [
        (10, f"[INIT] Target acquired → {url}"),
        (18, "[DNS]  Resolving A, MX, NS, TXT records..."),
        (30, "[SSL]  Fetching TLS certificate metadata..."),
        (44, "[PORT] Scanning common service ports..."),
        (58, "[HTTP] Analysing HTTP security headers..."),
        (72, "[VTOT] Querying VirusTotal reputation API..."),
        (85, "[WHOIS] Pulling domain registration data..."),
        (95, "[SCORE] Calculating unified risk score..."),
        (100, "[DONE] Scan complete. Generating report..."),
    ]

    for pct, msg in steps:
        log_lines.append(msg)
        progress_bar.progress(pct)
        log_html = "".join(f'<div class="status-line">{l}</div>' for l in log_lines)
        log_container.markdown(
            f'<div class="scan-status-wrap">{log_html}</div>',
            unsafe_allow_html=True
        )
        time.sleep(0.55)

    # Run actual backend scan
    with st.spinner(""):
        results = run_full_scan(url)

    progress_bar.empty()
    log_container.empty()

    # ── Risk Score Banner ────────────────────────────────────────────────────
    score = results.get("risk_score", 50)
    if score <= 30:
        color, level, badge_cls = "#00FFB4", "LOW RISK", "safe"
    elif score <= 60:
        color, level, badge_cls = "#FFB400", "MEDIUM RISK", "warn"
    elif score <= 80:
        color, level, badge_cls = "#FF7A00", "HIGH RISK", "warn"
    else:
        color, level, badge_cls = "#FF3B3B", "CRITICAL", "danger"

    bar_color = f"linear-gradient(90deg, {color}, {'#FF3B3B' if score > 60 else color})"
    st.markdown(f"""
    <div class="section-title">Consolidated Risk Score</div>
    <div class="risk-panel">
        <div class="risk-label">Unified Security Assessment Score</div>
        <div class="risk-score-num" style="color:{color}">{score}</div>
        <div class="risk-level" style="color:{color}">{level}</div>
        <div class="risk-bar-wrap">
            <div class="risk-bar-fill" style="width:{score}%;background:{bar_color}"></div>
        </div>
        <div style="margin-top:1.2rem;font-family:'Share Tech Mono',monospace;font-size:0.7rem;color:rgba(200,230,255,0.35);letter-spacing:0.15em">
            SCORE {score}/100 · {level} · Scanned at {results.get('scan_time','')}
        </div>
    </div>
    """, unsafe_allow_html=True)

    # ── Module Result Cards ──────────────────────────────────────────────────
    st.markdown('<div class="section-title">Module Results</div>', unsafe_allow_html=True)

    card_cfg = {
        "dns":     ("🌐", "DNS Recon",        "dns_status"),
        "ssl":     ("🔒", "SSL / TLS Audit",   "ssl_status"),
        "ports":   ("📡", "Port Scanner",      "port_status"),
        "headers": ("🛡️", "HTTP Headers",      "header_status"),
        "virustotal": ("🕷️", "VirusTotal",    "vt_status"),
        "whois":   ("🔍", "WHOIS Intel",       "whois_status"),
    }

    cols2 = st.columns(2)
    col_idx = 0
    for key, (icon, title, status_key) in card_cfg.items():
        data = results.get(key, {})
        status = data.get(status_key, "info")
        if status == "safe":   card_class, badge_class, badge_txt = "card-safe",   "badge-safe",   "SECURE"
        elif status == "warn": card_class, badge_class, badge_txt = "card-warn",   "badge-warn",   "WARNING"
        elif status == "danger":card_class, badge_class, badge_txt = "card-danger","badge-danger","CRITICAL"
        else:                  card_class, badge_class, badge_txt = "card-info",   "badge-info",  "INFO"

        findings_html = ""
        for k, v in data.items():
            if k == status_key: continue
            if isinstance(v, list): v = ", ".join(str(x) for x in v[:4]) + ("…" if len(v) > 4 else "")
            findings_html += f'<div class="finding-item"><span class="finding-key">{k.replace("_"," ").upper()}</span><span class="finding-val">{v}</span></div>'

        card_html = f"""
        <div class="tool-card {card_class}" style="margin-bottom:1.2rem">
            <div class="card-header">
                <div>
                    <div class="card-title">{title}</div>
                    <div style="margin-top:0.4rem"><span class="badge {badge_class}">{badge_txt}</span></div>
                </div>
                <div class="card-icon">{icon}</div>
            </div>
            <div class="card-findings">{findings_html}</div>
        </div>
        """
        with cols2[col_idx % 2]:
            st.markdown(card_html, unsafe_allow_html=True)
        col_idx += 1

    # ── Raw JSON Expander ────────────────────────────────────────────────────
    with st.expander("📋  Raw Scan Data (JSON)"):
        st.json(results)

    # ── Re-scan button ───────────────────────────────────────────────────────
    st.markdown("<br>", unsafe_allow_html=True)
    if st.button("🔄 NEW SCAN", use_container_width=False):
        st.rerun()

elif scan_btn and not url_input:
    st.markdown("""
    <div style="background:rgba(255,59,59,0.08);border:1px solid rgba(255,59,59,0.3);
                border-radius:4px;padding:1rem 1.5rem;font-family:'Share Tech Mono',monospace;
                font-size:0.8rem;color:#FF6B6B;letter-spacing:0.1em">
        ⚠ ERROR: No target URL provided. Please enter a valid URL to initiate scan.
    </div>
    """, unsafe_allow_html=True)

# ─── Footer ───────────────────────────────────────────────────────────────────
st.markdown("""
<div class="footer">
    SECLITE · UNIFIED SECURITY SCANNER · MCA MINI PROJECT<br>
    BUILT WITH STREAMLIT · PYTHON · OPEN SOURCE INTELLIGENCE<br>
    FOR EDUCATIONAL PURPOSES ONLY
</div>
""", unsafe_allow_html=True)
