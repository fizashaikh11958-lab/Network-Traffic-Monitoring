"""
Network Traffic Analyzer - Unusual Traffic Detector
A simple Streamlit cybersecurity project.

Run locally:   streamlit run app.py
"""
import random
import time
from datetime import datetime, timedelta

import numpy as np
import pandas as pd
import streamlit as st

st.set_page_config(page_title="Traffic Analyzer", page_icon="🛡️", layout="wide")

SAVE_FILE = "unusual_traffic.csv"
LIVE_SAVE_FILE = "live_unusual_traffic.csv"

# ---- Project credit (edit here if needed) ----
STUDENT_NAME = "Fiza Shaikh"
ROLL_NO = "19048"
CLASS_NAME = "TYBSc.IT"

# ---------------------------------------------------------------------------
# Loading screen (shown once when the app starts)
# ---------------------------------------------------------------------------
if "loaded" not in st.session_state:
    splash = st.empty()
    with splash.container():
        st.markdown(
            f"""
            <div style="text-align:center; padding:70px 10px 10px 10px;">
              <div style="font-size:70px;">🛡️</div>
              <h1 style="margin-bottom:0;">Network Traffic Analyzer</h1>
              <p style="font-size:18px; opacity:0.7;">Unusual Traffic Detection System</p>
              <hr style="width:50%; margin:25px auto;">
              <p style="font-size:18px; margin-bottom:4px;">This project is made By</p>
              <h2 style="margin:0;">{STUDENT_NAME}</h2>
              <p style="font-size:18px;">Roll No: {ROLL_NO} &nbsp;|&nbsp; {CLASS_NAME}</p>
            </div>
            """,
            unsafe_allow_html=True,
        )
        bar = st.progress(0)
        msg = st.empty()
        steps = ["Starting detection engine...", "Loading 10 attack patterns...",
                 "Preparing live packet monitor...", "Ready!"]
        for i, step in enumerate(steps):
            msg.markdown(f"<p style='text-align:center'>{step}</p>",
                         unsafe_allow_html=True)
            bar.progress(int((i + 1) / len(steps) * 100))
            time.sleep(0.7)
    splash.empty()
    st.session_state.loaded = True
COLUMNS = ["timestamp", "src_ip", "src_port", "dst_ip", "dst_port",
           "protocol", "length", "flags", "payload"]

BAD_PORTS = {4444, 31337, 1337, 6667, 12345, 5555, 6666, 9001}
WEB_REGEX = (r"(?:union\s+select|or\s+1=1|<script|\.\./\.\./|etc/passwd|"
             r"drop\s+table|cmd\.exe|;\s*sleep\()")
DEFAULT_BLACKLIST = "185.220.101.5\n198.51.100.77"

# ---------------------------------------------------------------------------
# The 10 unusual traffic patterns loaded into the tool
# ---------------------------------------------------------------------------
PATTERNS = [
    ("Port Scan", "High",
     "One IP probes many different ports to find open services.",
     "Source IP hits >= N distinct destination ports in 1 minute"),
    ("SYN Flood", "Critical",
     "Flood of TCP SYN packets that exhausts a server's connections.",
     "Source IP sends >= N SYN packets in 1 minute"),
    ("High-Volume Flood (DoS)", "Critical",
     "One source sends an abnormal number of packets (UDP/TCP flood).",
     "Source IP sends >= N packets in 1 minute"),
    ("Brute Force Login", "High",
     "Repeated login attempts on SSH / FTP / Telnet / RDP.",
     "Source IP makes >= N connections to ports 21, 22, 23, 3389 in 1 minute"),
    ("Suspicious Port", "Medium",
     "Traffic to ports used by backdoors, botnets, IRC C2 and Tor.",
     "Destination port in {4444, 31337, 1337, 6667, 12345, 5555, 6666, 9001}"),
    ("Data Exfiltration", "Critical",
     "Very large outbound transfers that may be stolen data.",
     "Source sends >= N MB in 1 minute with very large packets"),
    ("DNS Tunneling", "High",
     "Data hidden inside oversized DNS queries (used for covert channels).",
     "DNS packet longer than N bytes or payload longer than 60 chars"),
    ("ICMP Flood", "Medium",
     "Ping flood / ping sweep used for DoS or network discovery.",
     "Source IP sends >= N ICMP packets in 1 minute"),
    ("Blacklisted IP", "High",
     "Traffic to or from a known malicious IP address.",
     "Source or destination IP is in the blacklist (editable in sidebar)"),
    ("Web Attack Payload", "High",
     "SQL injection, XSS, path traversal and command injection strings.",
     "Payload contains UNION SELECT, OR 1=1, <script>, ../../, etc/passwd ..."),
]
SEV_RANK = {"Low": 1, "Medium": 2, "High": 3, "Critical": 4}
RANK_SEV = {v: k for k, v in SEV_RANK.items()}
SEV_COLOR = {"Medium": "#fff3cd", "High": "#ffd8b0", "Critical": "#f8c4c4"}


# ---------------------------------------------------------------------------
# Sample traffic generator (normal traffic + injected attacks)
# ---------------------------------------------------------------------------
def make_sample(seed=42):
    rng = random.Random(seed)
    start = datetime.now().replace(second=0, microsecond=0) - timedelta(minutes=10)
    rows = []

    def add(t, src, dst, sp, dp, proto, length, flags="ACK", payload=""):
        rows.append([t.strftime("%Y-%m-%d %H:%M:%S"), src, sp, dst, dp,
                     proto, length, flags, payload])

    externals = ["142.250.77.14", "157.240.1.35", "104.18.32.7", "13.107.42.14",
                 "151.101.1.69", "52.95.110.1"]
    # Normal traffic
    for _ in range(550):
        t = start + timedelta(seconds=rng.randint(0, 599))
        src = f"192.168.1.{rng.randint(2, 20)}"
        dp = rng.choice([80, 443, 443, 443, 8080, 53])
        if dp == 53:
            add(t, src, "8.8.8.8", rng.randint(40000, 60000), 53, "DNS",
                rng.randint(70, 120), "", "example.com")
        else:
            add(t, src, rng.choice(externals), rng.randint(40000, 60000), dp,
                "TCP", rng.randint(60, 1500), rng.choice(["ACK", "PSH", "SYN"]))

    def at(minute):
        return start + timedelta(minutes=minute, seconds=rng.randint(0, 59))

    # 1 Port scan
    for p in rng.sample(range(1, 1024), 40):
        add(at(2), "45.155.205.10", "192.168.1.10", 51000, p, "TCP", 60, "SYN")
    # 2 SYN flood
    for _ in range(150):
        add(at(3), "203.0.113.50", "192.168.1.10", rng.randint(1024, 65000),
            80, "TCP", 60, "SYN")
    # 3 UDP flood
    for _ in range(300):
        add(at(4), "91.240.118.2", "192.168.1.12", rng.randint(1024, 65000),
            rng.choice([80, 123, 1900]), "UDP", 512, "")
    # 4 Brute force on SSH
    for _ in range(30):
        add(at(5), "103.77.1.9", "192.168.1.5", rng.randint(1024, 65000),
            22, "TCP", 120, "PSH")
    # 5 Backdoor port
    for _ in range(3):
        add(at(6), "192.168.1.23", "91.92.109.43", 49222, 4444, "TCP", 300, "PSH")
    # 6 Data exfiltration
    for _ in range(6):
        add(at(7), "192.168.1.15", "185.199.110.153", 50505, 443, "TCP",
            2_000_000, "PSH")
    # 7 DNS tunneling
    for i in range(8):
        add(at(8), "192.168.1.30", "8.8.8.8", 53530 + i, 53, "DNS", 450, "",
            "aGVsbG8gd29ybGQ" * 6 + ".evil-tunnel.com")
    # 8 ICMP flood
    for _ in range(60):
        add(at(1), "77.88.55.60", "192.168.1.1", 0, 0, "ICMP", 84, "")
    # 9 Blacklisted IP
    for _ in range(3):
        add(at(9), "198.51.100.77", "192.168.1.8", 4000, 443, "TCP", 200, "ACK")
    # 10 Web attack payloads
    payloads = ["GET /item?id=1' OR 1=1--", "GET /?q=<script>alert(1)</script>",
                "GET /../../etc/passwd", "POST /login user=admin' UNION SELECT *",
                "GET /search?q=1;DROP TABLE users", "GET /cgi-bin/cmd.exe?/c+dir"]
    for pl in payloads:
        add(at(6), "172.67.10.4", "192.168.1.20", 52000, 80, "TCP", 400, "PSH", pl)

    df = pd.DataFrame(rows, columns=COLUMNS)
    return df.sort_values("timestamp").reset_index(drop=True)


# ---------------------------------------------------------------------------
# Detection engine
# ---------------------------------------------------------------------------
def detect(df, th, blacklist):
    d = df.copy()
    d["time"] = pd.to_datetime(d["timestamp"], errors="coerce")
    d = d.dropna(subset=["time"]).reset_index(drop=True)
    d["minute"] = d["time"].dt.floor("min")
    for c in ["src_port", "dst_port", "length"]:
        d[c] = pd.to_numeric(d[c], errors="coerce").fillna(0).astype(int)
    for c in ["src_ip", "dst_ip", "protocol", "flags", "payload"]:
        d[c] = d[c].fillna("").astype(str)

    key = [d["src_ip"], d["minute"]]
    grp = d.groupby(["src_ip", "minute"])
    hits = {}

    hits["Port Scan"] = grp["dst_port"].transform("nunique") >= th["scan"]

    syn = d["flags"].str.upper() == "SYN"
    hits["SYN Flood"] = syn & (syn.groupby(key).transform("sum") >= th["syn"])

    hits["High-Volume Flood (DoS)"] = grp["src_ip"].transform("size") >= th["flood"]

    bf = d["dst_port"].isin([21, 22, 23, 3389])
    hits["Brute Force Login"] = bf & (bf.groupby(key).transform("sum") >= th["brute"])

    hits["Suspicious Port"] = d["dst_port"].isin(BAD_PORTS)

    vol = grp["length"].transform("sum")
    hits["Data Exfiltration"] = (vol >= th["exfil"] * 1_000_000) & (d["length"] >= 100_000)

    dns = d["protocol"].str.upper() == "DNS"
    hits["DNS Tunneling"] = dns & ((d["length"] > th["dns"]) | (d["payload"].str.len() > 60))

    icmp = d["protocol"].str.upper() == "ICMP"
    hits["ICMP Flood"] = icmp & (icmp.groupby(key).transform("sum") >= th["icmp"])

    hits["Blacklisted IP"] = d["src_ip"].isin(blacklist) | d["dst_ip"].isin(blacklist)

    hits["Web Attack Payload"] = d["payload"].str.contains(WEB_REGEX, case=False, regex=True)

    sev_of = {p[0]: SEV_RANK[p[1]] for p in PATTERNS}
    rank = pd.Series(0, index=d.index)
    names = pd.Series([[] for _ in range(len(d))], index=d.index)
    for name, mask in hits.items():
        rank = np.maximum(rank, np.where(mask, sev_of[name], 0))
        for i in d.index[mask]:
            names[i].append(name)

    d["Detected Patterns"] = names.apply(", ".join)
    d["Severity"] = rank.map(lambda r: RANK_SEV.get(r, "Normal"))
    d["Unusual"] = rank > 0
    return d, hits


def style_rows(row):
    color = SEV_COLOR.get(row.get("Severity"), "")
    return [f"background-color: {color}; color: #000" if color else ""] * len(row)


SHOW = ["time", "src_ip", "src_port", "dst_ip", "dst_port", "protocol",
        "length", "flags", "payload"]


# ---------------------------------------------------------------------------
# Live packets (real capture with scapy, or simulated if capture is unavailable)
# ---------------------------------------------------------------------------
def sim_packets(n=4):
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    rows = []
    for _ in range(n):
        src = f"192.168.1.{random.randint(2, 30)}"
        if random.random() < 0.15:  # occasional suspicious packet
            kind = random.choice(["port", "web", "black", "dns"])
            if kind == "port":
                row = [now, src, random.randint(40000, 60000), "91.92.109.43", 4444, "TCP", 300, "PSH", ""]
            elif kind == "web":
                row = [now, "172.67.10.4", 52000, "192.168.1.20", 80, "TCP", 400, "PSH", "GET /item?id=1' OR 1=1--"]
            elif kind == "black":
                row = [now, "185.220.101.5", 4000, "192.168.1.8", 443, "TCP", 200, "ACK", ""]
            else:
                row = [now, src, 53530, "8.8.8.8", 53, "DNS", 450, "", "aGVsbG8gd29ybGQ" * 6 + ".evil-tunnel.com"]
        else:
            dp = random.choice([80, 443, 443, 443, 8080, 53])
            if dp == 53:
                row = [now, src, random.randint(40000, 60000), "8.8.8.8", 53, "DNS", random.randint(70, 120), "", "example.com"]
            else:
                row = [now, src, random.randint(40000, 60000), random.choice(["142.250.77.14", "157.240.1.35", "104.18.32.7"]),
                       dp, "TCP", random.randint(60, 1500), random.choice(["ACK", "PSH", "SYN"]), ""]
        rows.append(dict(zip(COLUMNS, row)))
    return rows


def real_packets(n=5):
    from scapy.all import sniff, IP, TCP, UDP, ICMP  # needs scapy + admin rights
    flag_names = {"S": "SYN", "SA": "SYN-ACK", "A": "ACK", "PA": "PSH", "FA": "FIN", "R": "RST"}
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    rows = []
    for p in sniff(count=n, timeout=2):
        if IP not in p:
            continue
        proto, sp, dp, flags = "OTHER", 0, 0, ""
        if TCP in p:
            proto, sp, dp = "TCP", p[TCP].sport, p[TCP].dport
            flags = flag_names.get(str(p[TCP].flags), str(p[TCP].flags))
        elif UDP in p:
            proto, sp, dp = "UDP", p[UDP].sport, p[UDP].dport
            if 53 in (sp, dp):
                proto = "DNS"
        elif ICMP in p:
            proto = "ICMP"
        rows.append(dict(zip(COLUMNS, [now, p[IP].src, sp, p[IP].dst, dp, proto, len(p), flags, ""])))
    return rows


def get_live_packets(use_real):
    if use_real:
        try:
            rows = real_packets()
            if rows:
                return rows, "Real network capture (scapy)"
        except Exception:
            pass
    return sim_packets(), "Simulated live traffic"

# ---------------------------------------------------------------------------
# Sidebar
# ---------------------------------------------------------------------------
st.sidebar.title("🛡️ Traffic Analyzer")
st.sidebar.caption(f"Made by {STUDENT_NAME} | Roll No {ROLL_NO} | {CLASS_NAME}")
source = st.sidebar.radio("Traffic source", ["Sample traffic", "Upload CSV"])

if source == "Sample traffic":
    if "seed" not in st.session_state:
        st.session_state.seed = 42
    if st.sidebar.button("🔄 Generate new sample"):
        st.session_state.seed = random.randint(1, 10_000)
    raw = make_sample(st.session_state.seed)
else:
    up = st.sidebar.file_uploader("Upload traffic CSV", type="csv")
    st.sidebar.caption("Columns: " + ", ".join(COLUMNS))
    if up is None:
        st.info("Upload a CSV file or switch to **Sample traffic** in the sidebar.")
        st.stop()
    raw = pd.read_csv(up)
    missing = [c for c in ["timestamp", "src_ip", "dst_ip", "dst_port",
                           "protocol", "length"] if c not in raw.columns]
    if missing:
        st.error(f"Missing required columns: {', '.join(missing)}")
        st.stop()
    for c in COLUMNS:
        if c not in raw.columns:
            raw[c] = ""

with st.sidebar.expander("⚙️ Detection thresholds"):
    th = {
        "scan": st.number_input("Port scan: distinct ports / min", 5, 500, 15),
        "syn": st.number_input("SYN flood: SYN packets / min", 20, 5000, 100),
        "flood": st.number_input("DoS flood: packets / min", 50, 10000, 250),
        "brute": st.number_input("Brute force: attempts / min", 3, 500, 10),
        "exfil": st.number_input("Exfiltration: MB / min", 1, 1000, 10),
        "dns": st.number_input("DNS tunnel: packet bytes >", 100, 2000, 300),
        "icmp": st.number_input("ICMP flood: pings / min", 5, 2000, 30),
    }
bl_text = st.sidebar.text_area("🚫 IP blacklist (one per line)", DEFAULT_BLACKLIST)
blacklist = {x.strip() for x in bl_text.splitlines() if x.strip()}

# ---------------------------------------------------------------------------
# Analysis
# ---------------------------------------------------------------------------
data, hits = detect(raw, th, blacklist)
unusual = data[data["Unusual"]].copy()
counts = {p[0]: int(hits[p[0]].sum()) for p in PATTERNS}
triggered = [n for n, c in counts.items() if c > 0]

if len(unusual):
    unusual.drop(columns=["minute", "Unusual"]).to_csv(SAVE_FILE, index=False)

# ---------------------------------------------------------------------------
# Main page
# ---------------------------------------------------------------------------
st.title("🛡️ Network Traffic Analyzer")
st.caption("Detects unusual network traffic using 10 built-in attack patterns.")

tab1, tab_live, tab2, tab3, tab4 = st.tabs(
    ["📊 Dashboard", "📡 Live Packets", "🌐 All Traffic",
     "🚨 Unusual Traffic", "📚 Pattern Library"])

# ---- Dashboard
with tab1:
    if len(unusual):
        st.error(f"🚨 ALERT: {len(unusual)} unusual packets detected "
                 f"across {len(triggered)} attack pattern(s)!")
    else:
        st.success("✅ No unusual traffic detected.")

    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Total packets", len(data))
    c2.metric("Unusual packets", len(unusual))
    c3.metric("Patterns detected", f"{len(triggered)} / {len(PATTERNS)}")
    c4.metric("Critical alerts", int((unusual["Severity"] == "Critical").sum()))

    if triggered:
        st.subheader("Active alerts")
        sev_lookup = {p[0]: p[1] for p in PATTERNS}
        for n in triggered:
            top = data[hits[n]]["src_ip"].value_counts().idxmax()
            msg = f"**{n}** ({sev_lookup[n]}): {counts[n]} packets, main source `{top}`"
            if sev_lookup[n] == "Critical":
                st.error(msg)
            elif sev_lookup[n] == "High":
                st.warning(msg)
            else:
                st.info(msg)

        st.subheader("Packets per pattern")
        chart = pd.Series(counts, name="Packets")
        st.bar_chart(chart[chart > 0])

        st.subheader("Top suspicious IPs")
        st.dataframe(unusual["src_ip"].value_counts().head(8)
                     .rename_axis("Source IP").reset_index(name="Unusual packets"),
                     hide_index=True)

# ---- All traffic
with tab2:
    st.write("Unusual packets are highlighted in colour "
             "(🟨 Medium, 🟧 High, 🟥 Critical).")
    view = data[SHOW + ["Severity", "Detected Patterns"]].copy()
    view["time"] = view["time"].astype(str)
    st.dataframe(view.style.apply(style_rows, axis=1), height=500)

# ---- Unusual traffic
with tab3:
    st.subheader("🚨 Unusual Traffic")
    if len(unusual):
        st.write(f"**{len(unusual)}** packets flagged. Saved to `{SAVE_FILE}`.")
        sev_filter = st.multiselect("Filter by severity",
                                    ["Critical", "High", "Medium"],
                                    default=["Critical", "High", "Medium"])
        pat_filter = st.multiselect("Filter by pattern", triggered)
        u = unusual[unusual["Severity"].isin(sev_filter)]
        if pat_filter:
            u = u[u["Detected Patterns"].apply(
                lambda s: any(p in s for p in pat_filter))]
        show = u[SHOW + ["Severity", "Detected Patterns"]].copy()
        show["time"] = show["time"].astype(str)
        st.dataframe(show.style.apply(style_rows, axis=1), height=450)
        st.download_button("⬇️ Download unusual traffic (CSV)",
                           show.to_csv(index=False).encode(),
                           "unusual_traffic.csv", "text/csv")
    else:
        st.info("Nothing here yet. No unusual traffic was found.")

# ---- Pattern library
with tab4:
    st.subheader("📚 Patterns this tool can identify")
    st.write(f"Total patterns loaded: **{len(PATTERNS)}** "
             f"| Detected in current traffic: **{len(triggered)}**")
    lib = pd.DataFrame([{
        "#": i + 1,
        "Pattern": p[0],
        "Severity": p[1],
        "What it means": p[2],
        "How it is detected": p[3],
        "Hits": counts[p[0]],
        "Status": "🔴 Detected" if counts[p[0]] else "🟢 Not seen",
    } for i, p in enumerate(PATTERNS)])
    st.dataframe(lib, hide_index=True)

# ---- Live packets
with tab_live:
    st.subheader("📡 Live Network Packets")
    c1, c2 = st.columns(2)
    c1.toggle("▶ Start live monitoring", key="live_on")
    c2.checkbox("Use real network capture (needs scapy + admin/root rights)",
                key="use_real")
    if "live_buf" not in st.session_state:
        st.session_state.live_buf = []

    @st.fragment(run_every=2 if st.session_state.get("live_on") else None)
    def live_monitor():
        if st.session_state.get("live_on"):
            rows, mode = get_live_packets(st.session_state.get("use_real", False))
            st.session_state.live_buf = (st.session_state.live_buf + rows)[-300:]
            st.session_state.live_mode = mode
        buf = st.session_state.live_buf
        if not buf:
            st.info("Turn on **Start live monitoring** to see packets arriving.")
            return
        ld, _ = detect(pd.DataFrame(buf), th, blacklist)
        flagged = ld[ld["Unusual"]]
        st.caption(f"Source: {st.session_state.get('live_mode', '-')}  |  refreshes every 2 seconds")
        m1, m2, m3 = st.columns(3)
        m1.metric("Packets captured", len(ld))
        m2.metric("Unusual packets", len(flagged))
        m3.metric("Latest packet", str(ld["time"].iloc[-1].time()))
        if ld.tail(5)["Unusual"].any():
            st.error("🚨 Unusual packet detected in the latest traffic!")
        else:
            st.success("✅ Live traffic looks normal.")
        cols = SHOW + ["Severity", "Detected Patterns"]
        latest = ld[cols].tail(15).iloc[::-1].copy()
        latest["time"] = latest["time"].astype(str)
        st.write("**Latest packets** (newest first)")
        st.dataframe(latest.style.apply(style_rows, axis=1))
        if len(flagged):
            st.write("**🚨 Unusual packets seen live**")
            fl = flagged[cols].tail(20).iloc[::-1].copy()
            fl["time"] = fl["time"].astype(str)
            fl.to_csv(LIVE_SAVE_FILE, index=False)
            st.dataframe(fl.style.apply(style_rows, axis=1))

    live_monitor()

st.divider()
st.caption(f"This project is made By {STUDENT_NAME} | Roll No {ROLL_NO} | {CLASS_NAME}")
