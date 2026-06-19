"""
Synthetic log generator — University Threat Detection research.

Generates 3 log sources with 5 shared attack scenarios:
  - nginx_large.log    : 50,000 lines, nginx Combined Log Format
  - auth_large.log     : 50,000 lines, Linux /var/log/auth.log format
  - firewall_large.csv : 50,000 lines, CSV firewall events

Each attack IP has a consistent time window across all sources it appears in,
enabling genuine cross-source feature correlation during ML evaluation.
"""
import csv
import os
import re
import random
import time
from datetime import datetime, timedelta

from faker import Faker

fake = Faker()
random.seed(42)

OUTPUT_DIR = os.path.join(
    os.path.dirname(__file__), "..", "..", "data", "synthetic"
)

TOTAL_RECORDS = 50_000
START_DT = datetime(2026, 1, 1, 0, 0, 0)
END_DT   = datetime(2026, 1, 8, 0, 0, 0)   # 7-day window

# ---------------------------------------------------------------------------
# Shared attack scenarios
# Each scenario has a consistent time window → timestamps overlap across sources
# ---------------------------------------------------------------------------
ATTACK_SCENARIOS = [
    {
        "ip":           "45.33.32.156",
        "label":        "full_attacker",
        "start":        datetime(2026, 1, 3, 0, 0, 0),
        "end":          datetime(2026, 1, 8, 0, 0, 0),
        "nginx_count":  5000, "nginx_type":  "scan",
        "auth_count":   2000, "auth_type":   "brute_force",
        "fw_count":     8000, "fw_type":     "portscan",
    },
    {
        "ip":           "185.220.101.45",
        "label":        "web_fw_attacker",
        "start":        datetime(2026, 1, 2, 0, 0, 0),
        "end":          datetime(2026, 1, 7, 0, 0, 0),
        "nginx_count":  3000, "nginx_type":  "brute_force",
        "auth_count":      0,
        "fw_count":     4000, "fw_type":     "blocked",
    },
    {
        "ip":           "192.241.175.65",
        "label":        "ssh_web_attacker",
        "start":        datetime(2026, 1, 4, 0, 0, 0),
        "end":          datetime(2026, 1, 8, 0, 0, 0),
        "nginx_count":  1500, "nginx_type":  "brute_force",
        "auth_count":   4000, "auth_type":   "brute_force",
        "fw_count":        0,
    },
    {
        "ip":           "117.21.191.136",
        "label":        "pure_ssh_attacker",
        "start":        datetime(2026, 1, 1, 0, 0, 0),
        "end":          datetime(2026, 1, 6, 0, 0, 0),
        "nginx_count":     0,
        "auth_count":   3000, "auth_type":   "invalid_user",
        "fw_count":     1000, "fw_type":     "blocked",
    },
    {
        "ip":           "198.199.83.42",
        "label":        "recon_attacker",
        "start":        datetime(2026, 1, 2, 0, 0, 0),
        "end":          datetime(2026, 1, 8, 0, 0, 0),
        "nginx_count":  2000, "nginx_type":  "scan",
        "auth_count":    500, "auth_type":   "brute_force",
        "fw_count":     3000, "fw_type":     "portscan",
    },
]

# ---------------------------------------------------------------------------
# Timestamp helpers
# ---------------------------------------------------------------------------

def _rand_ts() -> datetime:
    span = int((END_DT - START_DT).total_seconds())
    return START_DT + timedelta(seconds=random.randint(0, span))


def _rand_ts_in(start: datetime, end: datetime) -> datetime:
    span = int((end - start).total_seconds())
    return start + timedelta(seconds=random.randint(0, span))


def _pub_ip() -> str:
    return fake.ipv4_public()


def _priv_ip() -> str:
    return f"192.168.{random.randint(1, 10)}.{random.randint(2, 254)}"


# ===========================================================================
# NGINX ACCESS LOG  (Combined Log Format)
# ===========================================================================

_NGINX_NORMAL_ENDPOINTS = [
    "/", "/index.html", "/about", "/contact",
    "/api/v1/users", "/api/v1/products", "/api/v1/reports",
    "/static/main.js", "/static/style.css", "/images/logo.png",
    "/favicon.ico", "/sitemap.xml", "/dashboard", "/profile",
    "/search", "/blog", "/blog/post-1", "/blog/post-2",
]

_NGINX_SCAN_ENDPOINTS = [
    "/admin", "/wp-admin", "/phpmyadmin", "/.env", "/.git/config",
    "/backup.zip", "/config.php", "/install.php", "/setup.php",
    "/api/admin", "/shell.php", "/c99.php", "/webshell.php",
    "/../etc/passwd", "/wp-login.php", "/xmlrpc.php",
    "/cgi-bin/test.cgi", "/server-status", "/.htaccess",
    "/robots.txt", "/web.config", "/crossdomain.xml",
]

_NORMAL_UA = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/119.0.0.0 Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15",
    "curl/7.88.1",
    "python-requests/2.31.0",
]

_ATTACK_UA = [
    "Nikto/2.1.6",
    "sqlmap/1.7.8#stable",
    "Nmap Scripting Engine",
    "masscan/1.3.2",
    "w3af.org",
    "dirbuster/1.0-RC1",
]


def _nginx_ts(dt: datetime) -> str:
    return dt.strftime("%d/%b/%Y:%H:%M:%S +0000")


def _nginx_line(ip, method, endpoint, status, size, ref, ua, dt) -> str:
    return (
        f'{ip} - - [{_nginx_ts(dt)}] '
        f'"{method} {endpoint} HTTP/1.1" {status} {size} "{ref}" "{ua}"'
    )


def _nginx_normal(dt: datetime) -> str:
    ip     = _pub_ip()
    method = random.choice(["GET"] * 8 + ["POST"] * 2)
    ep     = random.choice(_NGINX_NORMAL_ENDPOINTS)
    status = random.choice([200] * 6 + [301, 304, 404, 200])
    size   = random.randint(200, 50_000)
    ua     = random.choice(_NORMAL_UA)
    return _nginx_line(ip, method, ep, status, size, "-", ua, dt)


def _nginx_large_response(dt: datetime) -> str:
    ip   = _pub_ip()
    ep   = random.choice(["/api/v1/data/export", "/reports/full.csv",
                          "/api/v1/logs", "/backup/dataset.zip"])
    size = random.randint(1_000_000, 50_000_000)
    ua   = random.choice(_NORMAL_UA[:3])
    return _nginx_line(ip, "GET", ep, 200, size,
                       f"https://university.edu{ep}", ua, dt)


def _nginx_scan(dt: datetime, ip: str) -> str:
    method = random.choice(["GET", "HEAD"])
    ep     = random.choice(_NGINX_SCAN_ENDPOINTS)
    status = random.choice([404, 404, 404, 404, 403, 200, 500])
    size   = random.randint(0, 2_000)
    ua     = random.choice(_ATTACK_UA)
    return _nginx_line(ip, method, ep, status, size, "-", ua, dt)


def _nginx_bruteforce(dt: datetime, ip: str) -> str:
    ep     = random.choice(["/api/v1/login", "/login", "/wp-login.php", "/admin/login"])
    status = random.choice([401, 401, 401, 403, 200])
    size   = random.randint(50, 500)
    ua     = random.choice(_NORMAL_UA[:3])
    return _nginx_line(ip, "POST", ep, status, size, "-", ua, dt)


def generate_nginx(scenarios=ATTACK_SCENARIOS, total=TOTAL_RECORDS):
    """Build nginx log lines: attack records from scenarios + normal filler."""
    records = []
    per_ip  = {}

    # Attack records — within each scenario's time window
    for sc in scenarios:
        n = sc["nginx_count"]
        if n == 0:
            continue
        ip = sc["ip"]
        for _ in range(n):
            dt = _rand_ts_in(sc["start"], sc["end"])
            line = _nginx_scan(dt, ip) if sc["nginx_type"] == "scan" else _nginx_bruteforce(dt, ip)
            records.append((dt, line))
        per_ip[ip] = n

    # Normal filler
    n_normal = total - sum(sc["nginx_count"] for sc in scenarios)
    for _ in range(n_normal):
        dt = _rand_ts()
        if random.random() < 0.95:
            records.append((dt, _nginx_normal(dt)))
        else:
            records.append((dt, _nginx_large_response(dt)))

    records.sort(key=lambda x: x[0])
    return [r[1] for r in records], per_ip, n_normal


# ===========================================================================
# AUTH LOG  (/var/log/auth.log syslog format)
# ===========================================================================

_HOSTS      = ["uni-server-01", "auth-srv-02", "lab-linux-03", "web-srv-04"]
_REAL_USERS = ["alice", "bob", "charlie", "dave", "eve",
               "frank", "grace", "henry", "ivan", "judy"]
_ATCK_USERS = ["root", "admin", "administrator", "ubuntu", "pi",
               "oracle", "postgres", "test", "ftpuser", "user"]
_MONTHS     = ["Jan", "Feb", "Mar", "Apr", "May", "Jun",
               "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]


def _auth_ts(dt: datetime) -> str:
    return f"{_MONTHS[dt.month - 1]} {str(dt.day).rjust(2)} {dt.strftime('%H:%M:%S')}"


def _auth_normal(dt: datetime) -> str:
    host = random.choice(_HOSTS)
    pid  = random.randint(10_000, 99_999)
    r    = random.random()
    if r < 0.40:
        user = random.choice(_REAL_USERS)
        ip   = _pub_ip()
        port = random.randint(49_152, 65_535)
        return (f"{_auth_ts(dt)} {host} sshd[{pid}]: "
                f"Accepted password for {user} from {ip} port {port} ssh2")
    elif r < 0.60:
        user = random.choice(_REAL_USERS)
        cmd  = random.choice([
            "/usr/bin/apt-get update",
            "/usr/bin/systemctl restart nginx",
            "/usr/bin/tail -f /var/log/syslog",
        ])
        return (f"{_auth_ts(dt)} {host} sudo[{pid}]:    {user} : "
                f"TTY=pts/0 ; PWD=/home/{user} ; USER=root ; COMMAND={cmd}")
    elif r < 0.80:
        action = random.choice(["opened", "closed"])
        return (f"{_auth_ts(dt)} {host} CRON[{pid}]: "
                f"pam_unix(cron:session): session {action} for user root by (uid=0)")
    else:
        user   = random.choice(_REAL_USERS)
        action = random.choice(["opened", "closed"])
        return (f"{_auth_ts(dt)} {host} sshd[{pid}]: "
                f"pam_unix(sshd:session): session {action} for user {user}")


def _auth_bruteforce(dt: datetime, ip: str) -> str:
    """SSH brute-force: mix of Failed password and Invalid user events."""
    host = random.choice(_HOSTS)
    user = random.choice(_ATCK_USERS)
    port = random.randint(49_152, 65_535)
    pid  = random.randint(10_000, 99_999)
    r    = random.random()
    if r < 0.55:
        return (f"{_auth_ts(dt)} {host} sshd[{pid}]: "
                f"Failed password for {user} from {ip} port {port} ssh2")
    elif r < 0.85:
        return (f"{_auth_ts(dt)} {host} sshd[{pid}]: "
                f"Invalid user {user} from {ip} port {port}")
    else:
        return (f"{_auth_ts(dt)} {host} sshd[{pid}]: "
                f"Connection closed by invalid user {user} {ip} port {port} [preauth]")


def _auth_invalid_user(dt: datetime, ip: str) -> str:
    """Pure username-enumeration pattern — only Invalid user lines."""
    host = random.choice(_HOSTS)
    user = random.choice(_ATCK_USERS)
    port = random.randint(49_152, 65_535)
    pid  = random.randint(10_000, 99_999)
    return (f"{_auth_ts(dt)} {host} sshd[{pid}]: "
            f"Invalid user {user} from {ip} port {port}")


def generate_auth(scenarios=ATTACK_SCENARIOS, total=TOTAL_RECORDS):
    """Build auth log lines: attack records from scenarios + normal filler."""
    records = []
    per_ip  = {}

    for sc in scenarios:
        n = sc["auth_count"]
        if n == 0:
            continue
        ip = sc["ip"]
        gen = _auth_invalid_user if sc.get("auth_type") == "invalid_user" else _auth_bruteforce
        for _ in range(n):
            dt = _rand_ts_in(sc["start"], sc["end"])
            records.append((dt, gen(dt, ip)))
        per_ip[ip] = n

    n_normal = total - sum(sc["auth_count"] for sc in scenarios)
    for _ in range(n_normal):
        dt = _rand_ts()
        records.append((dt, _auth_normal(dt)))

    records.sort(key=lambda x: x[0])
    return [r[1] for r in records], per_ip, n_normal


# ===========================================================================
# FIREWALL CSV
# ===========================================================================

_NORMAL_DST_PORTS = [80, 443, 53, 22, 8080, 8443, 587, 25, 21, 3306, 5432]
_MALICIOUS_PORTS  = [23, 445, 3389, 4444, 1433, 8888, 31337, 6667]


def _fw_normal(dt: datetime) -> list:
    src_ip   = _priv_ip()
    dst_ip   = _pub_ip()
    src_port = random.randint(49_152, 65_535)
    dst_port = random.choice(_NORMAL_DST_PORTS)
    proto    = "UDP" if dst_port == 53 else "TCP"
    return [dt.strftime("%Y-%m-%d %H:%M:%S"),
            src_ip, dst_ip, src_port, dst_port, proto, "allow",
            random.randint(100, 100_000)]


def _fw_portscan(dt: datetime, ip: str, counter: int) -> list:
    dst_ip   = _priv_ip()
    src_port = random.randint(49_152, 65_535)
    dst_port = (counter % 65_535) + 1   # sequential port sweep
    action   = random.choice(["deny"] * 8 + ["allow"])
    return [dt.strftime("%Y-%m-%d %H:%M:%S"),
            ip, dst_ip, src_port, dst_port, "TCP", action,
            random.randint(40, 100)]


def _fw_blocked(dt: datetime, ip: str) -> list:
    dst_ip   = _priv_ip()
    src_port = random.randint(1_024, 65_535)
    dst_port = random.choice(_MALICIOUS_PORTS)
    proto    = random.choice(["TCP", "UDP"])
    return [dt.strftime("%Y-%m-%d %H:%M:%S"),
            ip, dst_ip, src_port, dst_port, proto, "deny",
            random.randint(40, 500)]


def generate_firewall(scenarios=ATTACK_SCENARIOS, total=TOTAL_RECORDS):
    """Build firewall rows: attack records from scenarios + normal filler."""
    rows   = []
    per_ip = {}
    # Per-scenario port counter for sequential portscan
    scan_counters = {sc["ip"]: 0 for sc in scenarios if sc.get("fw_type") == "portscan"}

    for sc in scenarios:
        n = sc["fw_count"]
        if n == 0:
            continue
        ip = sc["ip"]
        for _ in range(n):
            dt = _rand_ts_in(sc["start"], sc["end"])
            if sc["fw_type"] == "portscan":
                row = _fw_portscan(dt, ip, scan_counters[ip])
                scan_counters[ip] += 1
            else:
                row = _fw_blocked(dt, ip)
            rows.append((dt, row))
        per_ip[ip] = n

    n_normal = total - sum(sc["fw_count"] for sc in scenarios)
    for _ in range(n_normal):
        dt = _rand_ts()
        rows.append((dt, _fw_normal(dt)))

    rows.sort(key=lambda x: x[0])
    return [r[1] for r in rows], per_ip, n_normal


# ===========================================================================
# VERIFY — cross-source IP overlap
# ===========================================================================

# Matches all 3 auth line patterns (Failed password / Invalid user / Connection closed)
_RE_AUTH_IP = re.compile(r"(\d+\.\d+\.\d+\.\d+) port \d+")


def _extract_ips(nginx_path: str, auth_path: str, fw_path: str):
    nginx_ips = set()
    with open(nginx_path, encoding="utf-8") as f:
        for line in f:
            parts = line.split()
            if parts:
                nginx_ips.add(parts[0])

    auth_ips = set()
    with open(auth_path, encoding="utf-8") as f:
        for line in f:
            for m in _RE_AUTH_IP.finditer(line):
                auth_ips.add(m.group(1))

    fw_ips = set()
    with open(fw_path, encoding="utf-8") as f:
        reader = csv.reader(f)
        next(reader)  # skip header
        for row in reader:
            if len(row) >= 2:
                fw_ips.add(row[1])

    return nginx_ips, auth_ips, fw_ips


def _verify_cross_source(nginx_path: str, auth_path: str, fw_path: str):
    nginx_ips, auth_ips, fw_ips = _extract_ips(nginx_path, auth_path, fw_path)
    attack_ips = {sc["ip"] for sc in ATTACK_SCENARIOS}

    print("\n=== Cross-source IP overlap (attack IPs only) ===")
    ng_a  = nginx_ips & auth_ips & attack_ips
    ng_fw = nginx_ips & fw_ips  & attack_ips
    a_fw  = auth_ips  & fw_ips  & attack_ips
    all3  = nginx_ips & auth_ips & fw_ips & attack_ips
    print(f"  nginx + auth     : {sorted(ng_a)}")
    print(f"  nginx + firewall : {sorted(ng_fw)}")
    print(f"  auth  + firewall : {sorted(a_fw)}")
    print(f"  all 3 sources    : {sorted(all3)}")

    print("\n=== Per-scenario source coverage ===")
    header = f"{'IP':<18} {'nginx':>6} {'auth':>6} {'fw':>6}  sources  in_data"
    print("  " + header)
    print("  " + "-" * len(header))
    for sc in ATTACK_SCENARIOS:
        ip       = sc["ip"]
        exp_ng   = sc["nginx_count"]
        exp_au   = sc["auth_count"]
        exp_fw   = sc["fw_count"]
        exp_srcs = sum(1 for c in [exp_ng, exp_au, exp_fw] if c > 0)
        in_ng  = "Y" if (exp_ng > 0 and ip in nginx_ips) else ("N" if exp_ng > 0 else "-")
        in_au  = "Y" if (exp_au > 0 and ip in auth_ips)  else ("N" if exp_au > 0 else "-")
        in_fw  = "Y" if (exp_fw > 0 and ip in fw_ips)    else ("N" if exp_fw > 0 else "-")
        print(f"  {ip:<18} {exp_ng:>6,} {exp_au:>6,} {exp_fw:>6,}     {exp_srcs}     ng={in_ng} au={in_au} fw={in_fw}")

    # Timestamp overlap sample for IPs in multiple sources
    print("\n=== Timestamp overlap sample (same IP, different sources) ===")
    _sample_timestamps(nginx_path, auth_path, fw_path)


def _sample_timestamps(nginx_path: str, auth_path: str, fw_path: str):
    """Show 1 record from each source for IPs that appear in >= 2 sources."""
    # Quick in-memory sample (read first matching line per IP per source)
    targets = {sc["ip"] for sc in ATTACK_SCENARIOS
               if sum(1 for c in [sc["nginx_count"], sc["auth_count"], sc["fw_count"]] if c > 0) >= 2}

    samples = {ip: {} for ip in targets}

    with open(nginx_path, encoding="utf-8") as f:
        for line in f:
            ip = line.split()[0] if line.split() else ""
            if ip in targets and "nginx" not in samples[ip]:
                samples[ip]["nginx"] = line.strip()

    with open(auth_path, encoding="utf-8") as f:
        for line in f:
            for m in _RE_AUTH_IP.finditer(line):
                ip = m.group(1)
                if ip in targets and "auth" not in samples[ip]:
                    samples[ip]["auth"] = line.strip()

    with open(fw_path, encoding="utf-8") as f:
        reader = csv.reader(f)
        next(reader)
        for row in reader:
            if len(row) >= 2:
                ip = row[1]
                if ip in targets and "fw" not in samples[ip]:
                    samples[ip]["fw"] = row[0]  # just timestamp

    for ip, src_map in sorted(samples.items()):
        if len(src_map) >= 2:
            print(f"\n  IP: {ip}")
            for src, sample in src_map.items():
                trimmed = sample[:100] + "..." if len(sample) > 100 else sample
                print(f"    [{src:6}] {trimmed}")


# ===========================================================================
# MAIN
# ===========================================================================

def main():
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    print("=" * 60)
    print("Synthetic Log Generator — University Threat Detection")
    print("=" * 60)

    # --- scenario summary table ---
    print("\nAttack scenarios:")
    print(f"  {'IP':<18} {'nginx':>7} {'auth':>7} {'fw':>7}  sources")
    print(f"  {'-'*18} {'-'*7} {'-'*7} {'-'*7}  -------")
    for sc in ATTACK_SCENARIOS:
        srcs = sum(1 for c in [sc["nginx_count"], sc["auth_count"], sc["fw_count"]] if c > 0)
        print(f"  {sc['ip']:<18} {sc['nginx_count']:>7,} {sc['auth_count']:>7,} {sc['fw_count']:>7,}     {srcs}")
    total_ng = sum(sc["nginx_count"] for sc in ATTACK_SCENARIOS)
    total_au = sum(sc["auth_count"]  for sc in ATTACK_SCENARIOS)
    total_fw = sum(sc["fw_count"]    for sc in ATTACK_SCENARIOS)
    print(f"  {'TOTAL ATTACK':<18} {total_ng:>7,} {total_au:>7,} {total_fw:>7,}")
    print(f"  {'NORMAL':<18} {TOTAL_RECORDS-total_ng:>7,} {TOTAL_RECORDS-total_au:>7,} {TOTAL_RECORDS-total_fw:>7,}")

    # --- nginx ---
    print(f"\n[1/3] nginx_large.log  (target: {TOTAL_RECORDS:,} lines) ...")
    t0 = time.time()
    nginx_lines, ng_per_ip, ng_normal = generate_nginx()
    out_ng = os.path.join(OUTPUT_DIR, "nginx_large.log")
    with open(out_ng, "w", encoding="utf-8") as f:
        f.write("\n".join(nginx_lines) + "\n")
    print(f"  Saved : {out_ng}")
    print(f"  Lines : {len(nginx_lines):,}  ({time.time()-t0:.1f}s)")
    print(f"  Size  : {os.path.getsize(out_ng)/1024/1024:.2f} MB")
    print(f"  Attack: {ng_per_ip}  |  Normal: {ng_normal:,}")

    # --- auth ---
    print(f"\n[2/3] auth_large.log   (target: {TOTAL_RECORDS:,} lines) ...")
    t0 = time.time()
    auth_lines, au_per_ip, au_normal = generate_auth()
    out_au = os.path.join(OUTPUT_DIR, "auth_large.log")
    with open(out_au, "w", encoding="utf-8") as f:
        f.write("\n".join(auth_lines) + "\n")
    print(f"  Saved : {out_au}")
    print(f"  Lines : {len(auth_lines):,}  ({time.time()-t0:.1f}s)")
    print(f"  Size  : {os.path.getsize(out_au)/1024/1024:.2f} MB")
    print(f"  Attack: {au_per_ip}  |  Normal: {au_normal:,}")

    # --- firewall ---
    print(f"\n[3/3] firewall_large.csv (target: {TOTAL_RECORDS:,} lines) ...")
    t0 = time.time()
    fw_rows, fw_per_ip, fw_normal = generate_firewall()
    out_fw = os.path.join(OUTPUT_DIR, "firewall_large.csv")
    with open(out_fw, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["timestamp", "src_ip", "dst_ip",
                         "src_port", "dst_port", "protocol", "action", "bytes"])
        writer.writerows(fw_rows)
    print(f"  Saved : {out_fw}")
    print(f"  Lines : {len(fw_rows)+1:,} (incl. header)  ({time.time()-t0:.1f}s)")
    print(f"  Size  : {os.path.getsize(out_fw)/1024/1024:.2f} MB")
    print(f"  Attack: {fw_per_ip}  |  Normal: {fw_normal:,}")

    # --- verify ---
    _verify_cross_source(out_ng, out_au, out_fw)

    print("\n[Done]")


if __name__ == "__main__":
    main()
