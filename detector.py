#!/usr/bin/env python3
import os, sys, re, time, sqlite3
from collections import defaultdict, deque

DB_PATH = os.path.expanduser("~/soc-project/soc.db")
LOG_FILE = "/var/log/soc-remote.log"
WINDOW_SECONDS = 60
BRUTE_FORCE_THRESHOLD = 4

# Regex Patterns for Linux Authentication Logs
RE_SSH_FAILED = re.compile(
    r"Failed password for (?P<invalid>invalid user )?(?P<user>\S+) from (?P<src_ip>\d+\.\d+\.\d+\.\d+)"
)
RE_SSH_SUCCESS = re.compile(
    r"Accepted (?:password|publickey) for (?P<user>\S+) from (?P<src_ip>\d+\.\d+\.\d+\.\d+)"
)
RE_SUDO_FAILED = re.compile(
    r"(?P<user>\S+) : (?:(?P<attempts>\d+) incorrect password attempts|user NOT in sudoers|command not allowed)"
)

# Stateful In-Memory Window: IP -> deque([timestamps])
ip_failed_logins = defaultdict(deque)

def normalize_line(raw: str):
    event = {
        "hostname": "soc-server",
        "app_name": "auth",
        "user": None,
        "src_ip": None,
        "event_type": "UNKNOWN",
        "raw_log": raw
    }
    
    # Check for SSH Failed
    m_fail = RE_SSH_FAILED.search(raw)
    if m_fail:
        event["user"] = m_fail.group("user")
        event["src_ip"] = m_fail.group("src_ip")
        event["event_type"] = "USER_ENUM" if m_fail.group("invalid") else "AUTH_FAILED"
        return event

    # Check for SSH Success
    m_ok = RE_SSH_SUCCESS.search(raw)
    if m_ok:
        event["user"] = m_ok.group("user")
        event["src_ip"] = m_ok.group("src_ip")
        event["event_type"] = "AUTH_SUCCESS"
        return event

    # Check for Sudo Abuse
    m_sudo = RE_SUDO_FAILED.search(raw)
    if m_sudo:
        event["user"] = m_sudo.group("user")
        event["src_ip"] = "127.0.0.1"
        event["event_type"] = "SUDO_FAILED"
        return event

    return event

def process_event(event: dict):
    now = time.time()
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    # 1. Save normalized event
    c.execute("""
        INSERT INTO events (hostname, app_name, user, src_ip, event_type, raw_log)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (event["hostname"], event["app_name"], event["user"], event["src_ip"], event["event_type"], event["raw_log"]))

    alerts = []

    # Rule 1: SSH Brute Force (T1110.001)
    if event["event_type"] in ("AUTH_FAILED", "USER_ENUM") and event["src_ip"]:
        ip = event["src_ip"]
        q = ip_failed_logins[ip]
        q.append(now)

        # Sliding window pruning
        while q and now - q[0] > WINDOW_SECONDS:
            q.popleft()

        if len(q) > BRUTE_FORCE_THRESHOLD:
            alerts.append((
                "SSH Brute Force Attack",
                "HIGH",
                "Brute Force: Password Guessing (T1110.001)",
                ip,
                event["user"],
                f"Observed {len(q)} failed SSH logins from {ip} in under {WINDOW_SECONDS}s."
            ))
            q.clear()

    # Rule 2: User Enumeration (T1110)
    if event["event_type"] == "USER_ENUM":
        alerts.append((
            "SSH User Enumeration",
            "MEDIUM",
            "Brute Force (T1110)",
            event["src_ip"],
            event["user"],
            f"Probed non-existent account '{event['user']}' from {event['src_ip']}."
        ))

    # Rule 3: Unauthorized Sudo (T1548.003)
    if event["event_type"] == "SUDO_FAILED":
        alerts.append((
            "Unauthorized Sudo Execution",
            "HIGH",
            "Abuse Elevation Control Mechanism: Sudo (T1548.003)",
            "127.0.0.1",
            event["user"],
            f"Unauthorized sudo execution attempted by '{event['user']}'."
        ))

    # 2. Save generated alerts
    for a in alerts:
        c.execute("""
            INSERT INTO alerts (rule_name, severity, mitre_technique, src_ip, user, description)
            VALUES (?, ?, ?, ?, ?, ?)
        """, a)
        print(f"\n🚨 [ALERT GENERATED] {a[0]} ({a[1]})")
        print(f"   ├── Technique: {a[2]}")
        print(f"   ├── Target:    {a[4]} @ {a[3]}")
        print(f"   └── Detail:    {a[5]}")

    conn.commit()
    conn.close()

def main():
    print("=" * 60)
    print("⚡ SOC DETECTION ENGINE ACTIVE & MONITORING")
    print(f"   Listening on: {LOG_FILE}")
    print(f"   Database:     {DB_PATH}")
    print("=" * 60)

    # Tail the log file from the end
    with open(LOG_FILE, "r") as f:
        f.seek(0, os.SEEK_END)
        while True:
            line = f.readline()
            if line:
                line = line.strip()
                if line:
                    ev = normalize_line(line)
                    process_event(ev)
            else:
                time.sleep(0.2)

if __name__ == "__main__":
    main()
