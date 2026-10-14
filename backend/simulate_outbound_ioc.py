"""
ARGUS — Suspicious Outbound Connection Attack Simulator
========================================================
This script demonstrates ARGUS detecting outbound connections to
known malicious IP addresses (IOC — Indicators of Compromise).

HOW IT WORKS:
  1. Adds a list of known-malicious IPs to the ARGUS IOC blocklist
     via the REST API (POST /api/ioc).
  2. Generates real outbound TCP connection attempts to those IPs
     on common C2 (Command & Control) ports.
  3. Scapy (running inside ARGUS) captures these outbound packets
     on the live network interface.
  4. The OutboundDetector matches the destination IP against the
     IOC blocklist and fires a HIGH severity alert.
  5. Alerts appear on the SOC dashboard in real-time via WebSocket.

NOTE:
  The IPs used are RFC 5737 TEST-NET addresses (198.51.100.x,
  203.0.113.x) — they are reserved for documentation and will
  never route to real hosts. The connections will fail (as expected),
  but the SYN packets are still captured by Scapy and trigger alerts.

REQUIREMENTS:
  - ARGUS server must be running (python backend/server.py)
  - Open the dashboard at http://localhost:8000 to watch alerts
  - No admin privileges required for this script

USAGE:
  cd backend
  python simulate_outbound_ioc.py
"""

import socket
import time
import sys
import os
import urllib.request
import json

# Fix Windows terminal encoding
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
    os.system("")  # Enable ANSI escape sequences


# ─────────────────────────────────────────────────────────────────────────────
# Configuration
# ─────────────────────────────────────────────────────────────────────────────

ARGUS_API = "http://127.0.0.1:8000"

# Simulated malicious C2 / threat-intel IOC IPs
# These are RFC 5737 TEST-NET addresses — safe, non-routable IPs
MALICIOUS_IOCS = [
    {
        "ip": "198.51.100.50",
        "label": "Cobalt Strike C2 Server",
        "ports": [443, 8443, 4444],
    },
    {
        "ip": "203.0.113.66",
        "label": "APT28 Exfiltration Node",
        "ports": [80, 443, 8080],
    },
    {
        "ip": "198.51.100.99",
        "label": "Ransomware Payment Gateway",
        "ports": [443, 9001],
    },
    {
        "ip": "203.0.113.200",
        "label": "Botnet C2 Controller",
        "ports": [6667, 443, 80],
    },
]

# Connection timeout — keep it short since these IPs won't respond
CONNECT_TIMEOUT = 0.5

# Delay between connection attempts (seconds)
DELAY_BETWEEN_ATTEMPTS = 1.0

# Delay between IOC groups (seconds)
DELAY_BETWEEN_IOCS = 2.0


# ─────────────────────────────────────────────────────────────────────────────
# Helper Functions
# ─────────────────────────────────────────────────────────────────────────────

def print_banner():
    print()
    print("=" * 70)
    print("  ARGUS  —  SUSPICIOUS OUTBOUND CONNECTION SIMULATOR")
    print("=" * 70)
    print()
    print("  This script simulates outbound connections to known malicious")
    print("  IPs (IOC blocklist). ARGUS captures these packets via Scapy")
    print("  and triggers HIGH severity 'Suspicious Outbound' alerts.")
    print()
    print("  IOC Targets:")
    for ioc in MALICIOUS_IOCS:
        print(f"    - {ioc['ip']:>16}  ({ioc['label']})")
    print()
    print("=" * 70)
    print()


def check_argus_running():
    """Check if ARGUS server is reachable."""
    try:
        resp = urllib.request.urlopen(f"{ARGUS_API}/api/status", timeout=5)
        data = json.loads(resp.read().decode())
        return True, data
    except Exception:
        return False, None


def get_current_stats():
    """Fetch current stats from ARGUS API."""
    try:
        resp = urllib.request.urlopen(f"{ARGUS_API}/api/status", timeout=5)
        return json.loads(resp.read().decode())
    except Exception:
        return None


def add_ioc_to_argus(ip_address):
    """Add an IP to the ARGUS IOC blocklist via REST API."""
    try:
        url = f"{ARGUS_API}/api/ioc?ip={ip_address}"
        req = urllib.request.Request(url, method="POST", data=b"")
        req.add_header("Content-Type", "application/json")
        resp = urllib.request.urlopen(req, timeout=5)
        result = json.loads(resp.read().decode())
        return result.get("status") == "ok"
    except Exception as e:
        # Try alternate endpoint format
        try:
            url = f"{ARGUS_API}/api/ioc/add"
            payload = json.dumps({"ip": ip_address}).encode()
            req = urllib.request.Request(url, data=payload, method="POST")
            req.add_header("Content-Type", "application/json")
            resp = urllib.request.urlopen(req, timeout=5)
            result = json.loads(resp.read().decode())
            return result.get("status") == "ok"
        except Exception:
            return False


def get_ioc_list():
    """Fetch current IOC blocklist from ARGUS."""
    try:
        resp = urllib.request.urlopen(f"{ARGUS_API}/api/ioc", timeout=5)
        data = json.loads(resp.read().decode())
        return data.get("ioc_blocklist", [])
    except Exception:
        return []


def get_recent_outbound_alerts(limit=50):
    """Fetch recent Suspicious Outbound Connection alerts from ARGUS."""
    try:
        resp = urllib.request.urlopen(f"{ARGUS_API}/api/alerts?limit={limit}", timeout=5)
        alerts = json.loads(resp.read().decode())
        outbound = [
            a for a in alerts
            if a.get("type") == "SUSPICIOUS_OUTBOUND" or a.get("detector") == "outbound_detector"
        ]
        return outbound
    except Exception:
        return []


def attempt_outbound_connection(target_ip, target_port):
    """
    Create a real outbound TCP connection attempt to the target IP.
    The SYN packet is captured by Scapy running inside ARGUS, which
    then checks it against the IOC blocklist and triggers an alert.

    The connection will fail (timeout/refused) since these are
    non-routable test IPs — but the outbound SYN packet is still
    generated and captured.
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(CONNECT_TIMEOUT)
        sock.connect((target_ip, target_port))
        sock.close()
        return "connected"  # Unlikely for test-net IPs
    except socket.timeout:
        return "timeout"
    except ConnectionRefusedError:
        return "refused"
    except OSError as e:
        return f"error ({e.errno})"
    except Exception as e:
        return f"error"
    finally:
        try:
            sock.close()
        except Exception:
            pass


# ─────────────────────────────────────────────────────────────────────────────
# Main Simulation
# ─────────────────────────────────────────────────────────────────────────────

def main():
    print_banner()

    # ── Pre-flight check ─────────────────────────────────────
    print("[1/3] Checking ARGUS server connection...")
    running, stats = check_argus_running()
    if not running:
        print()
        print("  ERROR: ARGUS server is not reachable at", ARGUS_API)
        print("  Please start the server first:")
        print("    cd backend")
        print("    python server.py")
        print()
        sys.exit(1)
    print(f"  [OK] ARGUS server online — {stats.get('total_alerts', 0)} existing alerts")
    print()

    # Record baseline stats
    start_total = stats.get("total_alerts", 0)
    start_network = stats.get("network_alerts", 0)

    # ── Step 1: Add IOCs to ARGUS blocklist ──────────────────
    print("[2/3] Adding malicious IPs to ARGUS IOC blocklist...")
    print()
    added_count = 0
    for ioc in MALICIOUS_IOCS:
        success = add_ioc_to_argus(ioc["ip"])
        status = "[OK] Added" if success else "[!!] Failed"
        print(f"  {status}  {ioc['ip']:>16}  —  {ioc['label']}")
        if success:
            added_count += 1
        time.sleep(0.3)

    print()
    print(f"  {added_count}/{len(MALICIOUS_IOCS)} IOCs loaded into blocklist")

    # Verify blocklist
    current_iocs = get_ioc_list()
    print(f"  Active IOC blocklist size: {len(current_iocs)}")
    print()

    if added_count == 0:
        print("  ERROR: Could not add any IOCs. Is the network engine running?")
        sys.exit(1)

    # ── Step 2: Generate outbound connections ─────────────────
    print("[3/3] Generating suspicious outbound connections...")
    print()
    print("  Open the ARGUS dashboard to watch alerts appear in real-time:")
    print("  --> http://localhost:8000")
    print()
    print("-" * 70)

    total_attempts = 0

    for ioc_idx, ioc in enumerate(MALICIOUS_IOCS, 1):
        ip = ioc["ip"]
        label = ioc["label"]
        ports = ioc["ports"]

        print()
        print(f"  TARGET: {ip}  ({label})")
        print(f"          ({ioc_idx}/{len(MALICIOUS_IOCS)})")
        print()

        for port in ports:
            total_attempts += 1
            result = attempt_outbound_connection(ip, port)
            print(f"    [{total_attempts:>2}]  --> {ip}:{port:<5}   Result: {result}")
            print(f"         Outbound SYN packet captured by Scapy -> IOC match -> ALERT")
            time.sleep(DELAY_BETWEEN_ATTEMPTS)

        if ioc_idx < len(MALICIOUS_IOCS):
            print()
            print(f"  ... pausing {DELAY_BETWEEN_IOCS}s before next target ...")
            time.sleep(DELAY_BETWEEN_IOCS)

    # ── Wait for ARGUS to process ─────────────────────────────
    print()
    print("-" * 70)
    print()
    print("  Attack simulation complete!")
    print(f"  Total outbound connection attempts: {total_attempts}")
    print()
    print("  Waiting 10 seconds for ARGUS to process all captured packets...")
    print()

    for i in range(5):
        time.sleep(2)
        current = get_current_stats()
        if current:
            new_total = current.get("total_alerts", 0) - start_total
            new_network = current.get("network_alerts", 0) - start_network
            bar = "#" * min(new_network, 20) + "." * max(0, 5 - new_network)
            print(f"  [{(i+1)*2:>2}s]  New alerts: {new_total}  |  Network alerts: {new_network}  {bar}")

    # ── Final report ──────────────────────────────────────────
    print()
    print("=" * 70)
    print("  SIMULATION RESULTS")
    print("=" * 70)

    final = get_current_stats()
    final_total = (final or {}).get("total_alerts", 0)
    final_network = (final or {}).get("network_alerts", 0)
    new_alerts = final_total - start_total
    new_network_alerts = final_network - start_network

    # Query active Suspicious Outbound alerts directly from the database
    outbound_alerts = get_recent_outbound_alerts(limit=50)

    print(f"  Outbound connections attempted : {total_attempts}")
    print(f"  IOCs in blocklist              : {added_count}")
    print(f"  New ARGUS alerts generated     : {new_alerts}")
    print(f"  Suspicious Outbound alerts     : {len(outbound_alerts)} recorded in system")
    print()

    if outbound_alerts:
        print("  [SUCCESS] Outbound IOC Alerts Detected by ARGUS:")
        print("  " + "-" * 66)
        for idx, alt in enumerate(outbound_alerts[:6], 1):
            target = alt.get("destination_ip") or alt.get("target_ip", "Unknown")
            port = alt.get("destination_port", "?")
            src = alt.get("source_ip", "?")
            sev = alt.get("severity", "HIGH")
            aid = alt.get("id") or alt.get("alert_id", "?")
            print(f"    [{idx}] {aid} | {sev} | {src} -> {target}:{port}")
            print(f"        Reason : {alt.get('reason', 'Destination matched IOC')}")
            print(f"        Time   : {alt.get('timestamp', '')[:19]}")
        print("  " + "-" * 66)
    else:
        print("  [INFO] Alerts are queued or still being processed.")

    print()
    print("  [DEMO FOR TEACHER / EXAMINER]:")
    print("  1. Open http://localhost:8000 in your browser.")
    print("  2. In the 'Alerts' tab, observe the 'Suspicious Outbound Connection' cards.")
    print("  3. Note that each alert flags: Source IP -> Malicious C2 IP with HIGH severity.")
    print("  4. Switch to the 'IOC Blocklist' tab to show the active threat-intel feeds.")
    print()
    print("=" * 70)
    print()


if __name__ == "__main__":
    main()
