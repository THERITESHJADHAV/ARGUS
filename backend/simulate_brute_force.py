"""
ARGUS — Brute Force / Failed Login Attack Simulator
====================================================
This script generates REAL Windows Security Event ID 4625 (Failed Login)
entries by attempting to authenticate against the local machine with
intentionally wrong passwords.

ARGUS monitors these events in real-time and triggers a
"Brute Force / Failed Login" alert when 5+ failures are detected
within a 60-second sliding window.

HOW IT WORKS:
  1. Uses Windows `net use` to attempt SMB connections to \\localhost
     with a fake password — each attempt creates an Event ID 4625.
  2. ARGUS polls the Windows Security Event Log every 5 seconds.
  3. Once 5+ failed logins for the same user are detected in 60s,
     a HIGH severity Brute Force alert appears on the SOC dashboard.

REQUIREMENTS:
  - Run PowerShell / Command Prompt as ADMINISTRATOR
  - ARGUS server must be running (python backend/server.py)
  - Open the dashboard at http://localhost:8000 to watch alerts appear

USAGE:
  cd backend
  python simulate_brute_force.py
"""

import subprocess
import time
import sys
import os
import urllib.request
import json

# Fix Windows terminal encoding — ensure emoji/unicode prints correctly
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
    os.system("")  # Enable ANSI/VT100 escape sequences on Windows


# ─────────────────────────────────────────────────────────────────────────────
# Configuration
# ─────────────────────────────────────────────────────────────────────────────

# Target accounts to brute-force (these users don't need to exist —
# failed login attempts still generate Event ID 4625 regardless)
TARGET_ACCOUNTS = [
    "Administrator",
    "admin",
    "TestUser",
]

# Number of failed login attempts per account
ATTEMPTS_PER_ACCOUNT = 8

# Delay between each login attempt (seconds)
DELAY_BETWEEN_ATTEMPTS = 0.8

# Delay between attacking different accounts (seconds)
DELAY_BETWEEN_ACCOUNTS = 2.0

# ARGUS API endpoint to check alert status
ARGUS_API = "http://127.0.0.1:8000"


# ─────────────────────────────────────────────────────────────────────────────
# Helper Functions
# ─────────────────────────────────────────────────────────────────────────────

def print_banner():
    """Print a professional header banner."""
    print()
    print("=" * 70)
    print("  🛡️  ARGUS — BRUTE FORCE ATTACK SIMULATOR")
    print("=" * 70)
    print()
    print("  This script simulates a brute-force login attack by generating")
    print("  real Windows Security Event ID 4625 (Failed Login) entries.")
    print()
    print("  ARGUS will detect these and trigger HIGH severity alerts on")
    print("  the SOC dashboard at http://localhost:8000")
    print()
    print("  Target accounts :", ", ".join(TARGET_ACCOUNTS))
    print("  Attempts/account:", ATTEMPTS_PER_ACCOUNT)
    print("  Detection threshold: 5 failures in 60 seconds")
    print()
    print("=" * 70)
    print()


def check_admin():
    """Check if running with Administrator privileges."""
    try:
        # Try to read the Security event log — requires admin
        result = subprocess.run(
            [
                "powershell", "-NoProfile", "-Command",
                "Get-WinEvent -FilterHashtable @{LogName='Security'} "
                "-MaxEvents 1 -ErrorAction Stop | Out-Null; "
                "Write-Output 'ADMIN_OK'"
            ],
            capture_output=True, text=True, timeout=10
        )
        if "ADMIN_OK" in result.stdout:
            return True
    except Exception:
        pass
    return False


def check_argus_running():
    """Check if ARGUS server is reachable."""
    try:
        resp = urllib.request.urlopen(f"{ARGUS_API}/api/status", timeout=5)
        data = json.loads(resp.read().decode())
        return True, data
    except Exception:
        return False, None


def get_current_alert_count():
    """Fetch current total alert count from ARGUS API."""
    try:
        resp = urllib.request.urlopen(f"{ARGUS_API}/api/status", timeout=5)
        data = json.loads(resp.read().decode())
        return data.get("total_alerts", 0), data.get("windows_alerts", 0)
    except Exception:
        return None, None


def attempt_failed_login(username, attempt_num, total):
    """
    Generate a single failed login attempt using `net use`.
    This connects to the local IPC$ share with a wrong password,
    creating a Windows Security Event ID 4625 entry.
    """
    # Clean up any existing connection first
    subprocess.run(
        ["net", "use", "\\\\127.0.0.1\\IPC$", "/delete", "/y"],
        capture_output=True, text=True,
        creationflags=subprocess.CREATE_NO_WINDOW
    )

    # Attempt login with intentionally wrong password
    fake_password = f"WrongPass_{attempt_num}_{int(time.time())}"
    result = subprocess.run(
        [
            "net", "use", "\\\\127.0.0.1\\IPC$",
            f"/user:{username}",
            fake_password
        ],
        capture_output=True, text=True,
        creationflags=subprocess.CREATE_NO_WINDOW
    )

    # Expected: this FAILS with "logon failure" — that's the point!
    failed = result.returncode != 0
    status = "✗ FAILED (Event 4625 generated)" if failed else "✓ Success (unexpected)"

    print(f"  [{attempt_num:>2}/{total}]  User: {username:<16}  {status}")

    return failed


def cleanup_connections():
    """Remove any leftover net use connections."""
    subprocess.run(
        ["net", "use", "\\\\127.0.0.1\\IPC$", "/delete", "/y"],
        capture_output=True, text=True,
        creationflags=subprocess.CREATE_NO_WINDOW
    )


# ─────────────────────────────────────────────────────────────────────────────
# Main Simulation
# ─────────────────────────────────────────────────────────────────────────────

def main():
    print_banner()

    # ── Pre-flight checks ────────────────────────────────────
    print("[1/3] Checking Administrator privileges...")
    if not check_admin():
        print()
        print("  ⚠️  ERROR: This script requires Administrator privileges!")
        print("  Please right-click PowerShell → 'Run as Administrator'")
        print("  and try again.")
        print()
        sys.exit(1)
    print("  ✓ Running as Administrator")
    print()

    print("[2/3] Checking ARGUS server connection...")
    running, stats = check_argus_running()
    if not running:
        print()
        print("  ⚠️  ERROR: ARGUS server is not reachable at", ARGUS_API)
        print("  Please start the server first:")
        print("    cd backend")
        print("    python server.py")
        print()
        sys.exit(1)
    print(f"  ✓ ARGUS server online — {stats.get('total_alerts', 0)} existing alerts")
    print()

    # Record starting alert count
    start_total, start_windows = get_current_alert_count()

    print("[3/3] Launching brute force simulation...")
    print()
    print("  Open the ARGUS dashboard to watch alerts appear in real-time:")
    print("  👉 http://localhost:8000")
    print()
    print("-" * 70)

    total_attempts = 0
    total_failures = 0

    for account_idx, username in enumerate(TARGET_ACCOUNTS, 1):
        print()
        print(f"  🎯 ATTACKING ACCOUNT: {username}")
        print(f"     ({account_idx}/{len(TARGET_ACCOUNTS)})")
        print()

        for attempt in range(1, ATTEMPTS_PER_ACCOUNT + 1):
            failed = attempt_failed_login(
                username, attempt, ATTEMPTS_PER_ACCOUNT
            )
            total_attempts += 1
            if failed:
                total_failures += 1
            time.sleep(DELAY_BETWEEN_ATTEMPTS)

        # Brief pause between accounts
        if account_idx < len(TARGET_ACCOUNTS):
            print()
            print(f"  ⏳ Waiting {DELAY_BETWEEN_ACCOUNTS}s before next account...")
            time.sleep(DELAY_BETWEEN_ACCOUNTS)

    cleanup_connections()

    # ── Wait for ARGUS to detect and process ──────────────────
    print()
    print("-" * 70)
    print()
    print("  ✅ Attack simulation complete!")
    print(f"  Total login attempts : {total_attempts}")
    print(f"  Failed logins (4625) : {total_failures}")
    print()
    print("  ⏳ Waiting 10 seconds for ARGUS to detect and process alerts...")
    print()

    # Poll ARGUS every 2 seconds to show detection progress
    for i in range(5):
        time.sleep(2)
        current_total, current_windows = get_current_alert_count()
        if current_total is not None:
            new_total = current_total - (start_total or 0)
            new_windows = current_windows - (start_windows or 0)
            bar = "█" * new_windows + "░" * max(0, 3 - new_windows)
            print(f"  [{(i+1)*2:>2}s]  New alerts: {new_total}  |  Windows/Brute Force: {new_windows}  {bar}")

    # ── Final report ──────────────────────────────────────────
    print()
    print("=" * 70)
    print("  📊 SIMULATION RESULTS")
    print("=" * 70)

    final_total, final_windows = get_current_alert_count()
    new_alerts = (final_total or 0) - (start_total or 0)
    new_windows_alerts = (final_windows or 0) - (start_windows or 0)

    print(f"  Login attempts generated  : {total_attempts}")
    print(f"  Event ID 4625 entries     : {total_failures}")
    print(f"  New ARGUS alerts          : {new_alerts}")
    print(f"  Brute Force alerts        : {new_windows_alerts}")
    print()

    if new_windows_alerts > 0:
        print("  🎉 SUCCESS! Brute Force alerts detected and visible on dashboard!")
    else:
        print("  ℹ️  Alerts may still be processing. Check the dashboard:")

    print()
    print("  👉 Open: http://localhost:8000")
    print("  📌 Go to: Alerts tab → look for 'Brute Force / Failed Login'")
    print("  📌 Also check: Windows Events tab for failed login audit trail")
    print()
    print("=" * 70)
    print()


if __name__ == "__main__":
    main()
