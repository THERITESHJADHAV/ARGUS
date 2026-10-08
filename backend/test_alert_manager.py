from app.detection.alert_manager import AlertManager


def main():

    print("=" * 70)
    print("ARGUS ALERT MANAGER TEST")
    print("=" * 70)

    manager = AlertManager()

    # =========================================================
    # TEST ALERT 1 - POWERSHELL
    # =========================================================

    powershell_result = {

        "alert": True,

        "alert_type":
            "Suspicious PowerShell",

        "severity":
            "HIGH",

        "risk_score":
            90,

        "process_name":
            "powershell.exe",

        "image":
            r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",

        "process_id":
            "1234",

        "parent_process_id":
            "567",

        "parent_image":
            r"C:\Windows\explorer.exe",

        "command_line":
            "powershell.exe -EncodedCommand ABCDEF",

        "user":
            "DESKTOP\\User",

        "integrity_level":
            "Medium",

        "sha256":
            "TESTHASH123",

        "categories": [
            "encoded_command"
        ],

        "indicators": [
            "-EncodedCommand"
        ],

        "reasons": [
            "Encoded PowerShell command detected"
        ],

        "status":
            "NEW"
    }

    alert1 = manager.create_alert(
        powershell_result,
        "powershell_detector"
    )

    print()
    print("ALERT 1")
    print("-" * 70)

    print(
        "Alert ID:",
        alert1["alert_id"]
    )

    print(
        "Type:",
        alert1["alert_type"]
    )

    print(
        "Detector:",
        alert1["detector"]
    )

    print(
        "Severity:",
        alert1["severity"]
    )

    print(
        "Risk Score:",
        alert1["risk_score"]
    )

    print(
        "Process:",
        alert1["process_name"]
    )

    print(
        "Status:",
        alert1["status"]
    )

    # =========================================================
    # TEST ALERT 2 - PORT SCANNING
    # =========================================================

    port_scan_result = {

        "alert": True,

        "alert_type":
            "Port Scanning",

        "severity":
            "HIGH",

        "risk_score":
            85,

        "source_ip":
            "192.168.1.20",

        "destination_ip":
            "192.168.1.10",

        "destination_port":
            445,

        "reasons": [
            "Source contacted more than 20 unique ports"
        ],

        "status":
            "NEW"
    }

    alert2 = manager.create_alert(
        port_scan_result,
        "port_scan_detector"
    )

    print()
    print("ALERT 2")
    print("-" * 70)

    print(
        "Alert ID:",
        alert2["alert_id"]
    )

    print(
        "Type:",
        alert2["alert_type"]
    )

    print(
        "Detector:",
        alert2["detector"]
    )

    print(
        "Severity:",
        alert2["severity"]
    )

    print(
        "Risk Score:",
        alert2["risk_score"]
    )

    print(
        "Source IP:",
        alert2["source_ip"]
    )

    print(
        "Status:",
        alert2["status"]
    )

    # =========================================================
    # TEST ALERT 3 - BRUTE FORCE
    # =========================================================

    brute_force_result = {

        "alert": True,

        "alert_type":
            "Brute Force / Failed Login",

        "severity":
            "HIGH",

        "risk_score":
            80,

        "source_ip":
            "192.168.1.50",

        "user":
            "Administrator",

        "reasons": [
            "5 failed login attempts within 60 seconds"
        ],

        "status":
            "NEW"
    }

    alert3 = manager.create_alert(
        brute_force_result,
        "failed_login_detector"
    )

    print()
    print("ALERT 3")
    print("-" * 70)

    print(
        "Alert ID:",
        alert3["alert_id"]
    )

    print(
        "Type:",
        alert3["alert_type"]
    )

    print(
        "Detector:",
        alert3["detector"]
    )

    print(
        "Severity:",
        alert3["severity"]
    )

    print(
        "Risk Score:",
        alert3["risk_score"]
    )

    print(
        "Source IP:",
        alert3["source_ip"]
    )

    print(
        "User:",
        alert3["user"]
    )

    # =========================================================
    # SUMMARY
    # =========================================================

    print()
    print("=" * 70)
    print("ALERT SUMMARY")
    print("=" * 70)

    summary = manager.get_summary()

    print(
        "Total Alerts:",
        summary["total_alerts"]
    )

    print(
        "Critical:",
        summary["critical"]
    )

    print(
        "High:",
        summary["high"]
    )

    print(
        "Medium:",
        summary["medium"]
    )

    print(
        "Low:",
        summary["low"]
    )

    print(
        "Info:",
        summary["info"]
    )

    print()
    print("=" * 70)
    print("ALERT MANAGER TEST COMPLETE")
    print("=" * 70)


if __name__ == "__main__":
    main()