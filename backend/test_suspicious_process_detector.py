from app.detection.suspicious_process_detector import (
    SuspiciousProcessDetector
)


def print_result(title, result):

    print()
    print("=" * 70)
    print(title)
    print("=" * 70)

    print("Alert:", result["alert"])
    print("Alert Type:", result["alert_type"])
    print("Severity:", result["severity"])
    print("Risk Score:", result["risk_score"])
    print("Process:", result["process_name"])
    print("Image:", result["image"])
    print("Parent:", result["parent_image"])
    print("User:", result["user"])
    print("Status:", result["status"])

    print("Reasons:")

    if result["reasons"]:
        for reason in result["reasons"]:
            print(" -", reason)
    else:
        print(" - No suspicious indicators")


def main():

    detector = SuspiciousProcessDetector()

    # ---------------------------------------------------------
    # TEST 1: Normal Chrome process
    # ---------------------------------------------------------

    normal_event = {
        "event_type": "PROCESS_CREATE",
        "event_id": 1,
        "timestamp": "2026-10-07T09:00:00Z",
        "process_id": "1234",
        "image": (
            r"C:\Program Files\Google\Chrome\Application\chrome.exe"
        ),
        "command_line": (
            r'"C:\Program Files\Google\Chrome\Application\chrome.exe"'
        ),
        "parent_image": (
            r"C:\Windows\explorer.exe"
        ),
        "parent_process_id": "1000",
        "user": "DESKTOP\\User",
        "integrity_level": "Medium",
        "sha256": "ABC123"
    }

    result = detector.process_event(
        normal_event
    )

    print_result(
        "TEST 1 - NORMAL CHROME",
        result
    )

    # ---------------------------------------------------------
    # TEST 2: Suspicious PowerShell
    # ---------------------------------------------------------

    suspicious_event = {
        "event_type": "PROCESS_CREATE",
        "event_id": 1,
        "timestamp": "2026-10-07T09:01:00Z",
        "process_id": "5678",
        "image": (
            r"C:\Users\User\AppData\Local\Temp\powershell.exe"
        ),
        "command_line": (
            "powershell.exe -ExecutionPolicy Bypass "
            "-EncodedCommand ABCDEFG"
        ),
        "parent_image": (
            r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE"
        ),
        "parent_process_id": "2000",
        "user": "DESKTOP\\User",
        "integrity_level": "Medium",
        "sha256": "DEF456"
    }

    result = detector.process_event(
        suspicious_event
    )

    print_result(
        "TEST 2 - SUSPICIOUS POWERSHELL",
        result
    )

    # ---------------------------------------------------------
    # TEST 3: Suspicious process from Downloads
    # ---------------------------------------------------------

    suspicious_download = {
        "event_type": "PROCESS_CREATE",
        "event_id": 1,
        "timestamp": "2026-10-07T09:02:00Z",
        "process_id": "9999",
        "image": (
            r"C:\Users\User\Downloads\test.exe"
        ),
        "command_line": (
            r"C:\Users\User\Downloads\test.exe"
        ),
        "parent_image": (
            r"C:\Windows\explorer.exe"
        ),
        "parent_process_id": "3000",
        "user": "DESKTOP\\User",
        "integrity_level": "Medium",
        "sha256": "XYZ789"
    }

    result = detector.process_event(
        suspicious_download
    )

    print_result(
        "TEST 3 - PROCESS FROM DOWNLOADS",
        result
    )

    print()
    print("=" * 70)
    print("SUSPICIOUS PROCESS DETECTOR TEST COMPLETE")
    print("=" * 70)


if __name__ == "__main__":
    main()