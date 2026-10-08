from app.detection.powershell_detector import (
    PowerShellDetector
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
    print("Process:", result.get("process_name"))
    print("Command:", result.get("command_line"))
    print("Parent:", result.get("parent_image"))
    print("Status:", result["status"])

    print("Categories:")

    for category in result.get(
        "categories",
        []
    ):
        print(" -", category)

    print("Reasons:")

    for reason in result.get(
        "reasons",
        []
    ):
        print(" -", reason)


def main():

    detector = PowerShellDetector()

    # ---------------------------------------------------------
    # TEST 1 - Normal PowerShell
    # ---------------------------------------------------------

    normal_event = {

        "event_type": "PROCESS_CREATE",

        "event_id": 1,

        "timestamp":
            "2026-10-07T09:00:00Z",

        "process_id":
            "1001",

        "image":
            r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",

        "command_line":
            "powershell.exe Get-Date",

        "parent_image":
            r"C:\Windows\explorer.exe",

        "parent_process_id":
            "500",

        "user":
            "DESKTOP\\User",

        "integrity_level":
            "Medium",

        "sha256":
            "TESTHASH001"
    }

    result = detector.process_event(
        normal_event
    )

    print_result(
        "TEST 1 - NORMAL POWERSHELL",
        result
    )

    # ---------------------------------------------------------
    # TEST 2 - Encoded PowerShell
    # ---------------------------------------------------------

    encoded_event = {

        "event_type": "PROCESS_CREATE",

        "event_id": 1,

        "timestamp":
            "2026-10-07T09:01:00Z",

        "process_id":
            "1002",

        "image":
            r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",

        "command_line":
            "powershell.exe -EncodedCommand ABCDEFG",

        "parent_image":
            r"C:\Windows\explorer.exe",

        "parent_process_id":
            "500",

        "user":
            "DESKTOP\\User",

        "integrity_level":
            "Medium",

        "sha256":
            "TESTHASH002"
    }

    result = detector.process_event(
        encoded_event
    )

    print_result(
        "TEST 2 - ENCODED POWERSHELL",
        result
    )

    # ---------------------------------------------------------
    # TEST 3 - Multiple suspicious indicators
    # ---------------------------------------------------------

    malicious_pattern_event = {

        "event_type": "PROCESS_CREATE",

        "event_id": 1,

        "timestamp":
            "2026-10-07T09:02:00Z",

        "process_id":
            "1003",

        "image":
            r"C:\Users\User\AppData\Local\Temp\powershell.exe",

        "command_line":
            "powershell.exe "
            "-ExecutionPolicy Bypass "
            "-WindowStyle Hidden "
            "-EncodedCommand ABCDEFG",

        "parent_image":
            r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE",

        "parent_process_id":
            "600",

        "user":
            "DESKTOP\\User",

        "integrity_level":
            "Medium",

        "sha256":
            "TESTHASH003"
    }

    result = detector.process_event(
        malicious_pattern_event
    )

    print_result(
        "TEST 3 - MULTIPLE SUSPICIOUS INDICATORS",
        result
    )

    # ---------------------------------------------------------
    # TEST 4 - Non-PowerShell process
    # ---------------------------------------------------------

    chrome_event = {

        "event_type": "PROCESS_CREATE",

        "event_id": 1,

        "timestamp":
            "2026-10-07T09:03:00Z",

        "process_id":
            "1004",

        "image":
            r"C:\Program Files\Google\Chrome\Application\chrome.exe",

        "command_line":
            r'"C:\Program Files\Google\Chrome\Application\chrome.exe"',

        "parent_image":
            r"C:\Windows\explorer.exe",

        "parent_process_id":
            "500",

        "user":
            "DESKTOP\\User",

        "integrity_level":
            "Medium",

        "sha256":
            "TESTHASH004"
    }

    result = detector.process_event(
        chrome_event
    )

    print_result(
        "TEST 4 - NON-POWERSHELL PROCESS",
        result
    )

    print()
    print("=" * 70)
    print("POWERSHELL DETECTOR TEST COMPLETE")
    print("=" * 70)


if __name__ == "__main__":
    main()