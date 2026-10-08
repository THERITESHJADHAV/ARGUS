from app.detection.windows_detection_engine import (
    WindowsDetectionEngine
)


print("=" * 70)
print("ARGUS WINDOWS BRUTE FORCE PIPELINE TEST")
print("=" * 70)


engine = WindowsDetectionEngine(
    failure_threshold=5,
    time_window_seconds=60
)


# -------------------------------------------------------
# Controlled sample Windows 4625 event
# -------------------------------------------------------

sample_event = {

    "TimeCreated":
        "2026-10-07T09:30:00",

    "Id":
        4625,

    "Message":
        """
        An account failed to log on.

        Account Name: administrator
        Logon Type: 3
        Failure Reason: Unknown user name or bad password
        Source Network Address: 192.168.0.50
        """
}


# -------------------------------------------------------
# Send five failed login events
# -------------------------------------------------------

for i in range(1, 6):

    print()
    print(
        f"========== FAILED LOGIN {i} =========="
    )

    engine.process_event(
        sample_event
    )


print()
print("=" * 70)
print("BRUTE FORCE PIPELINE TEST COMPLETE")
print("=" * 70)