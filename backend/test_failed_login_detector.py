from app.detection.failed_login_detector import (
    FailedLoginDetector
)


detector = FailedLoginDetector(
    failure_threshold=5,
    time_window_seconds=60
)


print("=" * 70)
print("ARGUS FAILED LOGIN DETECTOR TEST")
print("=" * 70)


for i in range(1, 8):

    event = {

        "event_type":
            "FAILED_LOGIN",

        "event_id":
            4625,

        "username":
            "administrator",

        "source_ip":
            "192.168.0.50",

        "timestamp":
            "test"
    }


    result = detector.process_event(
        event
    )


    print()
    print(
        f"Attempt {i}"
    )

    print(
        result
    )


print()
print("=" * 70)