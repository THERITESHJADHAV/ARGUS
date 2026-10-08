from app.detection.argus_detection_service import (
    ArgusDetectionService
)


def main():

    print("=" * 70)
    print("ARGUS UNIFIED DETECTION SERVICE TEST")
    print("=" * 70)

    service = ArgusDetectionService(
        windows_interval=5
    )

    print()
    print("=" * 70)
    print("SERVICE INITIALIZED SUCCESSFULLY")
    print("=" * 70)

    print(
        "Current alerts:",
        len(service.get_alerts())
    )

    print(
        "Summary:",
        service.get_summary()
    )

    print()
    print("=" * 70)
    print("TEST COMPLETE")
    print("=" * 70)


if __name__ == "__main__":
    main()