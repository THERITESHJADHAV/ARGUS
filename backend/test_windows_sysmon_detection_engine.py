from app.detection.windows_sysmon_detection_engine import (
    WindowsSysmonDetectionEngine
)


def main():

    print("=" * 70)
    print("ARGUS WINDOWS + SYSMON ENGINE TEST")
    print("=" * 70)

    engine = WindowsSysmonDetectionEngine()

    alerts = engine.scan_once()

    print()
    print("=" * 70)
    print("SCAN COMPLETE")
    print("=" * 70)

    print(
        "Alerts returned:",
        alerts
    )

    engine.print_summary()


if __name__ == "__main__":
    main()