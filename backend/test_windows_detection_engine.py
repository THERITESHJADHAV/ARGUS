from app.detection.windows_detection_engine import (
    WindowsDetectionEngine
)


print("=" * 70)
print("ARGUS WINDOWS DETECTION ENGINE TEST")
print("=" * 70)


engine = WindowsDetectionEngine(
    failure_threshold=5,
    time_window_seconds=60
)


# -------------------------------------------------------
# Test real Windows Security log
# -------------------------------------------------------

engine.scan_once()


print()
print("=" * 70)
print("REAL WINDOWS EVENT SCAN COMPLETE")
print("=" * 70)
