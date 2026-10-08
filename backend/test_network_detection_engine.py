from app.detection.network_detection_engine import (
    NetworkDetectionEngine
)


MODEL_PATH = (
    "app/models/argus_network_best_model.joblib"
)


print("=" * 70)
print("ARGUS NETWORK ENGINE TEST")
print("=" * 70)


engine = NetworkDetectionEngine(
    model_path=MODEL_PATH
)


# -------------------------------------------------------
# Controlled IOC for testing
# -------------------------------------------------------
#
# This is a private LAN address used only as a test IOC.
# It will not mean that the IP is actually malicious.
#

engine.add_ioc(
    "192.168.0.250"
)


# -------------------------------------------------------
# Start monitoring
# -------------------------------------------------------

engine.start()