from app.detection.live_network_detector import (
    LiveNetworkDetector
)


MODEL_PATH = (
    "app/models/argus_network_best_model.joblib"
)


detector = LiveNetworkDetector(
    model_path=MODEL_PATH
)


detector.start()