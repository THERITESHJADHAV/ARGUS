from app.detection.network_detection_engine import (
    NetworkDetectionEngine
)


from pathlib import Path

MODEL_PATH = str(
    Path(__file__).resolve().parent / "app" / "models" / "argus_network_best_model.joblib"
)

if __name__ == "__main__":
    print("=" * 70)
    print("ARGUS NETWORK ENGINE TEST")
    print("=" * 70)

    engine = NetworkDetectionEngine(
        model_path=MODEL_PATH
    )

    engine.add_ioc(
        "192.168.0.250"
    )

    engine.start()