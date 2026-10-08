from pathlib import Path
import joblib
import pandas as pd

from .network_features import NETWORK_FEATURES


class NetworkDetector:

    def __init__(self, model_path: str):

        self.model_path = Path(model_path)

        if not self.model_path.exists():
            raise FileNotFoundError(
                f"Network model not found: {self.model_path}"
            )

        print(f"[ARGUS] Loading network model:")
        print(f"[ARGUS] {self.model_path}")

        self.model = joblib.load(self.model_path)

        print("[ARGUS] Network model loaded successfully.")

    def validate_features(self, data: pd.DataFrame):

        missing = [
            feature
            for feature in NETWORK_FEATURES
            if feature not in data.columns
        ]

        if missing:
            raise ValueError(
                f"Missing required network features: {missing}"
            )

    def predict(self, data: pd.DataFrame):

        self.validate_features(data)

        X = data[NETWORK_FEATURES].copy()

        prediction = self.model.predict(X)

        probability = self.model.predict_proba(X)

        attack_probability = probability[:, 1]

        results = []

        for i in range(len(X)):

            pred = int(prediction[i])
            attack_prob = float(attack_probability[i])

            if pred == 1:

                result = {
                    "detector": "network_ml",
                    "prediction": "ATTACK",
                    "attack_probability": round(
                        attack_prob, 6
                    ),
                    "confidence": round(
                        attack_prob, 6
                    )
                }

            else:

                result = {
                    "detector": "network_ml",
                    "prediction": "BENIGN",
                    "attack_probability": round(
                        attack_prob, 6
                    ),
                    "confidence": round(
                        1 - attack_prob, 6
                    )
                }

            results.append(result)

        return results