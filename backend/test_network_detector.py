from pathlib import Path
import sys
import pandas as pd

sys.path.append(str(Path(__file__).parent))

from app.detection.network_detector import NetworkDetector


MODEL_PATH = (
    Path(__file__).parent
    / "app"
    / "models"
    / "argus_network_best_model.joblib"
)


TEST_DATA = (
    Path(__file__).parent
    / ".."
    / "data"
    / "argus_network_final_test.csv"
)


print("=" * 60)
print("ARGUS NETWORK DETECTOR TEST")
print("=" * 60)


# --------------------------------------------------
# 1. Load model
# --------------------------------------------------

detector = NetworkDetector(
    str(MODEL_PATH)
)


# --------------------------------------------------
# 2. Load test data
# --------------------------------------------------

print("\nLoading test data...")

df = pd.read_csv(TEST_DATA)

print("Test data shape:", df.shape)

print("\nColumns:")
print(df.columns.tolist())


# --------------------------------------------------
# 3. Select a few rows
# --------------------------------------------------

sample = df.head(10).copy()

print("\nTesting first 10 records...")


# --------------------------------------------------
# 4. Run detection
# --------------------------------------------------

results = detector.predict(sample)


# --------------------------------------------------
# 5. Display results
# --------------------------------------------------

print("\nRESULTS")
print("=" * 60)

for i, result in enumerate(results):

    print(f"\nRecord {i + 1}")

    for key, value in result.items():

        print(f"{key}: {value}")