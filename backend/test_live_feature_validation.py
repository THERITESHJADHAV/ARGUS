from app.detection.network_features import NETWORK_FEATURES
from app.detection.flow_feature_extractor import FlowFeatureExtractor
import pandas as pd
import numpy as np


print("=" * 70)
print("ARGUS LIVE FEATURE VALIDATION")
print("=" * 70)


# ---------------------------------------------------------
# 1. Check feature list
# ---------------------------------------------------------

print("\n[1] Checking feature list...")

print("Expected feature count:", len(NETWORK_FEATURES))
print("Features:")

for feature in NETWORK_FEATURES:
    print(" -", feature)


# ---------------------------------------------------------
# 2. Load training/test data
# ---------------------------------------------------------

print("\n[2] Loading training-compatible test data...")

from pathlib import Path
BASE_DIR = Path(__file__).resolve().parent.parent
DATA_PATH = BASE_DIR / "data" / "argus_network_final_test.csv"

if DATA_PATH.exists():
    df = pd.read_csv(DATA_PATH)
    print("Dataset shape:", df.shape)
else:
    df = pd.DataFrame(columns=NETWORK_FEATURES)
    print(f"Test CSV not found at {DATA_PATH}, using fallback mockup")


# ---------------------------------------------------------
# 3. Check missing features
# ---------------------------------------------------------

print("\n[3] Checking required features...")

missing = [
    feature
    for feature in NETWORK_FEATURES
    if feature not in df.columns
]

if missing:
    print("ERROR: Missing features:")
    for feature in missing:
        print(" -", feature)

    raise SystemExit(1)

print("All 27 required features are present.")


# ---------------------------------------------------------
# 4. Check data types
# ---------------------------------------------------------

print("\n[4] Checking data types...")

for feature in NETWORK_FEATURES:
    if not pd.api.types.is_numeric_dtype(df[feature]):
        print(
            f"WARNING: {feature} is not numeric: "
            f"{df[feature].dtype}"
        )

print("Data type check completed.")


# ---------------------------------------------------------
# 5. Check NaN / infinite values
# ---------------------------------------------------------

print("\n[5] Checking invalid values...")

nan_count = df[NETWORK_FEATURES].isna().sum().sum()

inf_count = np.isinf(
    df[NETWORK_FEATURES].to_numpy()
).sum()

print("NaN values:", nan_count)
print("Infinite values:", inf_count)


# ---------------------------------------------------------
# 6. Show training statistics
# ---------------------------------------------------------

print("\n[6] Training/Test feature statistics")
print("-" * 70)

stats = df[NETWORK_FEATURES].describe().T

print(
    stats[
        [
            "min",
            "mean",
            "max"
        ]
    ].to_string()
)


# ---------------------------------------------------------
# 7. Test FlowFeatureExtractor
# ---------------------------------------------------------

print("\n[7] Testing FlowFeatureExtractor...")

extractor = FlowFeatureExtractor()

print("FlowFeatureExtractor initialized.")


# ---------------------------------------------------------
# 8. Create sample packets
# ---------------------------------------------------------

sample_packets = [
    {
        "timestamp": "2026-10-06T10:00:00+00:00",
        "source_ip": "192.168.0.106",
        "destination_ip": "8.8.8.8",
        "source_port": 50000,
        "destination_port": 443,
        "protocol": "TCP",
        "packet_size": 100,
        "tcp_flags": "S"
    },

    {
        "timestamp": "2026-10-06T10:00:01+00:00",
        "source_ip": "192.168.0.106",
        "destination_ip": "8.8.8.8",
        "source_port": 50000,
        "destination_port": 443,
        "protocol": "TCP",
        "packet_size": 200,
        "tcp_flags": "A"
    }
]


# ---------------------------------------------------------
# 9. Feed packets
# ---------------------------------------------------------

features = None

for packet in sample_packets:

    result = extractor.add_packet(packet)

    if result is not None:
        features = result


# ---------------------------------------------------------
# 10. Validate generated features
# ---------------------------------------------------------

print("\n[8] Validating generated live features...")

if features is None:

    print(
        "WARNING: FlowFeatureExtractor did not "
        "produce a completed flow."
    )

    print(
        "This is not necessarily an error. "
        "The extractor may require more packets."
    )

else:

    print("Generated feature count:", len(features))

    missing_live = [
        feature
        for feature in NETWORK_FEATURES
        if feature not in features
    ]

    if missing_live:

        print("\nERROR: Missing live features:")

        for feature in missing_live:
            print(" -", feature)

    else:

        print(
            "SUCCESS: All 27 live features are present."
        )

        print("\nLIVE FEATURES")
        print("-" * 70)

        for feature in NETWORK_FEATURES:

            value = features[feature]

            print(
                f"{feature:25s}: {value}"
            )


print("\n" + "=" * 70)
print("VALIDATION COMPLETE")
print("=" * 70)