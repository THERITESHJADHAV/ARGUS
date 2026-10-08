from app.detection.flow_feature_extractor import (
    FlowFeatureExtractor
)


extractor = FlowFeatureExtractor()


events = [

    {
        "timestamp":
            "2026-10-06T17:30:00.000000+00:00",

        "source_ip":
            "192.168.0.106",

        "destination_ip":
            "142.250.146.95",

        "source_port":
            56089,

        "destination_port":
            443,

        "protocol":
            "UDP",

        "packet_size":
            77
    },

    {
        "timestamp":
            "2026-10-06T17:30:00.100000+00:00",

        "source_ip":
            "192.168.0.106",

        "destination_ip":
            "142.250.146.95",

        "source_port":
            56089,

        "destination_port":
            443,

        "protocol":
            "UDP",

        "packet_size":
            120
    },

    {
        "timestamp":
            "2026-10-06T17:30:00.200000+00:00",

        "source_ip":
            "142.250.146.95",

        "destination_ip":
            "192.168.0.106",

        "source_port":
            443,

        "destination_port":
            56089,

        "protocol":
            "UDP",

        "packet_size":
            200
    }
]


print("=" * 60)

print("ARGUS FLOW FEATURE TEST")

print("=" * 60)


for event in events:

    result = extractor.add_packet(event)

    if result is not None:

        print("\nFLOW FEATURES")

        print("-" * 60)

        for name, value in result.items():

            print(
                f"{name}: {value}"
            )