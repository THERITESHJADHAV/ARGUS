from collections import defaultdict
from datetime import datetime


class FlowAdapter:

    def __init__(self):

        self.flows = defaultdict(list)

        print("[ARGUS] Flow adapter initialized.")

    def get_flow_key(self, event):

        return (
            event["source_ip"],
            event["destination_ip"],
            event["source_port"],
            event["destination_port"],
            event["protocol"]
        )

    def add_event(self, event):

        key = self.get_flow_key(event)

        self.flows[key].append(event)

        return self.build_flow(key)

    def build_flow(self, key):

        events = self.flows[key]

        if not events:
            return None

        packet_sizes = [
            event["packet_size"]
            for event in events
        ]

        timestamps = []

        for event in events:

            timestamp = datetime.fromisoformat(
                event["timestamp"]
            )

            timestamps.append(timestamp)

        timestamps.sort()

        flow_duration = (
            timestamps[-1] - timestamps[0]
        ).total_seconds()

        if flow_duration < 0:
            flow_duration = 0

        return {
            "source_ip": key[0],

            "destination_ip": key[1],

            "source_port": key[2],

            "destination_port": key[3],

            "protocol": key[4],

            "packet_count": len(events),

            "total_bytes": sum(packet_sizes),

            "flow_duration": flow_duration,

            "first_seen": timestamps[0].isoformat(),

            "last_seen": timestamps[-1].isoformat()
        }