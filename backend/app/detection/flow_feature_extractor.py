from collections import defaultdict
from datetime import datetime


class FlowFeatureExtractor:

    def __init__(self):

        self.flows = defaultdict(list)

        print("[ARGUS] Flow feature extractor initialized.")

    # ---------------------------------------------------------
    # FLOW KEY
    # ---------------------------------------------------------

    def get_flow_key(self, event):

        src_ip = event["source_ip"]
        dst_ip = event["destination_ip"]

        src_port = event["source_port"]
        dst_port = event["destination_port"]

        protocol = event["protocol"]

        # Bidirectional flow key.
        # This means A -> B and B -> A belong to
        # the same flow.

        endpoint1 = (
            src_ip,
            src_port
        )

        endpoint2 = (
            dst_ip,
            dst_port
        )

        if endpoint1 <= endpoint2:

            return (
                src_ip,
                dst_ip,
                src_port,
                dst_port,
                protocol
            )

        return (
            dst_ip,
            src_ip,
            dst_port,
            src_port,
            protocol
        )

    # ---------------------------------------------------------
    # ADD PACKET
    # ---------------------------------------------------------

    def add_packet(self, event):

        key = self.get_flow_key(event)

        self.flows[key].append(event)

        return self.extract_features(key)

    # ---------------------------------------------------------
    # STATISTICS
    # ---------------------------------------------------------

    @staticmethod
    def maximum(values):

        return (
            float(max(values))
            if values else 0.0
        )

    @staticmethod
    def minimum(values):

        return (
            float(min(values))
            if values else 0.0
        )

    @staticmethod
    def mean(values):

        if not values:
            return 0.0

        return float(
            sum(values) / len(values)
        )

    @staticmethod
    def standard_deviation(values):

        if len(values) <= 1:

            return 0.0

        avg = sum(values) / len(values)

        variance = sum(
            (x - avg) ** 2
            for x in values
        ) / len(values)

        return float(
            variance ** 0.5
        )

    # ---------------------------------------------------------
    # TIME DIFFERENCES
    # ---------------------------------------------------------

    @staticmethod
    def calculate_iats(events):

        if len(events) < 2:

            return []

        timestamps = sorted(
            datetime.fromisoformat(
                event["timestamp"]
            )
            for event in events
        )

        result = []

        for i in range(1, len(timestamps)):

            difference = (
                timestamps[i]
                -
                timestamps[i - 1]
            ).total_seconds()

            result.append(
                difference * 1_000_000
            )

        return result

    # ---------------------------------------------------------
    # TCP FLAG COUNTS
    # ---------------------------------------------------------

    @staticmethod
    def count_flag(events, flag):

        count = 0

        for event in events:

            flags = event.get(
                "tcp_flags",
                ""
            )

            if flag in flags:

                count += 1

        return float(count)

    # ---------------------------------------------------------
    # ACTIVE / IDLE
    # ---------------------------------------------------------

    @staticmethod
    def calculate_active_idle(events):

        if len(events) < 2:

            return [], []

        timestamps = sorted(
            datetime.fromisoformat(
                event["timestamp"]
            )
            for event in events
        )

        intervals = []

        for i in range(1, len(timestamps)):

            difference = (
                timestamps[i]
                -
                timestamps[i - 1]
            ).total_seconds()

            intervals.append(
                difference * 1_000_000
            )

        if not intervals:

            return [], []

        # Approximation for live flow monitoring.
        #
        # Short gaps = active period
        # Long gaps = idle period

        ACTIVE_THRESHOLD = 1_000_000

        active = [
            value
            for value in intervals
            if value <= ACTIVE_THRESHOLD
        ]

        idle = [
            value
            for value in intervals
            if value > ACTIVE_THRESHOLD
        ]

        return active, idle

    # ---------------------------------------------------------
    # EXTRACT FEATURES
    # ---------------------------------------------------------

    def extract_features(self, key):

        events = self.flows[key]

        if len(events) < 2:

            return None

        events = sorted(
            events,
            key=lambda x: x["timestamp"]
        )

        # -----------------------------------------------------
        # FLOW DURATION
        # -----------------------------------------------------

        timestamps = [
            datetime.fromisoformat(
                event["timestamp"]
            )
            for event in events
        ]

        flow_duration = (
            timestamps[-1]
            -
            timestamps[0]
        ).total_seconds()

        flow_duration_us = (
            flow_duration * 1_000_000
        )

        # -----------------------------------------------------
        # FORWARD / BACKWARD
        # -----------------------------------------------------

        first_event = events[0]

        original_src_ip = (
            first_event["source_ip"]
        )

        original_src_port = (
            first_event["source_port"]
        )

        forward_events = []

        backward_events = []

        for event in events:

            if (
                event["source_ip"]
                == original_src_ip
                and
                event["source_port"]
                == original_src_port
            ):

                forward_events.append(event)

            else:

                backward_events.append(event)

        # -----------------------------------------------------
        # IAT
        # -----------------------------------------------------

        flow_iats = self.calculate_iats(
            events
        )

        forward_iats = self.calculate_iats(
            forward_events
        )

        backward_iats = self.calculate_iats(
            backward_events
        )

        # -----------------------------------------------------
        # ACTIVE / IDLE
        # -----------------------------------------------------

        active_values, idle_values = (
            self.calculate_active_idle(events)
        )

        # -----------------------------------------------------
        # FLAGS
        # -----------------------------------------------------

        fwd_psh = self.count_flag(
            forward_events,
            "PSH"
        )

        fwd_urg = self.count_flag(
            forward_events,
            "URG"
        )

        bwd_psh = self.count_flag(
            backward_events,
            "PSH"
        )

        bwd_urg = self.count_flag(
            backward_events,
            "URG"
        )

        # -----------------------------------------------------
        # DOWN / UP RATIO
        # -----------------------------------------------------

        if len(forward_events) > 0:

            down_up_ratio = (
                len(backward_events)
                /
                len(forward_events)
            )

        else:

            down_up_ratio = 0.0

        # -----------------------------------------------------
        # FEATURES
        # -----------------------------------------------------

        features = {

            "active_max":
                self.maximum(active_values),

            "active_mean":
                self.mean(active_values),

            "active_min":
                self.minimum(active_values),

            "active_std":
                self.standard_deviation(
                    active_values
                ),

            "bwd_iat_max":
                self.maximum(backward_iats),

            "bwd_iat_mean":
                self.mean(backward_iats),

            "bwd_iat_min":
                self.minimum(backward_iats),

            "bwd_iat_std":
                self.standard_deviation(
                    backward_iats
                ),

            "bwd_psh_flags":
                bwd_psh,

            "bwd_urg_flags":
                bwd_urg,

            "cwe_flag_count":
                0.0,

            "down_up_ratio":
                float(down_up_ratio),

            "flow_duration":
                flow_duration_us,

            "flow_iat_max":
                self.maximum(flow_iats),

            "flow_iat_mean":
                self.mean(flow_iats),

            "flow_iat_min":
                self.minimum(flow_iats),

            "flow_iat_std":
                self.standard_deviation(
                    flow_iats
                ),

            "fwd_iat_max":
                self.maximum(forward_iats),

            "fwd_iat_mean":
                self.mean(forward_iats),

            "fwd_iat_min":
                self.minimum(forward_iats),

            "fwd_iat_std":
                self.standard_deviation(
                    forward_iats
                ),

            "fwd_psh_flags":
                fwd_psh,

            "fwd_urg_flags":
                fwd_urg,

            "idle_max":
                self.maximum(idle_values),

            "idle_mean":
                self.mean(idle_values),

            "idle_min":
                self.minimum(idle_values),

            "idle_std":
                self.standard_deviation(
                    idle_values
                )
        }

        return features