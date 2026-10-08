import re


class FailedLoginParser:

    # =====================================================
    # EXTRACT FIELD FROM WINDOWS EVENT MESSAGE
    # =====================================================

    @staticmethod
    def extract_field(
        message,
        field_name
    ):

        pattern = (
            rf"{re.escape(field_name)}\s*:\s*(.*)"
        )

        match = re.search(
            pattern,
            message,
            re.IGNORECASE
        )

        if match:

            return match.group(1).strip()

        return None


    # =====================================================
    # PARSE EVENT
    # =====================================================

    def parse(self, event):

        message = event.get(
            "Message",
            ""
        )


        timestamp = event.get(
            "TimeCreated"
        )


        username = self.extract_field(
            message,
            "Account Name"
        )


        source_ip = self.extract_field(
            message,
            "Source Network Address"
        )


        logon_type = self.extract_field(
            message,
            "Logon Type"
        )


        failure_reason = self.extract_field(
            message,
            "Failure Reason"
        )


        return {

            "event_type":
                "FAILED_LOGIN",

            "event_id":
                4625,

            "timestamp":
                timestamp,

            "username":
                username,

            "source_ip":
                source_ip,

            "logon_type":
                logon_type,

            "failure_reason":
                failure_reason
        }