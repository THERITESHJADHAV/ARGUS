import re


class SysmonEventParser:

    FIELDS = [
        "RuleName",
        "UtcTime",
        "ProcessGuid",
        "ProcessId",
        "Image",
        "FileVersion",
        "Description",
        "Product",
        "Company",
        "OriginalFileName",
        "CommandLine",
        "CurrentDirectory",
        "User",
        "LogonGuid",
        "LogonId",
        "TerminalSessionId",
        "IntegrityLevel",
        "Hashes",
        "ParentProcessGuid",
        "ParentProcessId",
        "ParentImage",
        "ParentCommandLine",
        "ParentUser",
    ]

    def extract_field(self, message, field_name):

        pattern = rf"^{re.escape(field_name)}:\s*(.*)$"

        match = re.search(
            pattern,
            message,
            re.MULTILINE
        )

        if match:
            return match.group(1).strip()

        return None

    def extract_hash(self, hashes):

        if not hashes:
            return None

        match = re.search(
            r"SHA256=([A-Fa-f0-9]+)",
            hashes
        )

        if match:
            return match.group(1)

        return None

    def parse(self, event):

        message = event.get("Message", "")

        if not message:
            return None

        hashes = self.extract_field(
            message,
            "Hashes"
        )

        parsed_event = {
            "event_type": "PROCESS_CREATE",
            "event_id": 1,

            "record_id": event.get("RecordId"),

            "timestamp": self.extract_field(
                message,
                "UtcTime"
            ) or event.get("TimeCreated"),

            "rule_name": self.extract_field(
                message,
                "RuleName"
            ),

            "process_guid": self.extract_field(
                message,
                "ProcessGuid"
            ),

            "process_id": self.extract_field(
                message,
                "ProcessId"
            ),

            "image": self.extract_field(
                message,
                "Image"
            ),

            "file_version": self.extract_field(
                message,
                "FileVersion"
            ),

            "description": self.extract_field(
                message,
                "Description"
            ),

            "product": self.extract_field(
                message,
                "Product"
            ),

            "company": self.extract_field(
                message,
                "Company"
            ),

            "original_file_name": self.extract_field(
                message,
                "OriginalFileName"
            ),

            "command_line": self.extract_field(
                message,
                "CommandLine"
            ),

            "current_directory": self.extract_field(
                message,
                "CurrentDirectory"
            ),

            "user": self.extract_field(
                message,
                "User"
            ),

            "logon_guid": self.extract_field(
                message,
                "LogonGuid"
            ),

            "logon_id": self.extract_field(
                message,
                "LogonId"
            ),

            "terminal_session_id": self.extract_field(
                message,
                "TerminalSessionId"
            ),

            "integrity_level": self.extract_field(
                message,
                "IntegrityLevel"
            ),

            "hashes": hashes,

            "sha256": self.extract_hash(
                hashes
            ),

            "parent_process_guid": self.extract_field(
                message,
                "ParentProcessGuid"
            ),

            "parent_process_id": self.extract_field(
                message,
                "ParentProcessId"
            ),

            "parent_image": self.extract_field(
                message,
                "ParentImage"
            ),

            "parent_command_line": self.extract_field(
                message,
                "ParentCommandLine"
            ),

            "parent_user": self.extract_field(
                message,
                "ParentUser"
            ),

            "raw_message": message
        }

        return parsed_event