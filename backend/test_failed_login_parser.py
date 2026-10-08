from app.detection.failed_login_parser import (
    FailedLoginParser
)


parser = FailedLoginParser()


sample_event = {

    "TimeCreated":
        "2026-10-06T12:00:00",

    "Id":
        4625,

    "Message":
        """
        An account failed to log on.

        Account Name: administrator
        Logon Type: 3
        Failure Reason: Unknown user name or bad password
        Source Network Address: 192.168.0.50
        """
}


result = parser.parse(
    sample_event
)


print("=" * 70)
print("FAILED LOGIN PARSER TEST")
print("=" * 70)


for key, value in result.items():

    print(
        f"{key}: {value}"
    )


print("=" * 70)