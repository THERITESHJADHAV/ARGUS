from datetime import datetime, timezone


def create_network_alert(
    prediction_result,
    source_ip=None,
    destination_ip=None,
    destination_port=None
):
    """
    Create a standardized ARGUS network alert
    from the Random Forest prediction result.
    """

    # -------------------------------------------------
    # Determine severity
    # -------------------------------------------------

    if prediction_result["prediction"] == "ATTACK":

        severity = "HIGH"

    else:

        severity = "INFO"


    # -------------------------------------------------
    # Create alert
    # -------------------------------------------------

    alert = {

        "alert_id": None,

        "timestamp": datetime.now(
            timezone.utc
        ).isoformat(),

        "alert_type": "Network Attack",

        "detector": "network_ml",

        "prediction": prediction_result[
            "prediction"
        ],

        "confidence": prediction_result[
            "confidence"
        ],

        "attack_probability": prediction_result[
            "attack_probability"
        ],

        "severity": severity,

        "source_ip": source_ip,

        "destination_ip": destination_ip,

        "destination_port": destination_port,

        "status": "NEW"
    }


    return alert