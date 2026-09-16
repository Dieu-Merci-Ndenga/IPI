from __future__ import annotations


REQUIRED_ANOMALY_FIELDS = {
    "timestamp",
    "source",
    "destination",
    "protocol",
    "transaction_message",
    "category",
    "rule_violated",
    "evidence_events",
    "score_confidence",
    "explanation",
}


def verify_report(report: dict) -> dict:
    errors: list[str] = []

    events = report.get("events", [])
    event_refs = {event["evidence_ref"] for event in events if "evidence_ref" in event}

    for idx, anomaly in enumerate(report.get("anomalies", [])):
        missing = REQUIRED_ANOMALY_FIELDS - set(anomaly)
        if missing:
            errors.append(f"anomaly[{idx}] missing fields: {sorted(missing)}")
        for evidence in anomaly.get("evidence_events", []):
            if evidence not in event_refs:
                errors.append(f"anomaly[{idx}] references unknown evidence: {evidence}")

    for idx, exp in enumerate(report.get("explanations", [])):
        if not set(exp.get("evidence_events", [])).issubset(event_refs):
            errors.append(f"explanation[{idx}] contains unsupported evidence references")

    return {
        "valid": not errors,
        "errors": errors,
    }
