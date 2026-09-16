from __future__ import annotations


def generate_grounded_explanations(anomalies: list[dict]) -> list[dict]:
    """Grounded explanation layer: deterministic templates only from observed anomalies."""
    explanations = []
    for index, anomaly in enumerate(anomalies, start=1):
        explanations.append(
            {
                "id": f"exp-{index}",
                "anomaly_category": anomaly["category"],
                "statement": anomaly["explanation"],
                "evidence_events": anomaly["evidence_events"],
            }
        )
    return explanations
