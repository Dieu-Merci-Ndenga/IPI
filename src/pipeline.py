from __future__ import annotations

from anomaly.detectors import detect_anomalies
from behavior.profile import build_behavior_profile
from capture.tshark_reader import read_modbus_packets
from llm.grounded import generate_grounded_explanations
from modbus.decoder import decode_packets_to_ir
from tcp.reconstruction import build_conversations
from verification.verifier import verify_report


def run_pipeline(pcap_path: str, baseline_events: list[dict] | None = None) -> dict:
    baseline_packets = baseline_events if baseline_events is not None else read_modbus_packets(pcap_path)
    observed_packets = read_modbus_packets(pcap_path)

    baseline_ir = decode_packets_to_ir(baseline_packets)
    observed_ir = decode_packets_to_ir(observed_packets)

    profile = build_behavior_profile(baseline_ir)
    anomalies = detect_anomalies(observed_ir, profile)
    explanations = generate_grounded_explanations(anomalies)

    report = {
        "devices": sorted({event.src_ip for event in observed_ir} | {event.dst_ip for event in observed_ir}),
        "tcp_conversations": {k: len(v) for k, v in build_conversations(observed_ir).items()},
        "transactions": len({e.transaction_id for e in observed_ir}),
        "functions_addresses": sorted({(e.function, e.address) for e in observed_ir}),
        "timeline": [e.timestamp for e in sorted(observed_ir, key=lambda item: item.timestamp)],
        "statistics": {
            "events": len(observed_ir),
            "requests": sum(1 for e in observed_ir if e.direction == "request"),
            "responses": sum(1 for e in observed_ir if e.direction == "response"),
        },
        "behavior_sequences": [
            {"src": e.src_ip, "dst": e.dst_ip, "function": e.function, "address": e.address}
            for e in sorted(observed_ir, key=lambda item: item.timestamp)
        ],
        "events": [e.to_dict() for e in observed_ir],
        "anomalies": anomalies,
        "explanations": explanations,
    }
    report["verification"] = verify_report(report)
    return report
