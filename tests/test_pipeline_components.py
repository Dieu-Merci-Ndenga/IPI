from behavior.profile import build_behavior_profile
from anomaly.detectors import detect_anomalies
from llm.grounded import generate_grounded_explanations
from modbus.decoder import decode_packets_to_ir
from verification.verifier import verify_report


def test_detects_five_v0_categories():
    baseline_packets = [
        {
            "timestamp": 1.0,
            "src_ip": "10.0.0.1",
            "dst_ip": "10.0.0.2",
            "src_port": 40000,
            "dst_port": 502,
            "transaction_id": 1,
            "unit_id": 1,
            "function": 3,
            "address": 40001,
            "quantity": 2,
            "evidence_ref": "pcap_frame:0",
        },
        {
            "timestamp": 1.2,
            "src_ip": "10.0.0.2",
            "dst_ip": "10.0.0.1",
            "src_port": 502,
            "dst_port": 40000,
            "transaction_id": 1,
            "unit_id": 1,
            "function": 3,
            "address": 40001,
            "quantity": 2,
            "evidence_ref": "pcap_frame:1",
        },
        {
            "timestamp": 2.0,
            "src_ip": "10.0.0.1",
            "dst_ip": "10.0.0.2",
            "src_port": 40000,
            "dst_port": 502,
            "transaction_id": 2,
            "unit_id": 1,
            "function": 6,
            "address": 40010,
            "quantity": 1,
            "evidence_ref": "pcap_frame:2",
        },
        {
            "timestamp": 2.5,
            "src_ip": "10.0.0.2",
            "dst_ip": "10.0.0.1",
            "src_port": 502,
            "dst_port": 40000,
            "transaction_id": 2,
            "unit_id": 1,
            "function": 6,
            "address": 40010,
            "quantity": 1,
            "evidence_ref": "pcap_frame:3",
        },
        {
            "timestamp": 3.0,
            "src_ip": "10.0.0.1",
            "dst_ip": "10.0.0.2",
            "src_port": 40000,
            "dst_port": 502,
            "transaction_id": 3,
            "unit_id": 1,
            "function": 6,
            "address": 40010,
            "quantity": 1,
            "evidence_ref": "pcap_frame:4",
        },
    ]
    observed_packets = [
        {
            "timestamp": 10.0,
            "src_ip": "10.0.0.1",
            "dst_ip": "10.0.0.2",
            "src_port": 40000,
            "dst_port": 502,
            "transaction_id": 11,
            "unit_id": 1,
            "function": 6,
            "address": 40010,
            "quantity": 1,
            "evidence_ref": "pcap_frame:10",
        },
        {
            "timestamp": 13.0,
            "src_ip": "10.0.0.1",
            "dst_ip": "10.0.0.2",
            "src_port": 40000,
            "dst_port": 502,
            "transaction_id": 12,
            "unit_id": 1,
            "function": 6,
            "address": 40010,
            "quantity": 1,
            "evidence_ref": "pcap_frame:11",
        },
        {
            "timestamp": 13.2,
            "src_ip": "10.0.0.2",
            "dst_ip": "10.0.0.1",
            "src_port": 502,
            "dst_port": 40000,
            "transaction_id": 99,
            "unit_id": 1,
            "function": 6,
            "address": 40010,
            "quantity": 1,
            "evidence_ref": "pcap_frame:12",
        },
        {
            "timestamp": 14.0,
            "src_ip": "10.0.0.2",
            "dst_ip": "10.0.0.1",
            "src_port": 45000,
            "dst_port": 502,
            "transaction_id": 13,
            "unit_id": 1,
            "function": 8,
            "address": 49999,
            "quantity": 1,
            "evidence_ref": "pcap_frame:13",
        },
    ]

    baseline_ir = decode_packets_to_ir(baseline_packets)
    observed_ir = decode_packets_to_ir(observed_packets)
    profile = build_behavior_profile(baseline_ir)
    anomalies = detect_anomalies(observed_ir, profile)
    categories = {a["category"] for a in anomalies}

    assert "sequence_anomaly" in categories
    assert "periodicity_anomaly" in categories
    assert "request_response_anomaly" in categories
    assert "host_role_anomaly" in categories
    assert "function_address_anomaly" in categories


def test_verifier_rejects_unlinked_evidence():
    report = {
        "events": [{"evidence_ref": "pcap_frame:1"}],
        "anomalies": [
            {
                "timestamp": 1.0,
                "source": "a",
                "destination": "b",
                "protocol": "Modbus/TCP",
                "transaction_message": 1,
                "category": "request_response_anomaly",
                "rule_violated": "x",
                "evidence_events": ["unknown"],
                "score_confidence": 0.9,
                "explanation": "x",
            }
        ],
        "explanations": generate_grounded_explanations(
            [
                {
                    "category": "request_response_anomaly",
                    "explanation": "x",
                    "evidence_events": ["unknown"],
                }
            ]
        ),
    }

    result = verify_report(report)
    assert not result["valid"]
    assert result["errors"]
