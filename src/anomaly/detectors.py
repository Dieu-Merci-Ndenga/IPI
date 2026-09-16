from __future__ import annotations

from collections import defaultdict

from behavior.profile import BehaviorProfile
from protocol_ir.model import ProtocolEvent
from tcp.reconstruction import pair_transactions


def detect_anomalies(events: list[ProtocolEvent], profile: BehaviorProfile) -> list[dict]:
    anomalies: list[dict] = []
    anomalies.extend(_sequence_anomalies(events, profile))
    anomalies.extend(_periodicity_anomalies(events, profile))
    anomalies.extend(_request_response_anomalies(events))
    anomalies.extend(_host_role_anomalies(events, profile))
    anomalies.extend(_operation_access_anomalies(events, profile))
    return sorted(anomalies, key=lambda a: a["timestamp"])


def _base(event: ProtocolEvent, category: str, rule: str, evidence: list[str], confidence: float) -> dict:
    return {
        "timestamp": event.timestamp,
        "source": event.src_ip,
        "destination": event.dst_ip,
        "protocol": event.protocol,
        "transaction_message": event.transaction_id,
        "category": category,
        "rule_violated": rule,
        "evidence_events": evidence,
        "score_confidence": confidence,
        "explanation": f"{category}: {rule}",
    }


def _sequence_anomalies(events: list[ProtocolEvent], profile: BehaviorProfile) -> list[dict]:
    found = []
    last_by_pair: dict[tuple[str, str], tuple[int, int, str]] = {}
    for event in sorted(events, key=lambda e: e.timestamp):
        pair = (event.src_ip, event.dst_ip)
        current = (event.function, event.address)
        if pair in last_by_pair:
            prev_f, prev_a, prev_ref = last_by_pair[pair]
            transition = ((prev_f, prev_a), current)
            if transition not in profile.transitions:
                found.append(
                    _base(
                        event,
                        "sequence_anomaly",
                        f"Unexpected transition {(prev_f, prev_a)} -> {current}",
                        [prev_ref, event.evidence_ref],
                        0.85,
                    )
                )
        last_by_pair[pair] = (event.function, event.address, event.evidence_ref)
    return found


def _periodicity_anomalies(events: list[ProtocolEvent], profile: BehaviorProfile) -> list[dict]:
    found = []
    last_seen: dict[tuple[str, str, int, int], tuple[float, str]] = {}
    for event in sorted(events, key=lambda e: e.timestamp):
        key = (event.src_ip, event.dst_ip, event.function, event.address)
        baseline = profile.periodicity.get(key)
        if key in last_seen and baseline and baseline > 0:
            previous_ts, previous_ref = last_seen[key]
            observed = event.timestamp - previous_ts
            if abs(observed - baseline) > max(0.5, baseline * 0.5):
                found.append(
                    _base(
                        event,
                        "periodicity_anomaly",
                        f"Observed interval {observed:.3f}s differs from baseline {baseline:.3f}s",
                        [previous_ref, event.evidence_ref],
                        0.8,
                    )
                )
        last_seen[key] = (event.timestamp, event.evidence_ref)
    return found


def _request_response_anomalies(events: list[ProtocolEvent]) -> list[dict]:
    found = []
    pairings = pair_transactions(events)
    by_tx = {e.transaction_id: e for e in events}
    for tx_id, pair in pairings.items():
        if pair["request"] and not pair["response"]:
            req = pair["request"]
            found.append(
                _base(
                    req,
                    "request_response_anomaly",
                    "Request without response",
                    [req.evidence_ref],
                    0.9,
                )
            )
        if pair["response"] and not pair["request"]:
            resp = pair["response"]
            found.append(
                _base(
                    resp,
                    "request_response_anomaly",
                    "Response without matching request",
                    [resp.evidence_ref],
                    0.9,
                )
            )
        if tx_id in by_tx and pair.get("latency_ms") and pair["latency_ms"] > 2000:
            event = by_tx[tx_id]
            found.append(
                _base(
                    event,
                    "request_response_anomaly",
                    f"High transaction latency {pair['latency_ms']:.1f}ms",
                    [pair["request"].evidence_ref, pair["response"].evidence_ref],
                    0.75,
                )
            )
    return found


def _host_role_anomalies(events: list[ProtocolEvent], profile: BehaviorProfile) -> list[dict]:
    found = []
    for event in events:
        expected = profile.roles_by_host.get(event.src_ip)
        if expected == "server" and event.direction == "request":
            found.append(
                _base(
                    event,
                    "host_role_anomaly",
                    "Host observed as server is sending requests",
                    [event.evidence_ref],
                    0.8,
                )
            )
    return found


def _operation_access_anomalies(events: list[ProtocolEvent], profile: BehaviorProfile) -> list[dict]:
    found = []
    for event in events:
        op = (event.function, event.address)
        if op not in profile.allowed_operations:
            found.append(
                _base(
                    event,
                    "function_address_anomaly",
                    f"Operation {op} outside baseline profile",
                    [event.evidence_ref],
                    0.95,
                )
            )
    return found
