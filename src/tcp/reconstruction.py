from __future__ import annotations

from collections import defaultdict

from protocol_ir.model import ProtocolEvent


def build_conversations(events: list[ProtocolEvent]) -> dict[str, list[ProtocolEvent]]:
    conversations: dict[str, list[ProtocolEvent]] = defaultdict(list)
    for event in sorted(events, key=lambda e: e.timestamp):
        a = (event.src_ip, event.src_port)
        b = (event.dst_ip, event.dst_port)
        key = f"{min(a, b)}->{max(a, b)}"
        conversations[key].append(event)
    return dict(conversations)


def pair_transactions(events: list[ProtocolEvent]) -> dict[int, dict]:
    tx_map: dict[int, dict] = {}
    pending: dict[tuple, ProtocolEvent] = {}

    for event in sorted(events, key=lambda e: e.timestamp):
        key = (event.src_ip, event.dst_ip, event.transaction_id)
        reverse = (event.dst_ip, event.src_ip, event.transaction_id)
        if event.direction == "request":
            pending[key] = event
            tx_map[event.transaction_id] = {"request": event, "response": None, "latency_ms": None}
        else:
            req = pending.pop(reverse, None)
            if req:
                latency_ms = max(0.0, (event.timestamp - req.timestamp) * 1000)
                tx_map[event.transaction_id] = {"request": req, "response": event, "latency_ms": latency_ms}
            else:
                tx_map.setdefault(event.transaction_id, {"request": None, "response": event, "latency_ms": None})

    return tx_map
