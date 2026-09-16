from __future__ import annotations

from protocol_ir.model import ProtocolEvent


def decode_packets_to_ir(packets: list[dict]) -> list[ProtocolEvent]:
    events: list[ProtocolEvent] = []
    for packet in packets:
        direction = "request" if packet["dst_port"] == 502 else "response"
        events.append(
            ProtocolEvent(
                timestamp=packet["timestamp"],
                src_ip=packet["src_ip"],
                dst_ip=packet["dst_ip"],
                src_port=packet["src_port"],
                dst_port=packet["dst_port"],
                transport="TCP",
                protocol="Modbus/TCP",
                transaction_id=packet["transaction_id"],
                unit_id=packet["unit_id"],
                function=packet["function"],
                address=packet["address"],
                quantity=packet["quantity"],
                direction=direction,
                evidence_ref=packet["evidence_ref"],
            )
        )
    return events
