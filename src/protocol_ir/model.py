from __future__ import annotations

from dataclasses import asdict, dataclass


@dataclass(frozen=True)
class ProtocolEvent:
    timestamp: float
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    transport: str
    protocol: str
    transaction_id: int
    unit_id: int
    function: int
    address: int
    quantity: int
    direction: str
    evidence_ref: str

    def to_dict(self) -> dict:
        return asdict(self)
