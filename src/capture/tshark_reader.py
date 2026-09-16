from __future__ import annotations

import json
import subprocess
from pathlib import Path


class CaptureReadError(RuntimeError):
    pass


def read_modbus_packets(pcap_path: str) -> list[dict]:
    """Read Modbus/TCP packets from a pcap using tshark JSON output."""
    path = Path(pcap_path)
    if not path.exists():
        raise FileNotFoundError(path)

    cmd = [
        "tshark",
        "-r",
        str(path),
        "-Y",
        "modbus",
        "-T",
        "json",
    ]

    completed = subprocess.run(cmd, capture_output=True, text=True, check=False)
    if completed.returncode != 0:
        raise CaptureReadError(completed.stderr.strip() or "Unable to read capture")

    payload = completed.stdout.strip()
    if not payload:
        return []

    frames = json.loads(payload)
    packets: list[dict] = []
    for index, frame in enumerate(frames):
        layers = frame.get("_source", {}).get("layers", {})
        tcp = layers.get("tcp", {})
        ip = layers.get("ip", {})
        modbus = layers.get("mbtcp", {})
        frame_layer = layers.get("frame", {})

        try:
            packets.append(
                {
                    "timestamp": float(_pick(frame_layer, "frame.time_epoch", "0")),
                    "src_ip": _pick(ip, "ip.src", "0.0.0.0"),
                    "dst_ip": _pick(ip, "ip.dst", "0.0.0.0"),
                    "src_port": int(_pick(tcp, "tcp.srcport", "0")),
                    "dst_port": int(_pick(tcp, "tcp.dstport", "0")),
                    "transaction_id": int(_pick(modbus, "mbtcp.trans_id", "-1")),
                    "unit_id": int(_pick(modbus, "mbtcp.unit_id", "0")),
                    "function": int(_pick(modbus, "mbtcp.modbus.func_code", "0")),
                    "address": int(_pick(modbus, "mbtcp.modbus.reference_num", "0")),
                    "quantity": int(
                        _pick(modbus, "mbtcp.modbus.word_cnt", _pick(modbus, "mbtcp.modbus.bit_cnt", "0"))
                    ),
                    "evidence_ref": f"pcap_frame:{index}",
                }
            )
        except ValueError:
            continue

    return packets


def _pick(layer: dict, key: str, default: str) -> str:
    value = layer.get(key, default)
    if isinstance(value, list):
        return value[0]
    return value
