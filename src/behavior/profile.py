from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass

from protocol_ir.model import ProtocolEvent


@dataclass
class BehaviorProfile:
    allowed_operations: set[tuple[int, int]]
    roles_by_host: dict[str, str]
    transitions: set[tuple[tuple[int, int], tuple[int, int]]]
    periodicity: dict[tuple[str, str, int, int], float]


def build_behavior_profile(events: list[ProtocolEvent]) -> BehaviorProfile:
    allowed_operations = {(e.function, e.address) for e in events}

    host_roles = defaultdict(Counter)
    for event in events:
        if event.direction == "request":
            host_roles[event.src_ip]["client"] += 1
            host_roles[event.dst_ip]["server"] += 1
        else:
            host_roles[event.src_ip]["server"] += 1
            host_roles[event.dst_ip]["client"] += 1

    roles_by_host = {host: counts.most_common(1)[0][0] for host, counts in host_roles.items()}

    transitions: set[tuple[tuple[int, int], tuple[int, int]]] = set()
    last_by_pair: dict[tuple[str, str], tuple[int, int]] = {}
    periodicity_series: dict[tuple[str, str, int, int], list[float]] = defaultdict(list)
    last_seen: dict[tuple[str, str, int, int], float] = {}

    for event in sorted(events, key=lambda e: e.timestamp):
        pair = (event.src_ip, event.dst_ip)
        op = (event.function, event.address)
        if pair in last_by_pair:
            transitions.add((last_by_pair[pair], op))
        last_by_pair[pair] = op

        key = (event.src_ip, event.dst_ip, event.function, event.address)
        if key in last_seen:
            periodicity_series[key].append(event.timestamp - last_seen[key])
        last_seen[key] = event.timestamp

    periodicity = {k: sum(v) / len(v) for k, v in periodicity_series.items() if v}

    return BehaviorProfile(
        allowed_operations=allowed_operations,
        roles_by_host=roles_by_host,
        transitions=transitions,
        periodicity=periodicity,
    )
