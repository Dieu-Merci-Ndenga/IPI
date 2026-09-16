#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json

from pipeline import run_pipeline


def main() -> None:
    parser = argparse.ArgumentParser(description="Run IPI Modbus/TCP V0 pipeline")
    parser.add_argument("pcap", help="Path to pcap/pcapng file")
    parser.add_argument("-o", "--output", help="Output JSON file")
    args = parser.parse_args()

    report = run_pipeline(args.pcap)

    payload = json.dumps(report, indent=2)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as handle:
            handle.write(payload)
    else:
        print(payload)


if __name__ == "__main__":
    main()
