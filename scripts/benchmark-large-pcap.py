#!/usr/bin/env python3
"""Generate and analyze a large synthetic PCAP with parent/child peak RSS."""

from __future__ import annotations

import argparse
import json
import platform
import resource
import shutil
import struct
import sys
import tempfile
import time
from pathlib import Path

from fieldtrace.core.config import PathSettings, RuntimeConfig
from fieldtrace.core.service import FieldTraceService

MIB = 1024 * 1024


def _rss_mib(who: int) -> float:
    value = resource.getrusage(who).ru_maxrss
    return value / MIB if sys.platform == "darwin" else value / 1024


def _write_pcap(path: Path, size_bytes: int) -> int:
    project = Path(__file__).resolve().parents[1]
    fixture = bytes.fromhex(
        (project / "tests/fixtures/dns-query.pcap.hex").read_text(encoding="ascii")
    )
    global_header = fixture[:24]
    packet = fixture[40:]
    padded_packet = packet + b"\x00" * (65_535 - len(packet))
    record = struct.pack("<IIII", 1_700_000_000, 0, len(padded_packet), len(padded_packet))
    record += padded_packet
    records = max(1, (size_bytes - len(global_header) + len(record) - 1) // len(record))
    block = record * 32
    with path.open("xb") as stream:
        stream.write(global_header)
        full_blocks, remainder = divmod(records, 32)
        for _ in range(full_blocks):
            stream.write(block)
        stream.write(record * remainder)
    return records


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--size-gib", type=float, default=1.0)
    parser.add_argument("--rss-limit-mib", type=float, default=512.0)
    parser.add_argument("--keep", action="store_true")
    arguments = parser.parse_args()
    if arguments.size_gib <= 0 or arguments.rss_limit_mib <= 0:
        parser.error("size and RSS limit must be positive")
    tshark = shutil.which("tshark")
    if tshark is None:
        print("TShark가 없어 PCAP 대형 측정을 수행하지 않았습니다.", file=sys.stderr)
        return 2

    work = Path(tempfile.mkdtemp(prefix="fieldtrace-large-pcap-"))
    evidence = work / "synthetic-large.pcap"
    case = work / "case"
    requested_size = round(arguments.size_gib * 1024**3)
    try:
        generation_started = time.monotonic()
        packet_count = _write_pcap(evidence, requested_size)
        generation_seconds = time.monotonic() - generation_started
        service = FieldTraceService(RuntimeConfig(paths=PathSettings(cases=work / "cases")))
        analysis_started = time.monotonic()
        summary = service.analyze(evidence, case_dir=case, profile="full")
        analysis_seconds = time.monotonic() - analysis_started
        parent_rss = _rss_mib(resource.RUSAGE_SELF)
        child_rss = _rss_mib(resource.RUSAGE_CHILDREN)
        upper_bound_rss = parent_rss + child_rss
        result = {
            "platform": platform.platform(),
            "python": platform.python_version(),
            "tshark": tshark,
            "input_bytes": evidence.stat().st_size,
            "packets": packet_count,
            "generation_seconds": round(generation_seconds, 3),
            "analysis_seconds": round(analysis_seconds, 3),
            "parent_peak_rss_mib": round(parent_rss, 2),
            "tshark_peak_rss_mib": round(child_rss, 2),
            "combined_peak_upper_bound_mib": round(upper_bound_rss, 2),
            "rss_limit_mib": arguments.rss_limit_mib,
            "rss_target_met": upper_bound_rss <= arguments.rss_limit_mib,
            "external_tshark_included": True,
            "events": summary.events,
            "findings": summary.findings,
            "failures": summary.failures,
            "partial": summary.partial,
        }
        print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
        return (
            0
            if result["rss_target_met"]
            and not summary.failures
            and not summary.partial
            and not summary.cancelled
            else 1
        )
    finally:
        if arguments.keep:
            print(f"kept: {work}", file=sys.stderr)
        else:
            shutil.rmtree(work, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
