#!/usr/bin/env python3
"""Generate and analyze a large synthetic log while reporting peak process RSS."""

from __future__ import annotations

import argparse
import json
import platform
import resource
import shutil
import sys
import tempfile
import time
from pathlib import Path

from fieldtrace.core.config import PathSettings, RuntimeConfig
from fieldtrace.core.service import FieldTraceService

MIB = 1024 * 1024


def _peak_rss_mib() -> float:
    value = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    # Linux reports KiB; macOS reports bytes. macOS is outside the supported
    # target but keeping the measurement honest makes the script portable.
    return value / MIB if sys.platform == "darwin" else value / 1024


def _write_log(path: Path, size_bytes: int) -> None:
    line = b"x" * (64 * 1024 - 1) + b"\n"
    block = line * 128
    remaining = size_bytes
    with path.open("xb") as stream:
        while remaining:
            chunk = block if remaining >= len(block) else block[:remaining]
            stream.write(chunk)
            remaining -= len(chunk)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--size-gib", type=float, default=1.0)
    parser.add_argument("--rss-limit-mib", type=float, default=512.0)
    parser.add_argument("--keep", action="store_true")
    arguments = parser.parse_args()
    if arguments.size_gib <= 0 or arguments.rss_limit_mib <= 0:
        parser.error("size and RSS limit must be positive")

    work = Path(tempfile.mkdtemp(prefix="fieldtrace-large-log-"))
    evidence = work / "synthetic-large.log"
    case = work / "case"
    size_bytes = round(arguments.size_gib * 1024**3)
    try:
        generation_started = time.monotonic()
        _write_log(evidence, size_bytes)
        generation_seconds = time.monotonic() - generation_started
        service = FieldTraceService(RuntimeConfig(paths=PathSettings(cases=work / "cases")))
        analysis_started = time.monotonic()
        summary = service.analyze(
            evidence,
            case_dir=case,
            profile="full",
            forced_type="text",
        )
        analysis_seconds = time.monotonic() - analysis_started
        peak_rss = _peak_rss_mib()
        result = {
            "platform": platform.platform(),
            "python": platform.python_version(),
            "input_bytes": size_bytes,
            "generation_seconds": round(generation_seconds, 3),
            "analysis_seconds": round(analysis_seconds, 3),
            "peak_rss_mib": round(peak_rss, 2),
            "rss_limit_mib": arguments.rss_limit_mib,
            "rss_target_met": peak_rss <= arguments.rss_limit_mib,
            "external_tshark_included": False,
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
