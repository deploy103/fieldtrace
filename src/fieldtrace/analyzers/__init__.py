"""Explicit registry of trusted built-in analyzers."""

from __future__ import annotations

from fieldtrace.analyzers.generic_text import GenericTextAnalyzer
from fieldtrace.analyzers.linux_auth import LinuxAuthAnalyzer
from fieldtrace.analyzers.pcap import PcapAnalyzer
from fieldtrace.analyzers.web import WebLogAnalyzer
from fieldtrace.core.models import Analyzer

BUILTIN_ANALYZER_TYPES = (
    WebLogAnalyzer,
    LinuxAuthAnalyzer,
    PcapAnalyzer,
    GenericTextAnalyzer,
)


def builtin_analyzers() -> tuple[Analyzer, ...]:
    """Construct only reviewed built-ins; never discover arbitrary Python files."""

    return tuple(analyzer_type() for analyzer_type in BUILTIN_ANALYZER_TYPES)


built_in_analyzers = builtin_analyzers

__all__ = [
    "BUILTIN_ANALYZER_TYPES",
    "GenericTextAnalyzer",
    "LinuxAuthAnalyzer",
    "PcapAnalyzer",
    "WebLogAnalyzer",
    "built_in_analyzers",
    "builtin_analyzers",
]
