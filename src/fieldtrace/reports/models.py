"""Stable data-transfer model between core persistence and report exporters."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import asdict, dataclass, field, is_dataclass
from datetime import date, datetime
from enum import Enum
from pathlib import Path
from typing import Any, Protocol


def to_plain(value: Any) -> Any:
    """Convert dataclasses and common scalar types to JSON-compatible values."""

    if is_dataclass(value) and not isinstance(value, type):
        return to_plain(asdict(value))
    if isinstance(value, Mapping):
        return {str(key): to_plain(item) for key, item in value.items()}
    if isinstance(value, (list, tuple, set, frozenset)):
        return [to_plain(item) for item in value]
    if isinstance(value, (datetime, date)):
        return value.isoformat()
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, Enum):
        return value.value
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    return str(value)


def _records(values: Sequence[object]) -> tuple[dict[str, Any], ...]:
    records: list[dict[str, Any]] = []
    for value in values:
        plain = to_plain(value)
        if not isinstance(plain, Mapping):
            raise TypeError("보고서 레코드는 mapping 또는 dataclass여야 합니다.")
        records.append(dict(plain))
    return tuple(records)


@dataclass(frozen=True, slots=True)
class ReportBundle:
    """All records for one scoped report.

    Core owns database access and must populate only the requested/latest runs.
    Exporters never query SQLite and preserve evidence preview text verbatim in
    JSON.  ``selection`` documents the run/source scope used by core.
    """

    case: Mapping[str, Any] = field(default_factory=dict)
    summary: Mapping[str, Any] = field(default_factory=dict)
    sources: tuple[Mapping[str, Any], ...] = ()
    runs: tuple[Mapping[str, Any], ...] = ()
    events: tuple[Mapping[str, Any], ...] = ()
    findings: tuple[Mapping[str, Any], ...] = ()
    diagnostics: tuple[Mapping[str, Any], ...] = ()
    artifacts: tuple[Mapping[str, Any], ...] = ()
    correlations: tuple[Mapping[str, Any], ...] = ()
    selection: Mapping[str, Any] = field(default_factory=dict)

    @classmethod
    def build(
        cls,
        *,
        case: object | None = None,
        summary: object | None = None,
        sources: Sequence[object] = (),
        runs: Sequence[object] = (),
        events: Sequence[object] = (),
        findings: Sequence[object] = (),
        diagnostics: Sequence[object] = (),
        artifacts: Sequence[object] = (),
        correlations: Sequence[object] = (),
        selection: object | None = None,
    ) -> ReportBundle:
        plain_case = to_plain(case or {})
        plain_summary = to_plain(summary or {})
        plain_selection = to_plain(selection or {})
        if not all(
            isinstance(item, Mapping) for item in (plain_case, plain_summary, plain_selection)
        ):
            raise TypeError("case, summary, selection은 mapping 또는 dataclass여야 합니다.")
        return cls(
            case=dict(plain_case),
            summary=dict(plain_summary),
            sources=_records(sources),
            runs=_records(runs),
            events=_records(events),
            findings=_records(findings),
            diagnostics=_records(diagnostics),
            artifacts=_records(artifacts),
            correlations=_records(correlations),
            selection=dict(plain_selection),
        )

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> ReportBundle:
        case = value.get("case", {})
        runs = value.get("runs", ())
        sources = value.get("sources", ())
        selection = value.get("selection")
        if selection is None:
            plain_runs = _records(runs)
            plain_sources = _records(sources)
            plain_case = to_plain(case)
            selection = {
                "run_ids": [run["id"] for run in plain_runs if run.get("id") is not None],
                "source_ids": [
                    source["id"] for source in plain_sources if source.get("id") is not None
                ],
                "latest_only": (
                    plain_case.get("latest_only", True) if isinstance(plain_case, Mapping) else True
                ),
            }
        return cls.build(
            case=case,
            summary=value.get("summary", {}),
            sources=sources,
            runs=runs,
            events=value.get("events", ()),
            findings=value.get("findings", ()),
            diagnostics=value.get("diagnostics", ()),
            artifacts=value.get("artifacts", ()),
            correlations=value.get("correlations", ()),
            selection=selection,
        )

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema_version": 1,
            "case": to_plain(self.case),
            "summary": to_plain(self.summary),
            "selection": to_plain(self.selection),
            "sources": to_plain(self.sources),
            "runs": to_plain(self.runs),
            "events": to_plain(self.events),
            "findings": to_plain(self.findings),
            "diagnostics": to_plain(self.diagnostics),
            "artifacts": to_plain(self.artifacts),
            "correlations": to_plain(self.correlations),
        }


class ReportDataProvider(Protocol):
    """Core-side contract used by CLI before invoking an exporter."""

    def report_bundle(
        self, *, run_ids: Sequence[int] | None = None, latest_only: bool = True
    ) -> ReportBundle: ...
