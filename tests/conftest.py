from __future__ import annotations

import time
from collections.abc import Iterable
from pathlib import Path
from threading import Event as CancelEvent

import pytest

from fieldtrace.core.models import AnalysisContext, AnalysisItem, ExecutionBudget, TimePolicy


class NoopRunner:
    def run(self, *_args: object, **_kwargs: object) -> tuple[int, str, str]:
        raise AssertionError("이 테스트에서 외부 도구가 실행되면 안 됩니다")


@pytest.fixture
def make_context(tmp_path: Path):
    def factory(
        path: Path,
        *,
        source_id: int = 1,
        max_records: int | None = None,
        max_line_bytes: int = 1_048_576,
        tasks: Iterable[str] = (),
        runner: object | None = None,
        time_policy: TimePolicy | None = None,
        encoding: str | None = None,
        flag_prefixes: tuple[str, ...] = ("FLAG", "flag", "CTF", "ctf"),
        decode_max_depth: int = 2,
        decode_max_output_chars: int = 4_096,
        decode_max_candidates: int = 20,
        artifact_sink: object | None = None,
    ) -> AnalysisContext:
        return AnalysisContext(
            input_path=path,
            source_id=source_id,
            case_id="test-case",
            run_id=1,
            cancel=CancelEvent(),
            time_policy=time_policy or TimePolicy(),
            budget=ExecutionBudget(max_records=max_records, max_line_bytes=max_line_bytes),
            external_runner=runner or NoopRunner(),  # type: ignore[arg-type]
            profile="quick",
            started_at=time.monotonic(),
            selected_tasks=frozenset(tasks),
            text_encoding=encoding,
            flag_prefixes=flag_prefixes,
            decode_max_depth=decode_max_depth,
            decode_max_output_chars=decode_max_output_chars,
            decode_max_candidates=decode_max_candidates,
            artifact_sink=artifact_sink,  # type: ignore[arg-type]
        )

    return factory


def only(items: Iterable[AnalysisItem], kind: type[AnalysisItem]) -> list[AnalysisItem]:
    return [item for item in items if isinstance(item, kind)]
