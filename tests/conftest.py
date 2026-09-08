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
        tasks: Iterable[str] = (),
        runner: object | None = None,
        time_policy: TimePolicy | None = None,
        encoding: str | None = None,
    ) -> AnalysisContext:
        return AnalysisContext(
            input_path=path,
            source_id=source_id,
            case_id="test-case",
            run_id=1,
            cancel=CancelEvent(),
            time_policy=time_policy or TimePolicy(),
            budget=ExecutionBudget(max_records=max_records),
            external_runner=runner or NoopRunner(),  # type: ignore[arg-type]
            profile="quick",
            started_at=time.monotonic(),
            selected_tasks=frozenset(tasks),
            text_encoding=encoding,
        )

    return factory


def only(items: Iterable[AnalysisItem], kind: type[AnalysisItem]) -> list[AnalysisItem]:
    return [item for item in items if isinstance(item, kind)]
