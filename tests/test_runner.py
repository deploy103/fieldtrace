from __future__ import annotations

import sys
import time
from pathlib import Path
from threading import Event

import pytest

from fieldtrace.core.runner import ExternalToolCancelled, SafeExternalRunner


def test_runner_bounds_stdout_and_reports_truncation() -> None:
    runner = SafeExternalRunner(default_timeout=5, default_max_output=1024)

    code, stdout, stderr = runner.run(
        [sys.executable, "-c", "import sys; sys.stdout.write('x' * 100000)"],
        cancel=Event(),
    )

    assert code == 0
    assert stdout.startswith("x" * 1024)
    assert "출력 제한" in stdout
    assert "stdout 출력 제한" in stderr
    assert len(stdout) < 1200


def test_runner_timeout_terminates_child_promptly() -> None:
    runner = SafeExternalRunner(default_timeout=0.05, default_max_output=1024)
    started = time.monotonic()

    code, _stdout, stderr = runner.run(
        [sys.executable, "-c", "import time; time.sleep(30)"],
        cancel=Event(),
    )

    assert code == 124
    assert "제한 시간" in stderr
    assert time.monotonic() - started < 3


def test_runner_honors_preexisting_cancellation() -> None:
    cancel = Event()
    cancel.set()

    with pytest.raises(ExternalToolCancelled):
        SafeExternalRunner(default_timeout=5).run(
            ["definitely-missing-fieldtrace-tool"], cancel=cancel
        )


def test_runner_uses_isolated_home(tmp_path: Path) -> None:
    del tmp_path
    code, stdout, _stderr = SafeExternalRunner(default_timeout=5).run(
        [sys.executable, "-c", "import os; print(os.environ['HOME'])"],
        cancel=Event(),
        env={"HOME": "/untrusted/override"},
    )

    assert code == 0
    assert "fieldtrace-tool-" in stdout
