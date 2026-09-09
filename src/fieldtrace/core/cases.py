"""Case directory lifecycle and filesystem safety helpers."""

from __future__ import annotations

import os
import secrets
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

CASE_DB_NAME = "fieldtrace.sqlite3"


class CaseInUseError(OSError):
    """Raised when another FieldTrace process is writing the same case."""


@dataclass(frozen=True, slots=True)
class CasePaths:
    root: Path
    database: Path
    reports: Path
    derived: Path
    diagnostics: Path


def case_paths(root: Path | str) -> CasePaths:
    root_path = Path(root).expanduser().resolve()
    return CasePaths(
        root=root_path,
        database=root_path / CASE_DB_NAME,
        reports=root_path / "reports",
        derived=root_path / "derived",
        diagnostics=root_path / "diagnostics",
    )


def prepare_case(root: Path | str) -> CasePaths:
    """Create an explicit case directory without touching any input file."""

    paths = case_paths(root)
    paths.root.mkdir(parents=True, exist_ok=True)
    for directory in (paths.reports, paths.derived, paths.diagnostics):
        directory.mkdir(exist_ok=True)
    probe = paths.root / f".write-test-{os.getpid()}"
    try:
        probe.touch(exist_ok=False)
        probe.unlink()
    except OSError as exc:
        raise PermissionError(f"사례 폴더에 쓸 수 없습니다: {paths.root}") from exc
    return paths


def create_case(base: Path | str = "cases", *, now: datetime | None = None) -> CasePaths:
    timestamp = (now or datetime.now().astimezone()).strftime("%Y%m%d-%H%M%S")
    base_path = Path(base).expanduser().resolve()
    for _ in range(20):
        candidate = base_path / f"{timestamp}-{secrets.token_hex(3)}"
        try:
            candidate.mkdir(parents=True, exist_ok=False)
        except FileExistsError:
            continue
        return prepare_case(candidate)
    raise OSError("고유한 사례 폴더 이름을 만들 수 없습니다.")


@contextmanager
def case_analysis_lock(case: CasePaths) -> Iterator[None]:
    """Hold a process-scoped writer lock for one analysis request.

    SQLite still protects individual transactions.  This lock prevents two
    FieldTrace analysis processes from interleaving runs in the same case and
    lets the next process safely recover runs left as ``running`` after a crash.
    Read-only search/report operations do not take this lock.
    """

    lock_path = case.root / ".analysis.lock"
    try:
        stream = lock_path.open("a+b")
    except OSError as exc:
        raise PermissionError(f"사례 분석 잠금 파일을 만들 수 없습니다: {lock_path}") from exc

    try:
        try:
            import fcntl
        except ImportError:  # pragma: no cover - native Windows is outside the initial scope
            yield
            return
        try:
            fcntl.flock(stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise CaseInUseError(
                "같은 사례를 다른 FieldTrace 분석이 사용 중입니다. "
                "기존 분석을 완료하거나 취소한 뒤 다시 시도하세요."
            ) from exc
        try:
            yield
        finally:
            fcntl.flock(stream.fileno(), fcntl.LOCK_UN)
    finally:
        stream.close()
