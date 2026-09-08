"""Case directory lifecycle and filesystem safety helpers."""

from __future__ import annotations

import os
import secrets
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

CASE_DB_NAME = "fieldtrace.sqlite3"


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
