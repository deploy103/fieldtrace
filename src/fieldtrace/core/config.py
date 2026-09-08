"""TOML configuration loading with conservative, validated defaults."""

from __future__ import annotations

import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from .models import ExecutionBudget, TimePolicy


class ConfigError(ValueError):
    """Raised when a configuration file cannot be used safely."""


@dataclass(frozen=True, slots=True)
class AnalysisSettings:
    quick_seconds: float = 30.0
    quick_records: int = 100_000
    batch_size: int = 250
    max_line_bytes: int = 1_048_576
    max_preview_chars: int = 500
    command_timeout_seconds: float = 120.0
    command_output_bytes: int = 8_388_608

    def budget(self, profile: str) -> ExecutionBudget:
        if profile == "quick":
            return ExecutionBudget(
                max_seconds=self.quick_seconds,
                max_records=self.quick_records,
                max_line_bytes=self.max_line_bytes,
                max_preview_chars=self.max_preview_chars,
            )
        return ExecutionBudget(
            max_line_bytes=self.max_line_bytes,
            max_preview_chars=self.max_preview_chars,
        )


@dataclass(frozen=True, slots=True)
class PathSettings:
    input: Path = Path("input")
    cases: Path = Path("cases")


@dataclass(frozen=True, slots=True)
class RuntimeConfig:
    analysis: AnalysisSettings = field(default_factory=AnalysisSettings)
    paths: PathSettings = field(default_factory=PathSettings)
    time_policy: TimePolicy = field(default_factory=TimePolicy)
    flag_prefixes: tuple[str, ...] = ("FLAG", "flag", "CTF", "ctf")
    decode_max_depth: int = 2
    decode_max_output_chars: int = 4_096
    decode_max_candidates: int = 20
    source_path: Path | None = None


def _positive(value: Any, name: str, cast: type[int] | type[float]) -> int | float:
    try:
        result = cast(value)
    except (TypeError, ValueError) as exc:
        raise ConfigError(f"{name} 값은 숫자여야 합니다.") from exc
    if result <= 0:
        raise ConfigError(f"{name} 값은 0보다 커야 합니다.")
    return result


def load_config(path: Path | str | None = None) -> RuntimeConfig:
    """Load settings from *path*, or defaults when no file is present.

    Relative input/case paths remain relative to the invocation directory, not
    to the configuration file. This keeps documented CLI paths predictable.
    """

    config_path = Path(path) if path is not None else Path("configs/default.toml")
    if not config_path.exists():
        if path is not None:
            raise ConfigError(f"설정 파일을 찾을 수 없습니다: {config_path}")
        return RuntimeConfig()
    try:
        with config_path.open("rb") as stream:
            raw = tomllib.load(stream)
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise ConfigError(f"설정 파일을 읽을 수 없습니다: {config_path}: {exc}") from exc

    analysis = raw.get("analysis", {})
    paths = raw.get("paths", {})
    time = raw.get("time", {})
    patterns = raw.get("patterns", {})
    if not all(isinstance(section, dict) for section in (analysis, paths, time, patterns)):
        raise ConfigError("설정 섹션은 TOML 테이블이어야 합니다.")

    settings = AnalysisSettings(
        quick_seconds=float(_positive(analysis.get("quick_seconds", 30), "quick_seconds", float)),
        quick_records=int(_positive(analysis.get("quick_records", 100_000), "quick_records", int)),
        batch_size=int(_positive(analysis.get("batch_size", 250), "batch_size", int)),
        max_line_bytes=int(
            _positive(analysis.get("max_line_bytes", 1_048_576), "max_line_bytes", int)
        ),
        max_preview_chars=int(
            _positive(analysis.get("max_preview_chars", 500), "max_preview_chars", int)
        ),
        command_timeout_seconds=float(
            _positive(
                analysis.get("command_timeout_seconds", 120),
                "command_timeout_seconds",
                float,
            )
        ),
        command_output_bytes=int(
            _positive(
                analysis.get("command_output_bytes", 8_388_608),
                "command_output_bytes",
                int,
            )
        ),
    )
    year_value = time.get("default_year", 0)
    year = int(year_value) if year_value not in (None, "", 0) else None
    if year is not None and not 1970 <= year <= 9999:
        raise ConfigError("default_year 값은 1970~9999 범위여야 합니다.")
    timezone = time.get("default_timezone") or None
    if timezone is not None and not isinstance(timezone, str):
        raise ConfigError("default_timezone 값은 문자열이어야 합니다.")
    if timezone is not None:
        try:
            ZoneInfo(timezone)
        except ZoneInfoNotFoundError as exc:
            raise ConfigError(f"알 수 없는 default_timezone입니다: {timezone}") from exc
    prefixes = patterns.get("flag_prefixes", ["FLAG", "flag", "CTF", "ctf"])
    if not isinstance(prefixes, list) or not all(isinstance(item, str) for item in prefixes):
        raise ConfigError("flag_prefixes 값은 문자열 배열이어야 합니다.")
    if not prefixes or any(
        not item or len(item) > 64 or any(character in "{}\r\n" for character in item)
        for item in prefixes
    ):
        raise ConfigError("flag_prefixes에는 1~64자의 줄바꿈·중괄호 없는 값을 지정하세요.")
    return RuntimeConfig(
        analysis=settings,
        paths=PathSettings(
            input=Path(str(paths.get("input", "input"))),
            cases=Path(str(paths.get("cases", "cases"))),
        ),
        time_policy=TimePolicy(timezone=timezone, assumed_year=year),
        flag_prefixes=tuple(prefixes),
        decode_max_depth=int(
            _positive(patterns.get("decode_max_depth", 2), "decode_max_depth", int)
        ),
        decode_max_output_chars=int(
            _positive(
                patterns.get("decode_max_output_chars", 4_096),
                "decode_max_output_chars",
                int,
            )
        ),
        decode_max_candidates=int(
            _positive(
                patterns.get("decode_max_candidates", 20),
                "decode_max_candidates",
                int,
            )
        ),
        source_path=config_path.resolve(),
    )
