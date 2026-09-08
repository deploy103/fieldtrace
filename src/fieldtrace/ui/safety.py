"""Safety helpers for untrusted paths and terminal text."""

from __future__ import annotations

import os
import re
import unicodedata
from pathlib import Path

from rich.markup import escape

_WINDOWS_DRIVE_PATH = re.compile(r"^(?P<drive>[A-Za-z]):[\\/](?P<rest>.*)$")
_QUOTE_PAIRS = {"'": "'", '"': '"', "\u2018": "\u2019", "\u201c": "\u201d"}


def strip_paired_quotes(value: str) -> str:
    """Trim outer whitespace and one matching pair of quotes.

    Shell-style parsing is deliberately avoided: pasted evidence paths must never
    cause substitutions or escape interpretation.
    """

    cleaned = value.strip()
    if len(cleaned) >= 2 and _QUOTE_PAIRS.get(cleaned[0]) == cleaned[-1]:
        return cleaned[1:-1]
    return cleaned


def is_wsl() -> bool:
    """Return whether this process is running under WSL."""

    if os.environ.get("WSL_INTEROP") or os.environ.get("WSL_DISTRO_NAME"):
        return True
    try:
        release = Path("/proc/sys/kernel/osrelease").read_text(encoding="utf-8", errors="replace")
    except OSError:
        return False
    return "microsoft" in release.casefold() or "wsl" in release.casefold()


def windows_path_to_wsl(value: str, *, running_on_wsl: bool | None = None) -> str:
    """Convert a drive-letter path only when WSL is positively detected.

    UNC and device paths are returned unchanged because there is no universally
    correct WSL mount for them.
    """

    if running_on_wsl is None:
        running_on_wsl = is_wsl()
    if not running_on_wsl:
        return value
    match = _WINDOWS_DRIVE_PATH.match(value)
    if not match:
        return value
    drive = match.group("drive").lower()
    rest = match.group("rest").replace("\\", "/")
    return f"/mnt/{drive}/{rest}"


def normalize_pasted_path(
    value: str,
    *,
    cwd: Path | None = None,
    running_on_wsl: bool | None = None,
    require_exists: bool = True,
) -> Path:
    """Normalize a pasted path without interpreting shell syntax.

    Relative paths remain relative to ``cwd`` (or the process directory).
    Windows paths are translated only on WSL.  Existence is checked after any
    conversion so a misleading translation is never silently accepted.
    """

    cleaned = strip_paired_quotes(value)
    if not cleaned:
        raise ValueError("경로가 비어 있습니다.")
    converted = windows_path_to_wsl(cleaned, running_on_wsl=running_on_wsl)
    path = Path(converted).expanduser()
    if not path.is_absolute() and cwd is not None:
        path = cwd / path
    if require_exists and not path.exists():
        raise FileNotFoundError(f"경로를 찾을 수 없습니다: {path}")
    return path


def strip_terminal_controls(value: object, *, multiline: bool = False) -> str:
    """Remove terminal controls while preserving readable evidence text."""

    text = str(value)
    safe: list[str] = []
    for character in text:
        if multiline and character in {"\n", "\t"}:
            safe.append(character)
            continue
        if unicodedata.category(character) in {"Cc", "Cf"}:
            safe.append(" " if character in {"\n", "\r", "\t"} else "�")
            continue
        safe.append(character)
    return "".join(safe)


def safe_terminal_text(value: object, *, multiline: bool = False) -> str:
    """Return text safe to pass to Rich with markup parsing enabled."""

    return escape(strip_terminal_controls(value, multiline=multiline))
