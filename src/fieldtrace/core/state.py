"""Small local state file for recent menu locations.

This is convenience state only. Evidence paths and analysis results remain in
the case database, and a damaged state file never blocks analysis.
"""

from __future__ import annotations

import json
import os
import tomllib
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path


def default_state_path() -> Path:
    config_home = os.environ.get("XDG_CONFIG_HOME")
    base = Path(config_home).expanduser() if config_home else Path.home() / ".config"
    return base / "fieldtrace" / "state.toml"


@dataclass(slots=True)
class LocalState:
    last_directory: Path | None = None
    last_case: Path | None = None


class StateStore:
    def __init__(self, path: Path | None = None) -> None:
        self.path = path or default_state_path()

    def load(self) -> LocalState:
        try:
            with self.path.open("rb") as stream:
                value = tomllib.load(stream)
        except (OSError, tomllib.TOMLDecodeError):
            return LocalState()
        menu = value.get("menu", {})
        if not isinstance(menu, dict):
            return LocalState()
        directory = menu.get("last_directory")
        case = menu.get("last_case")
        return LocalState(
            last_directory=Path(directory) if isinstance(directory, str) else None,
            last_case=Path(case) if isinstance(case, str) else None,
        )

    def save(self, state: LocalState) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        lines = ["[menu]"]
        if state.last_directory is not None:
            lines.append(f"last_directory = {json.dumps(str(state.last_directory))}")
        if state.last_case is not None:
            lines.append(f"last_case = {json.dumps(str(state.last_case))}")
        payload = "\n".join(lines) + "\n"
        temporary = self.path.with_name(f".{self.path.name}.{os.getpid()}.tmp")
        try:
            temporary.write_text(payload, encoding="utf-8")
            temporary.replace(self.path)
        except OSError:
            with suppress(OSError):
                temporary.unlink(missing_ok=True)
