from __future__ import annotations

from pathlib import Path

import pytest

from fieldtrace.core.config import ConfigError, load_config


def test_invalid_timezone_is_rejected(tmp_path: Path) -> None:
    path = tmp_path / "invalid.toml"
    path.write_text('[time]\ndefault_timezone = "Not/A_Real_Zone"\n', encoding="utf-8")

    with pytest.raises(ConfigError, match="default_timezone"):
        load_config(path)
