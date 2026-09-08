from __future__ import annotations

from pathlib import Path

import pytest

from fieldtrace.core.config import ConfigError, load_config


def test_invalid_timezone_is_rejected(tmp_path: Path) -> None:
    path = tmp_path / "invalid.toml"
    path.write_text('[time]\ndefault_timezone = "Not/A_Real_Zone"\n', encoding="utf-8")

    with pytest.raises(ConfigError, match="default_timezone"):
        load_config(path)


def test_pattern_settings_are_loaded_and_invalid_prefix_is_rejected(tmp_path: Path) -> None:
    valid = tmp_path / "valid.toml"
    valid.write_text(
        '[patterns]\nflag_prefixes = ["HTB"]\ndecode_max_depth = 3\n'
        "decode_max_output_chars = 128\ndecode_max_candidates = 7\n",
        encoding="utf-8",
    )

    config = load_config(valid)

    assert config.flag_prefixes == ("HTB",)
    assert config.decode_max_depth == 3
    assert config.decode_max_output_chars == 128
    assert config.decode_max_candidates == 7

    invalid = tmp_path / "invalid-prefix.toml"
    invalid.write_text('[patterns]\nflag_prefixes = [""]\n', encoding="utf-8")
    with pytest.raises(ConfigError, match="flag_prefixes"):
        load_config(invalid)
