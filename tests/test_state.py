from __future__ import annotations

from pathlib import Path

from fieldtrace.core.state import LocalState, StateStore


def test_state_round_trip_preserves_korean_spaces_and_backslashes(tmp_path: Path) -> None:
    path = tmp_path / "state.toml"
    store = StateStore(path)
    state = LocalState(
        last_directory=Path("/mnt/c/대회 자료/입력 폴더"),
        last_case=Path(r"C:\CTF 자료\사례 1"),
    )

    store.save(state)

    assert store.load() == state


def test_corrupt_state_degrades_to_empty_state(tmp_path: Path) -> None:
    path = tmp_path / "state.toml"
    path.write_text("[menu\nlast_directory = ???", encoding="utf-8")

    loaded = StateStore(path).load()

    assert loaded == LocalState()
