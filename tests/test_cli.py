from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from fieldtrace.cli import app

runner = CliRunner()


def test_cli_analyze_search_timeline_report(tmp_path: Path) -> None:
    evidence = tmp_path / "한글 증거 파일.log"
    evidence.write_text(
        '192.0.2.44 - - [08/Sep/2026:14:12:30 +0900] "GET /FLAG%7Bcli_ok%7D HTTP/1.1" 200 12\n',
        encoding="utf-8",
    )
    case = tmp_path / "case"

    analyzed = runner.invoke(
        app,
        ["analyze", str(evidence), "--profile", "quick", "--case", str(case)],
    )
    searched = runner.invoke(
        app,
        ["search", "--case", str(case), "--text", "FLAG{cli_ok}"],
    )
    timeline = runner.invoke(app, ["timeline", "--case", str(case)])
    report_path = tmp_path / "결과 보고서.json"
    reported = runner.invoke(
        app,
        [
            "report",
            "--case",
            str(case),
            "--format",
            "json",
            "--output",
            str(report_path),
        ],
    )

    assert analyzed.exit_code == 0, analyzed.output
    assert "FLAG{cli_ok}" in analyzed.output
    assert searched.exit_code == 0 and "FLAG{cli_ok}" in searched.output
    assert timeline.exit_code == 0 and "line:1" in timeline.output
    assert reported.exit_code == 0
    payload = json.loads(report_path.read_text(encoding="utf-8"))
    assert payload["events"][0]["evidence_locator"] == "line:1"


def test_cli_invalid_input_is_exit_two(tmp_path: Path) -> None:
    missing = runner.invoke(app, ["analyze", str(tmp_path / "missing.log")])

    assert missing.exit_code == 2
    assert "실패 단계" in missing.output


def test_cli_exports_offline_html_report(tmp_path: Path) -> None:
    evidence = tmp_path / "evidence.log"
    evidence.write_text("FLAG{html_cli}\n", encoding="utf-8")
    case = tmp_path / "case"
    analyzed = runner.invoke(app, ["analyze", str(evidence), "--case", str(case)])
    output = tmp_path / "report.html"

    reported = runner.invoke(
        app,
        [
            "report",
            "--case",
            str(case),
            "--format",
            "html",
            "--output",
            str(output),
        ],
    )

    assert analyzed.exit_code == 0, analyzed.output
    assert reported.exit_code == 0, reported.output
    assert "FLAG{html_cli}" in output.read_text(encoding="utf-8")


def test_cli_explicit_cp949_encoding(tmp_path: Path) -> None:
    path = tmp_path / "한글 레거시.log"
    path.write_bytes("한글 FLAG{cli_cp949}\n".encode("cp949"))
    case = tmp_path / "case"

    result = runner.invoke(
        app,
        [
            "analyze",
            str(path),
            "--case",
            str(case),
            "--encoding",
            "cp949",
        ],
    )

    assert result.exit_code == 0, result.output
    assert "FLAG{cli_cp949}" in result.output


def test_cli_rejects_unreviewed_encoding(tmp_path: Path) -> None:
    path = tmp_path / "evidence.log"
    path.write_text("text", encoding="utf-8")

    result = runner.invoke(app, ["analyze", str(path), "--encoding", "rot13"])

    assert result.exit_code == 2
    assert "지원하지 않는 텍스트 인코딩" in result.output


def test_cli_correlates_same_indicator_across_inputs(tmp_path: Path) -> None:
    first = tmp_path / "first.log"
    second = tmp_path / "second.log"
    first.write_text("source 192.0.2.99 shared.example.test\n", encoding="utf-8")
    second.write_text("destination 192.0.2.99 shared.example.test\n", encoding="utf-8")
    case = tmp_path / "case"

    analyzed = runner.invoke(app, ["analyze", str(first), str(second), "--case", str(case)])
    correlated = runner.invoke(app, ["correlate", "--case", str(case)])

    assert analyzed.exit_code == 0, analyzed.output
    assert correlated.exit_code == 0, correlated.output
    assert "192.0.2.99" in correlated.output
    assert "shared.example.test" in correlated.output
    assert "인과관계를 뜻하지 않음" in correlated.output


def test_no_argument_menu_quits_cleanly(tmp_path: Path) -> None:
    result = runner.invoke(
        app,
        [],
        input="q\n",
        env={"XDG_CONFIG_HOME": str(tmp_path / "config")},
    )

    assert result.exit_code == 0
    assert "파일 선택" in result.output


def test_menu_file_enter_quick_candidate_evidence(tmp_path: Path) -> None:
    evidence_dir = tmp_path / "입력 폴더"
    evidence_dir.mkdir()
    (evidence_dir / "문제 로그.txt").write_text(
        "first line\nFLAG{menu_evidence}\n",
        encoding="utf-8",
    )

    result = runner.invoke(
        app,
        ["menu", str(evidence_dir)],
        # file 1 → Enter quick → finding 1 → result action 6 (quit)
        input="1\n\n1\n6\n",
        env={"XDG_CONFIG_HOME": str(tmp_path / "config")},
    )

    assert result.exit_code == 0, result.output
    assert "FLAG{menu_evidence}" in result.output
    assert "line:2" in result.output
    assert "원문 근거" in result.output
    assert "상세 분석 — 준비 중" in result.output


def test_menu_offers_cp949_after_detection_failure(tmp_path: Path) -> None:
    evidence_dir = tmp_path / "입력 폴더"
    evidence_dir.mkdir()
    (evidence_dir / "레거시 로그.txt").write_bytes("한글 FLAG{menu_cp949}\n".encode("cp949"))

    result = runner.invoke(
        app,
        ["menu", str(evidence_dir)],
        # file → default text type → default CP949 → quick → candidate → quit
        input="1\n\n\n\n1\n6\n",
        env={"XDG_CONFIG_HOME": str(tmp_path / "config")},
    )

    assert result.exit_code == 0, result.output
    assert "텍스트 인코딩 직접 선택" in result.output
    assert "FLAG{menu_cp949}" in result.output


def test_menu_controller_hides_gitkeep_placeholder(tmp_path: Path) -> None:
    evidence_dir = tmp_path / "input"
    evidence_dir.mkdir()
    (evidence_dir / ".gitkeep").touch()
    (evidence_dir / "visible.log").write_text("visible", encoding="utf-8")

    result = runner.invoke(
        app,
        ["menu", str(evidence_dir)],
        input="q\n",
        env={"XDG_CONFIG_HOME": str(tmp_path / "config")},
    )

    assert result.exit_code == 0
    assert "visible.log" in result.output
    assert ".gitkeep" not in result.output
