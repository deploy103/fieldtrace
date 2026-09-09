from __future__ import annotations

import json
from pathlib import Path

from rich.console import Console

from fieldtrace.core.models import AnalysisSummary, Diagnostic, EvidenceRef, Finding
from fieldtrace.reports import ReportBundle, export_report, protect_csv_cell
from fieldtrace.ui.menu import DetectionView, ResultView, run_menu
from fieldtrace.ui.menus import (
    ANALYSIS_TASKS,
    MenuStatus,
    TaskOption,
    choose_analysis_mode,
    choose_files,
    choose_result_action,
    choose_source_format,
)
from fieldtrace.ui.presentation import render_error, render_result
from fieldtrace.ui.safety import normalize_pasted_path, strip_paired_quotes, windows_path_to_wsl


def _answers(*values: str):
    iterator = iter(values)
    return lambda _prompt: next(iterator)


def test_path_quotes_spaces_korean_and_wsl_conversion(tmp_path: Path) -> None:
    path = tmp_path / "한글 증거 파일.log"
    path.write_text("evidence", encoding="utf-8")

    assert strip_paired_quotes(f"  '{path}'  ") == str(path)
    assert normalize_pasted_path(f'"{path}"') == path
    assert windows_path_to_wsl(r"C:\Users\분석\증거.log", running_on_wsl=False).startswith("C:")
    assert (
        windows_path_to_wsl(r"C:\Users\분석\증거.log", running_on_wsl=True)
        == "/mnt/c/Users/분석/증거.log"
    )


def test_menu_enter_is_quick_and_80_column_output() -> None:
    console = Console(width=80, record=True, force_terminal=False, color_system=None)

    result = choose_analysis_mode(input_fn=_answers(""), console=console)

    assert result.status is MenuStatus.SELECTED
    assert result.value == "quick"
    assert max(map(len, console.export_text().splitlines())) <= 80


def test_file_menu_selects_quoted_korean_path(tmp_path: Path) -> None:
    path = tmp_path / "한글 증거 파일.log"
    path.write_text("evidence", encoding="utf-8")
    console = Console(width=80, record=True, force_terminal=False, color_system=None)

    result = choose_files(tmp_path, input_fn=_answers("p", f'"{path}"'), console=console)

    assert result.status is MenuStatus.SELECTED
    assert result.value is not None
    assert result.value.paths == (path,)


def test_file_menu_hides_gitkeep_placeholder(tmp_path: Path) -> None:
    (tmp_path / ".gitkeep").touch()
    evidence = tmp_path / "evidence.log"
    evidence.write_text("evidence", encoding="utf-8")
    console = Console(width=80, record=True, force_terminal=False, color_system=None)

    result = choose_files(tmp_path, input_fn=_answers("1"), console=console)

    assert result.status is MenuStatus.SELECTED
    assert result.value is not None and result.value.paths == (evidence,)
    assert ".gitkeep" not in console.export_text()


def test_file_menu_runs_troubleshooting_without_leaving_browser(tmp_path: Path) -> None:
    calls = 0

    def troubleshoot() -> tuple[dict[str, object], ...]:
        nonlocal calls
        calls += 1
        return (
            {
                "name": "SQLite 결과 저장",
                "ok": False,
                "required": True,
                "detail": "잠금 상태",
                "next_action": "다른 작업을 닫으세요",
            },
        )

    console = Console(width=80, record=True, force_terminal=False, color_system=None)
    result = choose_files(
        tmp_path,
        input_fn=_answers("d", "q"),
        console=console,
        troubleshooting_provider=troubleshoot,
    )

    assert result.status is MenuStatus.QUIT
    assert calls == 1
    output = console.export_text()
    assert "문제 해결 · 환경 진단" in output
    assert "다른 작업을 닫으세요" in output


def test_unimplemented_detail_action_is_disabled() -> None:
    console = Console(width=80, record=True, force_terminal=False, color_system=None)

    result = choose_result_action(
        detail_available=False,
        input_fn=_answers("3", "6"),
        console=console,
    )

    assert result.status is MenuStatus.SELECTED and result.value == "quit"
    output = console.export_text()
    assert "상세 분석 — 준비 중" in output
    assert "현재 사용할 수 없습니다" in output


def test_manual_format_menu_includes_evtx() -> None:
    result = choose_source_format(input_fn=_answers("5"))

    assert result.status is MenuStatus.SELECTED
    assert result.value == "evtx"


class DetailMenuController:
    def __init__(self, directory: Path) -> None:
        self.default_directory = directory
        self.selected: frozenset[str] = frozenset()

    def list(self, directory: Path):  # type: ignore[no-untyped-def]
        return tuple(directory.iterdir())

    def detect(self, paths):  # type: ignore[no-untyped-def]
        return {path: DetectionView("pcap", "magic", confidence=1.0) for path in paths}

    def tasks(self, paths, detections):  # type: ignore[no-untyped-def]
        del paths, detections
        return ANALYSIS_TASKS

    def has_results(self, paths):  # type: ignore[no-untyped-def]
        del paths
        return False

    def analyze(self, paths, **_kwargs):  # type: ignore[no-untyped-def]
        del paths
        return ResultView(AnalysisSummary(self.default_directory), detail_available=True)

    def detail_tasks(self):  # type: ignore[no-untyped-def]
        return (TaskOption("tcp_streams", "TCP 대화 재조립 보기"),)

    def analyze_detail(self, selected_tasks):  # type: ignore[no-untyped-def]
        self.selected = selected_tasks
        return ResultView(AnalysisSummary(self.default_directory), detail_available=True)

    def open_results(self, paths):  # type: ignore[no-untyped-def]
        del paths
        raise AssertionError

    def search(self, text):  # type: ignore[no-untyped-def]
        del text
        return ()

    def timeline(self):  # type: ignore[no-untyped-def]
        return ()

    def evidence(self, item):  # type: ignore[no-untyped-def]
        del item
        return None

    def report(self, format):  # type: ignore[no-untyped-def]
        del format
        raise AssertionError


def test_result_menu_runs_available_detail_analysis(tmp_path: Path) -> None:
    (tmp_path / "capture.pcap").write_bytes(b"pcap")
    controller = DetailMenuController(tmp_path)
    console = Console(width=80, record=True, force_terminal=False, color_system=None)

    result = run_menu(
        controller,
        input_fn=_answers("1", "", "3", "1", "6"),
        console=console,
    )

    assert result == 0
    assert controller.selected == frozenset({"tcp_streams"})
    assert "TCP 대화 재조립 보기" in console.export_text()


def test_file_result_diagnostic_and_error_fit_80_columns(tmp_path: Path) -> None:
    long_name = "아주 긴 한글 증거 파일 이름과 공백 " * 4 + ".log"
    evidence_path = tmp_path / long_name
    evidence_path.write_text("FLAG{width}", encoding="utf-8")
    console = Console(width=80, record=True, force_terminal=False, color_system=None)

    selection = choose_files(tmp_path, input_fn=_answers("q"), console=console)
    assert selection.status is MenuStatus.QUIT
    finding = Finding(
        rule_id="width",
        title="긴 후보 제목 " * 12,
        observation="관측 내용 " * 30,
        interpretation="원문 확인 필요",
        confidence="medium",
        evidence=EvidenceRef(1, "text_line", "line:123", "[bold]\x1b[31m원문[/bold]"),
    )
    diagnostic = Diagnostic(
        "warning",
        "parse",
        "아주 긴 진단 이유 " * 20,
        "다음 행동을 확인하세요 " * 10,
    )
    render_result(
        AnalysisSummary(tmp_path, events=1, findings=1, failures=1, partial=True),
        (finding,),
        (diagnostic,),
        console=console,
    )
    render_error(
        "형식 감지",
        "제어문자\x1b[2J와 [bold]마크업[/bold]을 포함한 긴 실패 이유 " * 5,
        "파일을 다시 선택하세요",
        console=console,
    )

    output = console.export_text()
    assert "\x1b" not in output
    assert max(len(line) for line in output.splitlines()) <= 80


def test_report_json_preserves_raw_and_csv_prevents_formula(tmp_path: Path) -> None:
    bundle = ReportBundle.build(
        case={"id": "case"},
        findings=[
            {
                "id": 1,
                "title": "candidate",
                "observation": "observed",
                "evidence": {
                    "source_id": 1,
                    "kind": "text_line",
                    "locator": "line:1",
                    "preview": "=cmd|' /C calc'!A0",
                    "truncated": False,
                },
            }
        ],
        artifacts=[
            {
                "path": "/case/derived/object.bin",
                "kind": "http.object",
                "sha256": "abc",
                "analyzer": "pcap",
                "evidence_locator": "frame:9",
            }
        ],
        correlations=[
            {
                "kind": "ip",
                "value": "192.0.2.9",
                "source_ids": [1, 2],
                "occurrences": 2,
                "interpretation": "인과관계 아님",
            }
        ],
    )
    json_path = export_report(bundle, tmp_path / "report.json", "json")
    csv_path = export_report(bundle, tmp_path / "report.csv", "csv")

    assert json.loads(json_path.read_text(encoding="utf-8"))["findings"][0]["evidence"][
        "preview"
    ].startswith("=")
    assert "'=cmd" in csv_path.read_text(encoding="utf-8-sig")
    assert protect_csv_cell(" harmless") == " harmless"


def test_html_report_is_self_contained_searchable_and_escapes_evidence(
    tmp_path: Path,
) -> None:
    malicious = '<script src="https://attacker.invalid/x.js">alert(1)</script>'
    bundle = ReportBundle.build(
        case={"id": "case"},
        events=[
            {
                "id": 7,
                "category": "evtx.record",
                "summary": "원문 검토",
                "evidence_kind": "evtx",
                "evidence_locator": "channel:Security;record:77",
                "evidence_preview": malicious,
            }
        ],
        findings=[
            {
                "id": 1,
                "title": "후보 <검토>",
                "observation": "FLAG{html}",
                "evidence": {
                    "source_id": 1,
                    "locator": "line:2",
                    "preview": malicious,
                },
            }
        ],
        artifacts=[
            {
                "path": "/case/derived/object.bin",
                "kind": "http.object",
                "sha256": "abc",
                "analyzer": "pcap",
                "evidence_locator": "frame:9",
            }
        ],
        correlations=[
            {
                "kind": "ip",
                "value": "192.0.2.9",
                "source_ids": [1, 2],
                "occurrences": 2,
                "interpretation": "인과관계 아님",
            }
        ],
    )

    path = export_report(bundle, tmp_path / "report.html", "html")
    html = path.read_text(encoding="utf-8")

    assert "id=report-search" in html
    assert "channel:Security;record:77" in html
    assert "&lt;script src=&quot;https://attacker.invalid/x.js&quot;&gt;" in html
    assert malicious not in html
    assert '<script src="https://attacker.invalid/x.js">' not in html
    assert "/case/derived/object.bin" in html
    assert "192.0.2.9" in html
