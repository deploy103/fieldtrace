"""Portable ``input``-based Korean menus.

The functions in this module only collect choices.  They do not access SQLite,
run subprocesses, or start analysis; callers pass their choices to core services.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path

from rich.console import Console
from rich.table import Table
from rich.text import Text

from fieldtrace.ui.safety import normalize_pasted_path, strip_terminal_controls

type InputFunction = Callable[[str], str]


class MenuStatus(StrEnum):
    SELECTED = "selected"
    BACK = "back"
    QUIT = "quit"


@dataclass(frozen=True, slots=True)
class MenuResult[T]:
    status: MenuStatus
    value: T | None = None


@dataclass(frozen=True, slots=True)
class MenuOption[T]:
    label: str
    value: T
    description: str = ""
    available: bool = True
    unavailable_reason: str = ""


@dataclass(frozen=True, slots=True)
class FileChoice:
    paths: tuple[Path, ...]
    directory: Path


@dataclass(frozen=True, slots=True)
class TaskOption:
    key: str
    label: str
    available: bool = True
    reason: str = ""


ANALYSIS_TASKS: tuple[TaskOption, ...] = (
    TaskOption("network_summary", "IP·도메인 요약"),
    TaskOption("http_requests", "HTTP 요청"),
    TaskOption("login_activity", "로그인 성공/실패"),
    TaskOption("executed_commands", "실행 명령"),
    TaskOption("literal_search", "플래그·문자열 찾기"),
)

RESULT_ACTIONS: tuple[MenuOption[str], ...] = (
    MenuOption("검색", "search"),
    MenuOption("시간순 보기", "timeline"),
    MenuOption("상세 분석", "detail"),
    MenuOption("보고서 저장", "report"),
    MenuOption("다른 파일", "other_file"),
    MenuOption("종료", "quit"),
)


def _read(input_fn: InputFunction, prompt: str) -> str | None:
    try:
        return input_fn(prompt).strip()
    except EOFError:
        return "q"
    except KeyboardInterrupt:
        return None


def choose_one[T](
    title: str,
    options: Sequence[MenuOption[T]],
    *,
    default: int | None = None,
    input_fn: InputFunction = input,
    console: Console | None = None,
) -> MenuResult[T]:
    """Choose one numbered option with consistent Enter/0/q behavior."""

    console = console or Console()
    console.print(Text(strip_terminal_controls(title), style="bold"))
    for number, option in enumerate(options, 1):
        suffix = option.description
        if not option.available:
            suffix = f"준비 중: {option.unavailable_reason or '사용할 수 없음'}"
        line = f"{number}. {option.label}"
        if suffix:
            line += f" — {suffix}"
        console.print(
            Text(strip_terminal_controls(line), style="dim" if not option.available else "")
        )
    console.print("0. 뒤로    q. 종료", markup=False)

    while True:
        raw = _read(input_fn, "선택: ")
        if raw is None or raw == "0":
            return MenuResult(MenuStatus.BACK)
        if raw.casefold() == "q":
            return MenuResult(MenuStatus.QUIT)
        if not raw and default is not None:
            raw = str(default)
        if raw.isdigit() and 1 <= int(raw) <= len(options):
            option = options[int(raw) - 1]
            if option.available:
                return MenuResult(MenuStatus.SELECTED, option.value)
            reason = strip_terminal_controls(option.unavailable_reason)
            console.print(Text(f"현재 사용할 수 없습니다: {reason}"))
            continue
        console.print("표시된 번호, 0, q 중 하나를 입력하세요.", markup=False)


def choose_analysis_mode(
    *,
    recommendation: str = "사용 가능한 기본 분석",
    existing_results: bool = False,
    input_fn: InputFunction = input,
    console: Console | None = None,
) -> MenuResult[str]:
    """Choose quick/full/custom/existing; Enter always means quick."""

    options = (
        MenuOption("전체 분석", "full", "사용 가능한 모든 기본 분석"),
        MenuOption("분석 항목 직접 선택", "custom"),
        MenuOption(
            "기존 결과 열기",
            "existing",
            available=existing_results,
            unavailable_reason="저장된 결과가 없습니다",
        ),
    )
    console = console or Console()
    console.print(Text("분석 방법", style="bold"))
    console.print(Text(f"Enter. 추천 빠른 분석 — {strip_terminal_controls(recommendation)}"))
    for index, option in enumerate(options, 1):
        suffix = option.description
        if not option.available:
            suffix = f"준비 중: {option.unavailable_reason}"
        console.print(
            Text(
                f"{index}. {option.label}" + (f" — {suffix}" if suffix else ""),
                style="dim" if not option.available else "",
            )
        )
    console.print("0. 뒤로    q. 종료", markup=False)
    while True:
        raw = _read(input_fn, "선택 [Enter]: ")
        if raw is None or raw == "0":
            return MenuResult(MenuStatus.BACK)
        if raw.casefold() == "q":
            return MenuResult(MenuStatus.QUIT)
        if not raw:
            return MenuResult(MenuStatus.SELECTED, "quick")
        if raw.isdigit() and 1 <= int(raw) <= len(options):
            selected = options[int(raw) - 1]
            if selected.available:
                return MenuResult(MenuStatus.SELECTED, selected.value)
            console.print(f"현재 사용할 수 없습니다: {selected.unavailable_reason}", markup=False)
            continue
        console.print("Enter, 표시된 번호, 0, q 중 하나를 입력하세요.", markup=False)


def choose_custom_tasks(
    tasks: Sequence[TaskOption] = ANALYSIS_TASKS,
    *,
    input_fn: InputFunction = input,
    console: Console | None = None,
) -> MenuResult[frozenset[str]]:
    """Choose multiple available tasks as comma-separated numbers."""

    console = console or Console()
    console.print(Text("분석 항목 직접 선택", style="bold"))
    for index, task in enumerate(tasks, 1):
        note = ""
        if not task.available:
            note = f" — 준비 중: {task.reason or '이 파일에서 지원하지 않음'}"
        console.print(
            Text(f"{index}. {strip_terminal_controls(task.label)}{strip_terminal_controls(note)}"),
            style="dim" if not task.available else "",
        )
    console.print("번호를 쉼표로 구분한 뒤 Enter를 누르세요. 0: 뒤로, q: 종료", markup=False)
    while True:
        raw = _read(input_fn, "항목: ")
        if raw is None or raw == "0":
            return MenuResult(MenuStatus.BACK)
        if raw.casefold() == "q":
            return MenuResult(MenuStatus.QUIT)
        if not raw:
            console.print("분석 항목을 하나 이상 선택하세요.", markup=False)
            continue
        pieces = [piece.strip() for piece in raw.split(",")]
        if not pieces or any(not piece.isdigit() for piece in pieces):
            console.print("예: 1,3,5", markup=False)
            continue
        indexes = {int(piece) for piece in pieces}
        if any(index < 1 or index > len(tasks) for index in indexes):
            console.print("표시된 번호만 입력하세요.", markup=False)
            continue
        unavailable = [tasks[index - 1] for index in indexes if not tasks[index - 1].available]
        if unavailable:
            labels = ", ".join(task.label for task in unavailable)
            console.print(f"선택할 수 없는 항목: {labels}", markup=False)
            continue
        selected = frozenset(tasks[index - 1].key for index in indexes)
        return MenuResult(MenuStatus.SELECTED, selected)


def choose_source_format(
    *,
    detected: str | None = None,
    input_fn: InputFunction = input,
    console: Console | None = None,
) -> MenuResult[str]:
    """Manually select an input format, defaulting to a confident detection."""

    options = (
        MenuOption("일반 텍스트 로그", "text"),
        MenuOption("Apache/Nginx 웹 로그", "web"),
        MenuOption("OpenSSH/sudo 인증 로그", "linux_auth"),
        MenuOption("PCAP/PCAPNG 패킷", "pcap"),
    )
    default = next((i for i, option in enumerate(options, 1) if option.value == detected), None)
    return choose_one(
        "파일 형식 직접 선택",
        options,
        default=default,
        input_fn=input_fn,
        console=console,
    )


def choose_text_encoding(
    *,
    input_fn: InputFunction = input,
    console: Console | None = None,
) -> MenuResult[str]:
    """Choose a reviewed fallback after automatic UTF detection fails."""

    options = (
        MenuOption("CP949 (Windows 한국어)", "cp949", "추천"),
        MenuOption("EUC-KR", "euc-kr"),
        MenuOption("UTF-8", "utf-8"),
        MenuOption("UTF-16 little-endian", "utf-16-le"),
        MenuOption("UTF-16 big-endian", "utf-16-be"),
    )
    return choose_one(
        "텍스트 인코딩 직접 선택",
        options,
        default=1,
        input_fn=input_fn,
        console=console,
    )


def choose_result_action(
    *,
    detail_available: bool = True,
    input_fn: InputFunction = input,
    console: Console | None = None,
) -> MenuResult[str]:
    options = tuple(
        MenuOption(
            option.label,
            option.value,
            option.description,
            option.available and (detail_available or option.value != "detail"),
            "추가 분석 항목이 없습니다" if option.value == "detail" else option.unavailable_reason,
        )
        for option in RESULT_ACTIONS
    )
    return choose_one("결과에서 할 일", options, input_fn=input_fn, console=console)


def _regular_files(directory: Path) -> list[Path]:
    try:
        return sorted(
            (
                entry
                for entry in directory.iterdir()
                if entry.is_file() and entry.name != ".gitkeep"
            ),
            key=lambda entry: entry.name.casefold(),
        )
    except OSError:
        return []


def _file_table(files: Sequence[Path], *, offset: int) -> Table:
    table = Table(show_header=True, header_style="bold", expand=True)
    table.add_column("번호", width=5, no_wrap=True)
    table.add_column("파일명", overflow="fold")
    table.add_column("크기", justify="right", width=11)
    for local_number, path in enumerate(files, 1):
        try:
            size = path.stat().st_size
        except OSError:
            size = 0
        table.add_row(
            str(offset + local_number),
            Text(strip_terminal_controls(path.name)),
            _human_size(size),
        )
    return table


def _human_size(size: int) -> str:
    amount = float(size)
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if amount < 1024 or unit == "TiB":
            return f"{amount:.0f} {unit}" if unit == "B" else f"{amount:.1f} {unit}"
        amount /= 1024
    return f"{size} B"


def choose_files(
    directory: Path,
    *,
    page_size: int = 15,
    input_fn: InputFunction = input,
    console: Console | None = None,
    detected_formats: dict[Path, tuple[str, str]] | None = None,
    file_provider: Callable[[Path], Sequence[Path]] | None = None,
    detection_provider: Callable[[Sequence[Path]], Mapping[Path, object]] | None = None,
) -> MenuResult[FileChoice]:
    """Browse files with pagination, search, paste, and all-file selection.

    ``detected_formats`` may contain ``path: (format, reason)`` entries from the
    core detector.  ``file_provider`` and ``detection_provider`` let a core menu
    controller exclude output paths and perform bounded content detection.
    """

    if page_size < 1:
        raise ValueError("page_size must be positive")
    console = console or Console()
    current = directory
    query = ""
    page = 0
    while True:
        try:
            all_files = list(file_provider(current) if file_provider else _regular_files(current))
        except OSError as error:
            console.print(f"파일 목록 실패: {strip_terminal_controls(error)}", markup=False)
            all_files = []
        all_files = sorted(
            (Path(path) for path in all_files), key=lambda path: path.name.casefold()
        )
        visible = [path for path in all_files if query.casefold() in path.name.casefold()]
        page_count = max(1, (len(visible) + page_size - 1) // page_size)
        page = min(page, page_count - 1)
        start = page * page_size
        current_page = visible[start : start + page_size]
        if detection_provider and current_page:
            try:
                supplied = detection_provider(current_page)
                detected_formats = {
                    Path(path): _detection_pair(detection) for path, detection in supplied.items()
                }
            except Exception as error:  # controller failure is recoverable in the browser
                console.print(f"형식 감지 실패: {strip_terminal_controls(error)}", markup=False)
        console.print(Text(f"파일 선택: {strip_terminal_controls(current)}", style="bold"))
        if current_page:
            if detected_formats:
                table = Table(show_header=True, header_style="bold", expand=True)
                table.add_column("번호", width=5)
                table.add_column("파일명", overflow="fold")
                table.add_column("감지 형식", width=14)
                table.add_column("크기", justify="right", width=11)
                for number, path in enumerate(current_page, start + 1):
                    detected = detected_formats.get(path, ("확인 전", ""))[0]
                    try:
                        size = path.stat().st_size
                    except OSError:
                        size = 0
                    table.add_row(
                        str(number),
                        Text(strip_terminal_controls(path.name)),
                        Text(strip_terminal_controls(detected)),
                        _human_size(size),
                    )
                console.print(table)
            else:
                console.print(_file_table(current_page, offset=start))
        else:
            console.print("표시할 파일이 없습니다.", markup=False)
        console.print(
            f"페이지 {page + 1}/{page_count} · 파일 {len(visible)}개"
            + (f" · 검색: {strip_terminal_controls(query)}" if query else ""),
            markup=False,
        )
        console.print(
            "번호/쉼표: 선택  a: 전체  n: 다음  b: 이전  s: 파일명 검색  p: 경로 붙여넣기",
            markup=False,
        )
        console.print("Enter: 새로고침  0: 뒤로  q: 종료", markup=False)
        raw = _read(input_fn, "선택: ")
        if raw is None or raw == "0":
            return MenuResult(MenuStatus.BACK)
        command = raw.casefold()
        if command == "q":
            return MenuResult(MenuStatus.QUIT)
        if not raw:
            continue
        if command == "n":
            if page + 1 < page_count:
                page += 1
            else:
                console.print("마지막 페이지입니다.", markup=False)
            continue
        if command == "b":
            if page > 0:
                page -= 1
            else:
                console.print("첫 페이지입니다.", markup=False)
            continue
        if command == "s":
            entered = _read(input_fn, "파일명 검색 (Enter: 해제): ")
            if entered is None:
                continue
            if entered.casefold() == "q":
                return MenuResult(MenuStatus.QUIT)
            if entered == "0":
                continue
            query = entered
            page = 0
            continue
        if command == "p":
            entered = _read(input_fn, "파일 또는 폴더 경로 붙여넣기: ")
            if entered is None:
                continue
            if entered.casefold() == "q":
                return MenuResult(MenuStatus.QUIT)
            if entered == "0":
                continue
            try:
                pasted = normalize_pasted_path(entered, cwd=current)
            except (ValueError, OSError) as error:
                console.print(f"경로 확인 실패: {strip_terminal_controls(error)}", markup=False)
                console.print("경로를 확인한 뒤 다시 붙여넣으세요.", markup=False)
                continue
            if pasted.is_dir():
                current = pasted
                page = 0
                query = ""
                continue
            if pasted.is_file():
                return MenuResult(MenuStatus.SELECTED, FileChoice((pasted,), pasted.parent))
            console.print("일반 파일이나 폴더가 아닙니다.", markup=False)
            continue
        if command == "a":
            if visible:
                return MenuResult(MenuStatus.SELECTED, FileChoice(tuple(visible), current))
            console.print("선택할 파일이 없습니다.", markup=False)
            continue
        pieces = [piece.strip() for piece in raw.split(",")]
        if all(piece.isdigit() for piece in pieces):
            indexes = list(dict.fromkeys(int(piece) for piece in pieces))
            if indexes and all(1 <= index <= len(visible) for index in indexes):
                return MenuResult(
                    MenuStatus.SELECTED,
                    FileChoice(tuple(visible[index - 1] for index in indexes), current),
                )
        console.print("표시된 번호나 안내된 문자를 입력하세요.", markup=False)


def _detection_pair(value: object) -> tuple[str, str]:
    if isinstance(value, tuple) and len(value) >= 2:
        return str(value[0]), str(value[1])
    if isinstance(value, Mapping):
        return str(value.get("format", value.get("detected_format", "확인 전"))), str(
            value.get("reason", value.get("detection_reason", ""))
        )
    return str(getattr(value, "format", getattr(value, "detected_format", "확인 전"))), str(
        getattr(value, "reason", getattr(value, "detection_reason", ""))
    )


def available_tasks(
    supported: Iterable[str], tasks: Sequence[TaskOption] = ANALYSIS_TASKS
) -> tuple[TaskOption, ...]:
    """Mark tasks unavailable using analyzer capability keys from core."""

    supported_keys = frozenset(supported)
    return tuple(
        TaskOption(
            task.key,
            task.label,
            task.available and task.key in supported_keys,
            task.reason or "선택한 파일 형식에서 지원하지 않음",
        )
        for task in tasks
    )
