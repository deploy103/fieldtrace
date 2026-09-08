"""Structured offline readiness diagnostics."""

from __future__ import annotations

import importlib.metadata
import shutil
import sys
import tempfile
from dataclasses import dataclass
from threading import Event

from .config import RuntimeConfig
from .models import Environment
from .runner import ExternalToolError, SafeExternalRunner


@dataclass(frozen=True, slots=True)
class DoctorCheck:
    name: str
    ok: bool
    required: bool
    detail: str
    next_action: str = ""


@dataclass(frozen=True, slots=True)
class DoctorResult:
    checks: tuple[DoctorCheck, ...]
    environment: Environment

    @property
    def ready(self) -> bool:
        return all(check.ok for check in self.checks if check.required)

    @property
    def degraded(self) -> bool:
        return any(not check.ok for check in self.checks if not check.required)


_TSHARK_FIELDS = (
    "frame.number",
    "frame.time_epoch",
    "frame.protocols",
    "ip.src",
    "ip.dst",
    "ipv6.src",
    "ipv6.dst",
    "tcp.srcport",
    "tcp.dstport",
    "udp.srcport",
    "udp.dstport",
    "dns.qry.name",
    "http.request.method",
    "http.host",
    "http.request.uri",
    "_ws.col.protocol",
)


def detect_environment(*, runner: SafeExternalRunner | None = None) -> Environment:
    """Detect optional tools without turning their absence into a global error."""

    tshark_path = shutil.which("tshark")
    if tshark_path is None:
        return Environment()
    active_runner = runner or SafeExternalRunner(default_timeout=10, default_max_output=65_536)
    try:
        code, stdout, stderr = active_runner.run(
            [tshark_path, "--version"], cancel=Event(), timeout=10, max_output_bytes=65_536
        )
    except ExternalToolError:
        return Environment(tshark_path=tshark_path)
    lines = (stdout or stderr).splitlines()
    version = lines[0] if code == 0 and lines else None
    return Environment(tshark_path=tshark_path, tshark_version=version)


def run_doctor(config: RuntimeConfig, *, runner: SafeExternalRunner | None = None) -> DoctorResult:
    runner = runner or SafeExternalRunner(
        default_timeout=config.analysis.command_timeout_seconds,
        default_max_output=config.analysis.command_output_bytes,
    )
    checks: list[DoctorCheck] = []
    python_ok = sys.version_info >= (3, 12)
    checks.append(
        DoctorCheck(
            "Python 3.12+",
            python_ok,
            True,
            sys.version.split()[0],
            "Python 3.12 환경에서 실행하세요." if not python_ok else "",
        )
    )
    for distribution in ("typer", "rich"):
        try:
            version = importlib.metadata.version(distribution)
        except importlib.metadata.PackageNotFoundError:
            checks.append(
                DoctorCheck(
                    distribution,
                    False,
                    True,
                    "설치되지 않음",
                    "준비 환경에서 uv sync를 실행하세요.",
                )
            )
        else:
            checks.append(DoctorCheck(distribution, True, True, version))

    case_base = config.paths.cases.expanduser().resolve()
    try:
        case_base.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(prefix=".fieldtrace-write-", dir=case_base):
            pass
    except OSError as exc:
        checks.append(
            DoctorCheck(
                "사례 폴더 쓰기",
                False,
                True,
                str(exc),
                f"쓰기 가능한 사례 경로를 설정하세요: {case_base}",
            )
        )
    else:
        checks.append(DoctorCheck("사례 폴더 쓰기", True, True, str(case_base)))
    try:
        free = shutil.disk_usage(case_base).free
        enough = free >= 100 * 1024 * 1024
        checks.append(
            DoctorCheck(
                "디스크 여유 공간",
                enough,
                True,
                f"{free / (1024**3):.2f} GiB 사용 가능",
                "최소 100 MiB 이상의 여유 공간을 확보하세요." if not enough else "",
            )
        )
    except OSError as exc:
        checks.append(DoctorCheck("디스크 여유 공간", False, True, str(exc)))

    tshark_path = shutil.which("tshark")
    tshark_version: str | None = None
    if tshark_path is None:
        checks.append(
            DoctorCheck(
                "TShark",
                False,
                False,
                "찾을 수 없음(텍스트 분석은 사용 가능)",
                "패킷 분석이 필요하면 준비 환경에서 TShark를 설치하세요.",
            )
        )
    else:
        cancel = Event()
        try:
            code, stdout, stderr = runner.run(
                [tshark_path, "--version"], cancel=cancel, timeout=10, max_output_bytes=65_536
            )
            first_line = (stdout or stderr).splitlines()[0]
            if code != 0:
                raise ExternalToolError(first_line or f"exit {code}")
            tshark_version = first_line
            checks.append(DoctorCheck("TShark", True, False, f"{tshark_path}: {first_line}"))
            code, fields_out, fields_err = runner.run(
                [tshark_path, "-G", "fields"],
                cancel=cancel,
                timeout=30,
                max_output_bytes=32 * 1024 * 1024,
            )
            missing = [name for name in _TSHARK_FIELDS if f"\t{name}\t" not in fields_out]
            checks.append(
                DoctorCheck(
                    "TShark 필드",
                    code == 0 and not missing,
                    False,
                    "필수 필드 확인" if not missing else "누락: " + ", ".join(missing),
                    "다른 지원 TShark 버전을 준비하세요."
                    if missing or (fields_err and code)
                    else "",
                )
            )
        except (ExternalToolError, IndexError) as exc:
            checks.append(
                DoctorCheck(
                    "TShark 실행",
                    False,
                    False,
                    str(exc),
                    "TShark 설치와 실행 권한을 확인하세요.",
                )
            )
    return DoctorResult(tuple(checks), Environment(tshark_path, tshark_version))
