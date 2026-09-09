"""Shared, dependency-free helpers for the built-in text analyzers."""

from __future__ import annotations

import codecs
import re
import time
from collections.abc import Iterator
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

from fieldtrace.core.models import AnalysisContext, Diagnostic, EvidenceRef, Progress

PROBE_LIMIT = 65_536
PROGRESS_INTERVAL = 1_000
SUPPORTED_ENCODINGS = frozenset(
    {"utf-8", "utf-8-sig", "utf-16", "utf-16-le", "utf-16-be", "cp949", "euc-kr"}
)

_IPV4_RE = re.compile(
    r"(?<![\w.])(?:25[0-5]|2[0-4]\d|1?\d?\d)"
    r"(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}(?![\w.])"
)
_IPV6_CANDIDATE_RE = re.compile(r"(?<![\w:])(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f:]{0,4}(?![\w:])")
_DOMAIN_TOKEN_RE = re.compile(r"[A-Za-z0-9.-]+")
_DEFAULT_FLAG_PREFIXES = ("FLAG", "flag", "CTF", "ctf")
_QUOTED_RE = re.compile(r"""(?P<quote>["'])(?P<value>[^"'\r\n]{4,256})(?P=quote)""")


@dataclass(slots=True)
class TextLine:
    number: int
    text: str
    raw_bytes: int


def bounded_sample(sample: bytes) -> bytes:
    """Never inspect more than the documented probe window."""

    return sample[:PROBE_LIMIT]


def text_encoding(sample: bytes) -> tuple[str | None, str]:
    """Return a safe automatic encoding and a human-readable reason."""

    head = bounded_sample(sample)
    if head.startswith(b"\xef\xbb\xbf"):
        return "utf-8-sig", "UTF-8 BOM"
    if head.startswith((b"\xff\xfe", b"\xfe\xff")):
        return "utf-16", "UTF-16 BOM"
    if not head:
        return "utf-8", "empty or UTF-8 text"
    if b"\x00" in head:
        return None, "NUL bytes without a UTF-16 BOM"
    try:
        # A bounded probe can end in the middle of a valid multibyte character.
        codecs.getincrementaldecoder("utf-8")(errors="strict").decode(head, final=False)
    except UnicodeDecodeError:
        return None, "not valid UTF-8 and no supported BOM"
    control_count = sum(byte < 32 and byte not in b"\t\n\r\f\b" for byte in head)
    if control_count / len(head) > 0.02:
        return None, "binary-like control bytes"
    return "utf-8", "valid UTF-8 text"


def decode_sample(sample: bytes, encoding: str) -> str:
    """Decode a possibly cut-off probe sample without masking interior errors."""

    decoder = codecs.getincrementaldecoder(encoding)(errors="strict")
    return decoder.decode(bounded_sample(sample), final=False)


def normalize_encoding(value: str) -> str:
    """Return one reviewed encoding name instead of accepting arbitrary codecs."""

    normalized = value.strip().casefold().replace("_", "-")
    aliases = {"utf8": "utf-8", "utf8-sig": "utf-8-sig", "euckr": "euc-kr"}
    normalized = aliases.get(normalized, normalized)
    if normalized not in SUPPORTED_ENCODINGS:
        choices = ", ".join(sorted(SUPPORTED_ENCODINGS))
        raise ValueError(f"지원하지 않는 텍스트 인코딩입니다: {value} (가능: {choices})")
    return normalized


def select_text_encoding(sample: bytes, requested: str | None = None) -> tuple[str | None, str]:
    """Select an automatic or explicit encoding while still refusing binary controls."""

    if requested is None:
        return text_encoding(sample)
    try:
        encoding = normalize_encoding(requested)
        decoded = decode_sample(sample, encoding)
    except (LookupError, UnicodeDecodeError, ValueError) as exc:
        return None, f"선택한 인코딩 {requested} 디코딩 실패: {exc}"
    controls = sum(character not in "\t\n\r\f\b" and ord(character) < 32 for character in decoded)
    if decoded and controls / len(decoded) > 0.02:
        return None, f"선택한 인코딩 {encoding}에서 바이너리 제어 문자가 너무 많음"
    return encoding, f"사용자가 {encoding} 인코딩을 지정함"


def looks_like_text(sample: bytes) -> bool:
    return text_encoding(sample)[0] is not None


def iter_text_lines(
    path: Path,
    max_line_bytes: int,
    encoding_override: str | None = None,
) -> Iterator[TextLine | Diagnostic]:
    """Stream supported text without ever materializing an oversized line."""

    safe_limit = max(256, max_line_bytes)
    try:
        with path.open("rb") as stream:
            sample = stream.read(PROBE_LIMIT)
            encoding, reason = select_text_encoding(sample, encoding_override)
            if encoding is None:
                yield Diagnostic(
                    level="error",
                    stage="decode",
                    message=f"텍스트 인코딩을 안전하게 결정할 수 없습니다: {reason}",
                    next_action=(
                        "UTF-8 또는 BOM이 있는 UTF-16으로 변환하거나 형식을 수동 확인하세요."
                    ),
                )
                return
            stream.seek(0)
            # TextIOWrapper.readline(size) bounds decoded characters and correctly
            # handles either UTF-16 byte order. The byte-size check below remains
            # authoritative for the configured limit.
            import io

            text_stream = io.TextIOWrapper(stream, encoding=encoding, errors="strict", newline="")
            multibyte = encoding.startswith("utf-16") or encoding in {"cp949", "euc-kr"}
            char_limit = max(128, safe_limit // 2) if multibyte else safe_limit
            if encoding == "utf-16":
                size_encoding = "utf-16-le"
            elif encoding == "utf-8-sig":
                size_encoding = "utf-8"
            else:
                size_encoding = encoding
            line_number = 0
            while True:
                try:
                    text = text_stream.readline(char_limit + 1)
                except UnicodeDecodeError as exc:
                    yield Diagnostic(
                        level="warning",
                        stage="decode",
                        message=f"{line_number + 1}번 줄 부근을 {encoding}로 해석하지 못했습니다.",
                        next_action="원본 인코딩을 확인한 뒤 지원 인코딩으로 변환하세요.",
                        exception=repr(exc),
                    )
                    return
                if not text:
                    break
                line_number += 1
                raw_size = len(text.encode(size_encoding))
                complete = text.endswith(("\n", "\r"))
                if raw_size > safe_limit or (len(text) > char_limit and not complete):
                    try:
                        while text and not complete:
                            text = text_stream.readline(char_limit + 1)
                            complete = text.endswith(("\n", "\r"))
                    except UnicodeDecodeError as exc:
                        yield Diagnostic(
                            level="warning",
                            stage="decode",
                            message=(
                                f"{line_number}번의 긴 줄을 버리는 중 디코딩 오류가 발생했습니다."
                            ),
                            next_action="원본 인코딩을 확인하세요.",
                            exception=repr(exc),
                        )
                        return
                    yield Diagnostic(
                        level="warning",
                        stage="read",
                        message=(
                            f"{line_number}번 줄이 {safe_limit}바이트 제한을 넘어 생략되었습니다."
                        ),
                        next_action="필요하면 max_line_bytes 설정을 늘려 다시 분석하세요.",
                    )
                    continue
                yield TextLine(line_number, text.rstrip("\r\n"), raw_size)
    except OSError as exc:
        yield Diagnostic(
            level="error",
            stage="read",
            message=f"입력 파일을 읽지 못했습니다: {exc}",
            next_action="경로와 읽기 권한을 확인하세요.",
            exception=repr(exc),
        )


def preview(text: str, limit: int) -> tuple[str, bool]:
    safe_limit = max(1, limit)
    if len(text) <= safe_limit:
        return text, False
    return text[:safe_limit], True


def line_evidence(context: AnalysisContext, line_number: int, text: str) -> EvidenceRef:
    value, truncated = preview(text, context.budget.max_preview_chars)
    return EvidenceRef(
        source_id=context.source_id,
        kind="text_line",
        locator=f"line:{line_number}",
        preview=value,
        truncated=truncated,
    )


def requested(context: AnalysisContext, *names: str) -> bool:
    """An empty task set means the profile-selected analyzer runs all of its basics."""

    selected = {item.casefold().replace("-", "_") for item in context.selected_tasks}
    if not selected or selected & {"all", "full", "quick"}:
        return True
    return bool(selected.intersection(name.casefold().replace("-", "_") for name in names))


def limit_reason(context: AnalysisContext, processed: int) -> str | None:
    if context.cancel.is_set():
        return "cancelled"
    if context.budget.max_records is not None and processed >= context.budget.max_records:
        return "max_records"
    if context.budget.max_seconds is not None:
        elapsed = time.monotonic() - context.started_at
        if elapsed >= context.budget.max_seconds:
            return "max_seconds"
    return None


def limit_diagnostic(reason: str, processed: int) -> Diagnostic:
    if reason == "cancelled":
        return Diagnostic(
            level="warning",
            stage="cancel",
            message=f"사용자 취소 신호로 {processed:,}개 레코드 처리 후 중단했습니다.",
            next_action="저장된 부분 결과를 확인하거나 다시 실행하세요.",
        )
    label = "레코드 수" if reason == "max_records" else "실행 시간"
    return Diagnostic(
        level="warning",
        stage="budget",
        message=f"{label} 예산에 도달해 {processed:,}개 레코드에서 분석을 멈췄습니다.",
        next_action="전체 결과가 필요하면 full 프로필이나 더 큰 예산으로 다시 실행하세요.",
    )


def progress(stage: str, processed: int, message: str = "") -> Progress:
    return Progress(stage=stage, processed=processed, total=None, message=message)


def extract_ipv4(text: str) -> list[str]:
    if "." not in text:
        return []
    return list(dict.fromkeys(_IPV4_RE.findall(text)))


def extract_ipv6(text: str) -> list[str]:
    # Validate candidates to keep the deliberately broad regular expression honest.
    import ipaddress

    if ":" not in text:
        return []
    values: list[str] = []
    for candidate in _IPV6_CANDIDATE_RE.findall(text):
        try:
            value = str(ipaddress.IPv6Address(candidate))
        except ipaddress.AddressValueError:
            continue
        if value not in values:
            values.append(value)
    return values


def extract_domains(text: str) -> list[str]:
    if "." not in text:
        return []
    values: list[str] = []
    for match in _DOMAIN_TOKEN_RE.finditer(text):
        candidate = match.group(0).strip(".").casefold()
        if not candidate or len(candidate) > 253 or "." not in candidate:
            continue
        labels = candidate.split(".")
        if (
            len(labels) < 2
            or not 2 <= len(labels[-1]) <= 63
            or not labels[-1].isalpha()
            or any(
                not label
                or len(label) > 63
                or label.startswith("-")
                or label.endswith("-")
                for label in labels
            )
        ):
            continue
        if candidate not in values:
            values.append(candidate)
    return values


@lru_cache(maxsize=32)
def _flag_pattern(prefixes: tuple[str, ...]) -> re.Pattern[str]:
    ordered = sorted(set(prefixes), key=len, reverse=True)
    alternatives = "|".join(re.escape(prefix) for prefix in ordered)
    return re.compile(rf"(?:{alternatives})\{{[^\r\n{{}}]{{1,512}}\}}", re.IGNORECASE)


def extract_flags(text: str, prefixes: tuple[str, ...] = _DEFAULT_FLAG_PREFIXES) -> list[str]:
    if not prefixes or "{" not in text:
        return []
    return list(dict.fromkeys(_flag_pattern(prefixes).findall(text)))


def extract_literals(text: str) -> list[str]:
    if '"' not in text and "'" not in text:
        return []
    values = []
    for match in _QUOTED_RE.finditer(text):
        value = match.group("value")
        if value not in values:
            values.append(value)
    return values
