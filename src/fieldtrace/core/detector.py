"""Bounded, content-first input format detection."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from .models import Analyzer, ProbeMetadata, ProbeResult, SourceFormat

SAMPLE_BYTES = 65_536
_PCAP_MAGICS = {
    b"\xa1\xb2\xc3\xd4",
    b"\xd4\xc3\xb2\xa1",
    b"\xa1\xb2\x3c\x4d",
    b"\x4d\x3c\xb2\xa1",
}
_PCAPNG_MAGIC = b"\x0a\x0d\x0d\x0a"
_WEB_LINE = re.compile(
    rb"(?m)^(?:\d{1,3}\.){3}\d{1,3}\s+\S+\s+\S+\s+\[[^\]\r\n]+\]\s+\""
    rb"(?:GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH|CONNECT)\s+"
)
_AUTH_MARKERS = (
    b"sshd[",
    b"sudo:",
    b"Accepted password",
    b"Accepted publickey",
    b"Failed password",
)


@dataclass(frozen=True, slots=True)
class DetectionResult:
    format: SourceFormat
    confidence: float
    reason: str
    analyzer: str | None = None
    manual_selection_recommended: bool = False


class FormatDetector:
    def __init__(self, analyzers: tuple[Analyzer, ...] = (), *, sample_bytes: int = SAMPLE_BYTES):
        self.analyzers = analyzers
        self.sample_bytes = sample_bytes

    def detect(
        self, path: Path | str, *, forced_type: SourceFormat | str | None = None
    ) -> DetectionResult:
        input_path = Path(path).expanduser().resolve()
        stat = input_path.stat()
        if not input_path.is_file():
            raise ValueError(f"일반 파일이 아닙니다: {input_path}")
        if forced_type is not None:
            try:
                selected = (
                    forced_type
                    if isinstance(forced_type, SourceFormat)
                    else SourceFormat(forced_type)
                )
            except ValueError as exc:
                valid = ", ".join(
                    item.value for item in SourceFormat if item is not SourceFormat.UNKNOWN
                )
                raise ValueError(
                    f"지원하지 않는 형식입니다: {forced_type} (가능: {valid})"
                ) from exc
            return DetectionResult(selected, 1.0, "사용자가 형식을 직접 지정함")
        with input_path.open("rb") as stream:
            sample = stream.read(self.sample_bytes)
        metadata = ProbeMetadata(
            path=input_path, size=stat.st_size, suffix=input_path.suffix.lower()
        )
        candidates = [self._builtin_probe(sample)]
        for analyzer in self.analyzers:
            try:
                result = analyzer.probe(sample, metadata)
            except Exception:
                # A broken optional probe must not make the file unselectable.
                continue
            if result.format in analyzer.formats:
                candidates.append(result)
        best = max(candidates, key=lambda item: item.confidence)
        return DetectionResult(
            format=best.format,
            confidence=max(0.0, min(1.0, best.confidence)),
            reason=best.reason,
            analyzer=best.analyzer,
            manual_selection_recommended=(
                best.format is SourceFormat.UNKNOWN or best.confidence < 0.65
            ),
        )

    @staticmethod
    def _builtin_probe(sample: bytes) -> ProbeResult:
        if sample[:4] in _PCAP_MAGICS:
            return ProbeResult(SourceFormat.PCAP, 1.0, "PCAP magic 값 확인")
        if sample.startswith(_PCAPNG_MAGIC):
            return ProbeResult(SourceFormat.PCAP, 1.0, "PCAPNG section magic 값 확인")
        if not sample:
            return ProbeResult(SourceFormat.GENERIC_TEXT, 0.55, "빈 파일(텍스트로 수동 확인 권장)")
        encoding: str | None = None
        text_sample = sample
        if sample.startswith(b"\xef\xbb\xbf"):
            encoding = "UTF-8 BOM"
            text_sample = sample[3:]
        elif sample.startswith((b"\xff\xfe", b"\xfe\xff")):
            encoding = "UTF-16 BOM"
            try:
                decoded = sample.decode("utf-16")
            except UnicodeDecodeError:
                return ProbeResult(SourceFormat.UNKNOWN, 0.9, "손상된 UTF-16 BOM")
            if any(marker.decode().lower() in decoded.lower() for marker in _AUTH_MARKERS):
                return ProbeResult(
                    SourceFormat.LINUX_AUTH, 0.85, "UTF-16 내용에서 인증 로그 표식 확인"
                )
            return ProbeResult(SourceFormat.GENERIC_TEXT, 0.88, f"{encoding} 텍스트 확인")
        if _WEB_LINE.search(text_sample):
            return ProbeResult(SourceFormat.WEB, 0.95, "Common/Combined 웹 로그 구조 확인")
        lowered = text_sample.lower()
        if any(marker.lower() in lowered for marker in _AUTH_MARKERS):
            return ProbeResult(SourceFormat.LINUX_AUTH, 0.9, "OpenSSH/sudo 로그 표식 확인")
        nul_ratio = sample.count(0) / len(sample)
        control_count = sum(byte < 9 or (13 < byte < 32) for byte in sample)
        if nul_ratio > 0.01 or control_count / len(sample) > 0.05:
            return ProbeResult(
                SourceFormat.UNKNOWN, 0.9, "바이너리 제어 문자가 많아 텍스트로 확정하지 않음"
            )
        try:
            text_sample.decode("utf-8")
        except UnicodeDecodeError:
            return ProbeResult(
                SourceFormat.GENERIC_TEXT,
                0.5,
                "UTF-8이 아닌 텍스트 가능성(인코딩 선택 필요)",
            )
        reason = f"{encoding or 'UTF-8'} 텍스트 확인"
        return ProbeResult(SourceFormat.GENERIC_TEXT, 0.8, reason)
