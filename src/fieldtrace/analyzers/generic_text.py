"""Streaming analyzer for safely recognized text evidence."""

from __future__ import annotations

from collections import Counter
from collections.abc import Iterator

from fieldtrace.analyzers._common import (
    PROGRESS_INTERVAL,
    bounded_sample,
    extract_domains,
    extract_flags,
    extract_ipv4,
    extract_ipv6,
    extract_literals,
    iter_text_lines,
    limit_diagnostic,
    limit_reason,
    line_evidence,
    progress,
    requested,
    select_text_encoding,
    text_encoding,
)
from fieldtrace.core.models import (
    AnalysisContext,
    AnalysisItem,
    Capability,
    Diagnostic,
    Environment,
    Event,
    Finding,
    ProbeMetadata,
    ProbeResult,
    SourceFormat,
)


class GenericTextAnalyzer:
    """Extract reproducible, low-risk indicators from UTF text files."""

    name = "generic_text"
    formats = (SourceFormat.GENERIC_TEXT,)

    def probe(self, sample: bytes, metadata: ProbeMetadata) -> ProbeResult:
        inspected = bounded_sample(sample)
        encoding, reason = text_encoding(inspected)
        if encoding is None:
            return ProbeResult(SourceFormat.UNKNOWN, 0.0, reason, self.name)
        confidence = 0.3 if not inspected else 0.58
        suffix = metadata.suffix.casefold()
        if suffix in {".txt", ".log", ".csv", ".json", ".xml"}:
            confidence += 0.08
        return ProbeResult(
            SourceFormat.GENERIC_TEXT,
            min(confidence, 0.66),
            f"{reason}; 내용이 텍스트로 안전하게 판별됨",
            self.name,
        )

    def capabilities(self, environment: Environment) -> Capability:
        del environment
        return Capability(
            available=True,
            reason="Python 스트리밍 텍스트 분석 사용 가능",
            features=("network_summary", "literal_search"),
        )

    def analyze(self, context: AnalysisContext) -> Iterator[AnalysisItem]:
        try:
            with context.input_path.open("rb") as stream:
                sample = stream.read(65_536)
        except OSError as exc:
            yield Diagnostic(
                level="error",
                stage="probe",
                message=f"입력 파일을 열 수 없습니다: {exc}",
                next_action="경로와 읽기 권한을 확인하세요.",
                exception=repr(exc),
            )
            return
        encoding, encoding_reason = select_text_encoding(sample, context.text_encoding)
        if encoding is None:
            yield Diagnostic(
                level="error",
                stage="probe",
                message=(
                    "바이너리이거나 지원 인코딩으로 확인되지 않아 텍스트 분석을 "
                    f"중단했습니다: {encoding_reason}"
                ),
                next_action="파일 형식과 인코딩을 확인하세요.",
            )
            return

        counts: Counter[str] = Counter()
        processed = 0
        emitted = 0
        scan_network = requested(
            context, "network_summary", "ip_domain", "network", "domains", "ips"
        )
        scan_flags = requested(
            context, "literal_search", "flags", "flag", "strings", "literal", "literals"
        )
        yield progress("text", 0, "텍스트를 스트리밍으로 읽는 중")
        for item in iter_text_lines(
            context.input_path,
            context.budget.max_line_bytes,
            context.text_encoding,
        ):
            if isinstance(item, Diagnostic):
                yield item
                continue
            reason = limit_reason(context, processed)
            if reason:
                yield limit_diagnostic(reason, processed)
                break
            processed += 1
            evidence = line_evidence(context, item.number, item.text)
            line_ips: list[str] = []
            line_domains: list[str] = []
            line_flags: list[str] = []
            line_literals: list[str] = []
            if scan_network:
                line_ips = extract_ipv4(item.text) + extract_ipv6(item.text)
                line_domains = extract_domains(item.text)
                for value in line_ips:
                    counts["ip"] += 1
                    emitted += 1
                    yield Event(
                        category="indicator.ip",
                        summary=f"IP 주소 관측: {value}",
                        evidence=evidence,
                        fields={"value": value, "indicator_type": "ip"},
                    )
                for value in line_domains:
                    counts["domain"] += 1
                    emitted += 1
                    yield Event(
                        category="indicator.domain",
                        summary=f"도메인 관측: {value}",
                        evidence=evidence,
                        fields={"value": value, "indicator_type": "domain"},
                    )
            if scan_flags:
                line_flags = extract_flags(item.text)
                line_literals = extract_literals(item.text)
                for value in line_flags:
                    counts["flag"] += 1
                    emitted += 1
                    yield Finding(
                        rule_id="text.flag_candidate",
                        title="플래그 형태 문자열 후보",
                        observation=f"플래그 형태와 일치하는 문자열을 관측했습니다: {value}",
                        interpretation="대회 정답 후보일 수 있으나 원문 문맥 확인이 필요합니다.",
                        confidence="medium",
                        evidence=evidence,
                        severity="info",
                        fields={"value": value},
                    )
                for value in line_literals:
                    if value in line_flags:
                        continue
                    counts["literal"] += 1
                    emitted += 1
                    yield Event(
                        category="indicator.literal",
                        summary=f"인용 문자열 관측: {value}",
                        evidence=evidence,
                        fields={"value": value, "indicator_type": "literal"},
                    )
            # Keeping every bounded line makes the case-wide literal search useful
            # even when no pre-defined indicator pattern matches it.
            yield Event(
                category="text.line",
                summary=f"텍스트 {item.number}번 줄",
                evidence=evidence,
                fields={
                    "line_number": item.number,
                    "ips": line_ips,
                    "domains": line_domains,
                    "flags": line_flags,
                    "literals": line_literals,
                },
            )
            if processed % PROGRESS_INTERVAL == 0:
                yield progress("text", processed, f"후보 {emitted:,}개 관측")
        yield Finding(
            rule_id="text.summary",
            title="텍스트 후보 요약",
            observation=(
                f"{processed:,}개 줄에서 IP {counts['ip']:,}, 도메인 {counts['domain']:,}, "
                f"플래그 형태 {counts['flag']:,}, 인용 문자열 "
                f"{counts['literal']:,}개를 관측했습니다."
            ),
            interpretation="단순 문자열 관측 통계이며 악성 또는 정답임을 뜻하지 않습니다.",
            confidence="high",
            fields={"lines": processed, "emitted": emitted, "counts": dict(counts)},
        )
        yield progress("text", processed, "텍스트 분석 완료")
