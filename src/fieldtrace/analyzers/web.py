"""Apache/Nginx Common and Combined access-log analyzer."""

from __future__ import annotations

import re
from collections import Counter
from collections.abc import Iterator
from datetime import UTC, datetime
from ipaddress import ip_address
from urllib.parse import unquote

from fieldtrace.analyzers._common import (
    PROGRESS_INTERVAL,
    bounded_sample,
    decode_sample,
    extract_flags,
    iter_text_lines,
    limit_diagnostic,
    limit_reason,
    line_evidence,
    progress,
    requested,
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

_ACCESS_RE = re.compile(
    r"^(?P<host>\S+) (?P<ident>\S+) (?P<user>\S+) \[(?P<time>[^\]]+)\] "
    r'"(?P<request>[^"]*)" (?P<status>\d{3}) (?P<size>\d+|-)'
    r'(?: "(?P<referer>[^"]*)" "(?P<agent>[^"]*)")?\s*$'
)
_REQUEST_RE = re.compile(r"^(?P<method>[A-Za-z]+)\s+(?P<uri>\S+)\s+(?P<protocol>HTTP/\d(?:\.\d)?)$")


def _parse_timestamp(raw: str) -> tuple[str | None, str]:
    try:
        parsed = datetime.strptime(raw, "%d/%b/%Y:%H:%M:%S %z")
    except ValueError:
        return None, "unknown"
    return parsed.astimezone(UTC).isoformat(), "explicit_offset"


def _top(counter: Counter[str], limit: int = 20) -> list[dict[str, int | str]]:
    return [{"value": value, "count": count} for value, count in counter.most_common(limit)]


def _source_ip(host: str) -> str | None:
    try:
        return str(ip_address(host))
    except ValueError:
        return None


class WebLogAnalyzer:
    name = "web"
    formats = (SourceFormat.WEB,)

    def probe(self, sample: bytes, metadata: ProbeMetadata) -> ProbeResult:
        inspected = bounded_sample(sample)
        encoding, reason = text_encoding(inspected)
        if encoding is None:
            return ProbeResult(SourceFormat.UNKNOWN, 0.0, reason, self.name)
        try:
            decoded = decode_sample(inspected, encoding)
        except UnicodeDecodeError:
            return ProbeResult(SourceFormat.UNKNOWN, 0.0, "지원 텍스트 디코딩 실패", self.name)
        nonempty = [line for line in decoded.splitlines()[:40] if line.strip()]
        matches = sum(_ACCESS_RE.match(line) is not None for line in nonempty)
        if matches:
            ratio = matches / len(nonempty)
            return ProbeResult(
                SourceFormat.WEB,
                min(0.99, 0.72 + ratio * 0.27),
                f"Apache/Nginx Common 또는 Combined 형식 {matches}/{len(nonempty)}줄 일치",
                self.name,
            )
        suffix_clue = metadata.suffix.casefold() in {".access", ".log"}
        confidence = 0.18 if suffix_clue else 0.0
        return ProbeResult(
            SourceFormat.UNKNOWN,
            confidence,
            "웹 접근 로그 내용 패턴이 확인되지 않음",
            self.name,
        )

    def capabilities(self, environment: Environment) -> Capability:
        del environment
        return Capability(
            available=True,
            reason="Apache/Nginx Common/Combined 스트리밍 분석 사용 가능",
            features=("network_summary", "http_requests", "literal_search"),
        )

    def analyze(self, context: AnalysisContext) -> Iterator[AnalysisItem]:
        processed = 0
        parsed_count = 0
        unsupported = 0
        by_ip: Counter[str] = Counter()
        by_path: Counter[str] = Counter()
        by_status: Counter[str] = Counter()
        methods: Counter[str] = Counter()
        want_web = requested(
            context,
            "network_summary",
            "http_requests",
            "http",
            "web",
            "ip_domain",
            "network",
        )
        want_flags = requested(
            context, "literal_search", "flags", "flag", "strings", "literal", "literals"
        )
        yield progress("web", 0, "웹 접근 로그를 읽는 중")

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
            if not item.text.strip():
                continue
            evidence = line_evidence(context, item.number, item.text)
            match = _ACCESS_RE.match(item.text)
            request_match = _REQUEST_RE.match(match.group("request")) if match else None
            if match is None or request_match is None:
                unsupported += 1
                yield Event(
                    category="web.unparsed",
                    summary="지원 웹 로그 형식으로 해석하지 못한 원문",
                    evidence=evidence,
                    fields={"raw_preserved": True},
                )
            else:
                parsed_count += 1
                host = match.group("host")
                method = request_match.group("method").upper()
                uri_raw = request_match.group("uri")
                uri_decoded = unquote(uri_raw, errors="replace")
                status = match.group("status")
                size_raw = match.group("size")
                timestamp_raw = match.group("time")
                timestamp_utc, timezone_status = _parse_timestamp(timestamp_raw)
                by_ip[host] += 1
                by_path[uri_decoded.split("?", 1)[0]] += 1
                by_status[status] += 1
                methods[method] += 1
                if want_web or want_flags:
                    yield Event(
                        category="web.request",
                        summary=f"{host} {method} {uri_decoded} → {status}",
                        evidence=evidence,
                        timestamp_raw=timestamp_raw,
                        timestamp_utc=timestamp_utc,
                        timezone_status=timezone_status,
                        src_ip=_source_ip(host),
                        user=None if match.group("user") == "-" else match.group("user"),
                        fields={
                            "method": method,
                            "uri_raw": uri_raw,
                            "uri_decoded": uri_decoded,
                            "protocol": request_match.group("protocol"),
                            "status": int(status),
                            "bytes": None if size_raw == "-" else int(size_raw),
                            "ident": match.group("ident"),
                            "referer": match.group("referer"),
                            "user_agent": match.group("agent"),
                        },
                    )
                if timestamp_utc is None:
                    yield Diagnostic(
                        level="warning",
                        stage="timestamp",
                        message=f"{item.number}번 줄의 시각 또는 오프셋을 해석하지 못했습니다.",
                        next_action="원문 시각 형식을 확인하세요.",
                    )
            if want_flags:
                flag_text = item.text
                if match is not None and request_match is not None:
                    flag_text = f"{flag_text}\n{uri_decoded}"
                for value in extract_flags(flag_text):
                    yield Finding(
                        rule_id="web.flag_candidate",
                        title="웹 로그의 플래그 형태 문자열 후보",
                        observation=f"플래그 형태 문자열을 관측했습니다: {value}",
                        interpretation=(
                            "요청 값에 포함된 후보이며 정답 여부는 원문 문맥 확인이 필요합니다."
                        ),
                        confidence="medium",
                        evidence=evidence,
                        fields={"value": value},
                    )
            if processed % PROGRESS_INTERVAL == 0:
                yield progress("web", processed, f"요청 {parsed_count:,}개 해석")

        ratio = unsupported / (parsed_count + unsupported) if parsed_count + unsupported else 0.0
        yield Finding(
            rule_id="web.summary",
            title="웹 요청 집계",
            observation=(
                f"비어 있지 않은 {parsed_count + unsupported:,}줄 중 {parsed_count:,}줄을 해석했고 "
                f"{unsupported:,}줄({ratio:.1%})은 지원 형식과 일치하지 않았습니다."
            ),
            interpretation="요청 빈도 요약이며 비정상 행위나 침입을 확정하지 않습니다.",
            confidence="high",
            fields={
                "processed_lines": processed,
                "parsed": parsed_count,
                "unsupported": unsupported,
                "unsupported_ratio": ratio,
                "top_ips": _top(by_ip),
                "top_paths": _top(by_path),
                "statuses": _top(by_status),
                "methods": _top(methods),
            },
        )
        if unsupported:
            yield Diagnostic(
                level="warning",
                stage="parse",
                message=f"지원하지 않는 웹 로그 형식 비율: {ratio:.1%} ({unsupported:,}줄)",
                next_action="미해석 줄은 원문으로 보존되었습니다. generic text 분석도 확인하세요.",
            )
        yield progress("web", processed, "웹 로그 분석 완료")
