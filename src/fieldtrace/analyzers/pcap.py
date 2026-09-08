"""Read-only TShark adapter for PCAP and PCAPNG evidence."""

from __future__ import annotations

import csv
import io
from collections import Counter
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import unquote

from fieldtrace.analyzers._common import (
    PROGRESS_INTERVAL,
    bounded_sample,
    extract_flags,
    limit_diagnostic,
    limit_reason,
    preview,
    progress,
    requested,
)
from fieldtrace.core.models import (
    AnalysisContext,
    AnalysisItem,
    Capability,
    Diagnostic,
    Environment,
    Event,
    EvidenceRef,
    Finding,
    ProbeMetadata,
    ProbeResult,
    SourceFormat,
)

_PCAP_MAGICS = {
    b"\xd4\xc3\xb2\xa1": "PCAP little-endian",
    b"\xa1\xb2\xc3\xd4": "PCAP big-endian",
    b"\x4d\x3c\xb2\xa1": "PCAP nanosecond little-endian",
    b"\xa1\xb2\x3c\x4d": "PCAP nanosecond big-endian",
}
_PCAPNG_MAGIC = b"\x0a\x0d\x0d\x0a"
_OUTPUT_LIMIT_MARKER = "[FieldTrace: 출력 제한으로 나머지 생략]"
_FIELDS = (
    "frame.number",
    "frame.time_epoch",
    "_ws.col.Protocol",
    "frame.protocols",
    "ip.src",
    "ipv6.src",
    "ip.dst",
    "ipv6.dst",
    "tcp.srcport",
    "udp.srcport",
    "tcp.dstport",
    "udp.dstport",
    "dns.qry.name",
    "http.request.method",
    "http.host",
    "http.request.uri",
)


def _first(*values: str) -> str | None:
    for value in values:
        if value:
            return value.split(",", 1)[0]
    return None


def _integer(value: str | None) -> int | None:
    if value is None:
        return None
    try:
        return int(value)
    except ValueError:
        return None


def _timestamp(epoch: str) -> str | None:
    try:
        return datetime.fromtimestamp(float(epoch), tz=UTC).isoformat()
    except (OverflowError, OSError, ValueError):
        return None


def _split_occurrences(value: str) -> list[str]:
    return [part for part in value.split(",") if part]


def _frame_evidence(context: AnalysisContext, frame: str, summary: str) -> EvidenceRef:
    value, truncated = preview(summary, context.budget.max_preview_chars)
    return EvidenceRef(
        source_id=context.source_id,
        kind="pcap_frame",
        locator=f"frame:{frame}",
        preview=value,
        truncated=truncated,
    )


class PcapAnalyzer:
    name = "pcap"
    formats = (SourceFormat.PCAP,)

    def __init__(self, tshark_path: str | None = None) -> None:
        self._tshark_path = tshark_path
        self._tshark_version: str | None = None

    def probe(self, sample: bytes, metadata: ProbeMetadata) -> ProbeResult:
        del metadata
        magic = bounded_sample(sample)[:4]
        if magic == _PCAPNG_MAGIC:
            return ProbeResult(
                SourceFormat.PCAP, 1.0, "PCAPNG section-header magic 확인", self.name
            )
        if magic in _PCAP_MAGICS:
            return ProbeResult(
                SourceFormat.PCAP, 1.0, f"{_PCAP_MAGICS[magic]} magic 확인", self.name
            )
        return ProbeResult(
            SourceFormat.UNKNOWN, 0.0, "PCAP/PCAPNG magic이 확인되지 않음", self.name
        )

    def capabilities(self, environment: Environment) -> Capability:
        self._tshark_path = environment.tshark_path
        self._tshark_version = environment.tshark_version
        if not environment.tshark_path:
            return Capability(False, "TShark 실행 파일을 찾지 못함")
        return Capability(
            available=True,
            reason=f"TShark 사용 가능 ({environment.tshark_version or '버전 미확인'})",
            features=("network_summary", "http_requests", "literal_search"),
        )

    def _argv(self, path: Path) -> list[str]:
        if self._tshark_path is None:
            raise RuntimeError("TShark 경로가 확인되지 않았습니다")
        argv = [
            self._tshark_path,
            "-n",
            "-r",
            str(path),
            "-T",
            "fields",
            "-E",
            "header=n",
            "-E",
            "separator=\t",
            "-E",
            "quote=d",
            "-E",
            "occurrence=a",
            "-E",
            "aggregator=,",
        ]
        for field_name in _FIELDS:
            argv.extend(("-e", field_name))
        return argv

    def analyze(self, context: AnalysisContext) -> Iterator[AnalysisItem]:
        if context.cancel.is_set():
            yield limit_diagnostic("cancelled", 0)
            return
        if self._tshark_path is None:
            yield Diagnostic(
                level="error",
                stage="capability",
                message="TShark를 사용할 수 없어 패킷 분석을 실행하지 않았습니다.",
                next_action="fieldtrace doctor로 TShark 설치와 경로를 확인하세요.",
            )
            return

        want_network = requested(
            context, "network_summary", "network", "ip_domain", "ips", "ports", "protocols"
        )
        want_dns = requested(context, "network_summary", "dns", "domains", "ip_domain", "network")
        want_http = requested(context, "http_requests", "http", "web", "network")
        want_flags = requested(context, "literal_search", "flags", "flag", "strings")
        if context.selected_tasks and not (want_network or want_dns or want_http or want_flags):
            yield Diagnostic(
                level="warning",
                stage="selection",
                message="선택한 분석 항목 중 PCAP에서 지원하는 항목이 없습니다.",
                next_action="IP·도메인 요약 또는 HTTP 요청을 선택하세요.",
            )
            return

        max_records = context.budget.max_records or 100_000
        max_output_bytes = min(64 * 1024 * 1024, max(1 * 1024 * 1024, max_records * 768))
        yield progress("pcap.tshark", 0, "TShark로 패킷 필드를 읽는 중")
        try:
            return_code, stdout, stderr = context.external_runner.run(
                self._argv(context.input_path),
                cancel=context.cancel,
                timeout=context.budget.max_seconds,
                max_output_bytes=max_output_bytes,
                env={"TZ": "UTC", "LC_ALL": "C"},
            )
        except Exception as exc:  # runner owns platform-specific process errors
            if context.cancel.is_set():
                yield limit_diagnostic("cancelled", 0)
            elif (
                isinstance(exc, TimeoutError)
                or "timeout" in type(exc).__name__.casefold()
                or ("제한 시간" in str(exc))
            ):
                yield limit_diagnostic("max_seconds", 0)
            else:
                yield Diagnostic(
                    level="error",
                    stage="tshark",
                    message=f"TShark 실행에 실패했습니다: {exc}",
                    next_action="fieldtrace doctor 결과와 입력 파일 읽기 권한을 확인하세요.",
                    exception=repr(exc),
                )
            return

        if context.cancel.is_set():
            yield limit_diagnostic("cancelled", 0)
            return
        output_limited = _OUTPUT_LIMIT_MARKER in stdout or _OUTPUT_LIMIT_MARKER in stderr
        if output_limited:
            stdout = stdout.replace(f"\n{_OUTPUT_LIMIT_MARKER}", "")
            stderr = stderr.replace(f"\n{_OUTPUT_LIMIT_MARKER}", "")
            yield Diagnostic(
                level="warning",
                stage="budget",
                message="TShark 출력 크기 제한에 도달해 사용 가능한 부분만 처리합니다.",
                next_action="더 작은 캡처 파일로 나누거나 출력 예산을 조정하세요.",
            )
        if return_code != 0:
            error_preview, _ = preview(stderr.strip(), 500)
            yield Diagnostic(
                level="error",
                stage="tshark",
                message=f"TShark 종료 코드 {return_code}: {error_preview or '상세 없음'}",
                next_action="파일 손상과 지원 형식을 확인하세요. 부분 출력은 계속 처리합니다.",
            )
        elif stderr.strip():
            error_preview, _ = preview(stderr.strip(), 500)
            yield Diagnostic(
                level="warning",
                stage="tshark",
                message=f"TShark 경고: {error_preview}",
                next_action="결과 누락 여부를 진단 기록에서 확인하세요.",
            )

        packets = 0
        malformed_rows = 0
        protocol_counts: Counter[str] = Counter()
        ip_counts: Counter[str] = Counter()
        port_counts: Counter[str] = Counter()
        dns_counts: Counter[str] = Counter()
        http_counts: Counter[str] = Counter()
        reader = csv.reader(io.StringIO(stdout), delimiter="\t", quotechar='"')
        for row in reader:
            reason = limit_reason(context, packets)
            if reason:
                yield limit_diagnostic(reason, packets)
                break
            if len(row) != len(_FIELDS):
                malformed_rows += 1
                continue
            values = dict(zip(_FIELDS, row, strict=True))
            frame = values["frame.number"]
            if not frame:
                malformed_rows += 1
                continue
            packets += 1
            epoch = values["frame.time_epoch"]
            timestamp_utc = _timestamp(epoch)
            src_ip = _first(values["ip.src"], values["ipv6.src"])
            dst_ip = _first(values["ip.dst"], values["ipv6.dst"])
            src_port = _integer(_first(values["tcp.srcport"], values["udp.srcport"]))
            dst_port = _integer(_first(values["tcp.dstport"], values["udp.dstport"]))
            protocol = values["_ws.col.Protocol"] or values["frame.protocols"].rsplit(":", 1)[-1]
            protocol = protocol or "UNKNOWN"
            protocols = [part for part in values["frame.protocols"].split(":") if part]
            protocol_counts[protocol] += 1
            for address in (src_ip, dst_ip):
                if address:
                    ip_counts[address] += 1
            transport = "tcp" if values["tcp.srcport"] or values["tcp.dstport"] else "udp"
            for port in (src_port, dst_port):
                if port is not None:
                    port_counts[f"{transport}/{port}"] += 1
            summary = (
                f"frame {frame}: {src_ip or '?'}:{src_port or '-'} → "
                f"{dst_ip or '?'}:{dst_port or '-'} {protocol}"
            )
            evidence = _frame_evidence(context, frame, f"{epoch or 'time unknown'} {summary}")

            if want_network:
                yield Event(
                    category="network.packet",
                    summary=summary,
                    evidence=evidence,
                    timestamp_raw=epoch or None,
                    timestamp_utc=timestamp_utc,
                    timezone_status="utc" if timestamp_utc else "unknown",
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    src_port=src_port,
                    dst_port=dst_port,
                    fields={
                        "frame": _integer(frame),
                        "protocol": protocol,
                        "protocol_stack": protocols,
                    },
                )

            for query in _split_occurrences(values["dns.qry.name"]):
                dns_counts[query.casefold()] += 1
                if want_dns or want_flags:
                    yield Event(
                        category="network.dns_query",
                        summary=f"DNS 질의: {query}",
                        evidence=evidence,
                        timestamp_raw=epoch or None,
                        timestamp_utc=timestamp_utc,
                        timezone_status="utc" if timestamp_utc else "unknown",
                        src_ip=src_ip,
                        dst_ip=dst_ip,
                        src_port=src_port,
                        dst_port=dst_port,
                        fields={"frame": _integer(frame), "query": query},
                    )

            method = values["http.request.method"]
            host = values["http.host"]
            uri_raw = values["http.request.uri"]
            if (want_http or want_flags) and method:
                uri_decoded = unquote(uri_raw, errors="replace")
                key = f"{method} {host}{uri_decoded}"
                http_counts[key] += 1
                yield Event(
                    category="network.http_request",
                    summary=f"HTTP {method} {host}{uri_decoded}",
                    evidence=evidence,
                    timestamp_raw=epoch or None,
                    timestamp_utc=timestamp_utc,
                    timezone_status="utc" if timestamp_utc else "unknown",
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    src_port=src_port,
                    dst_port=dst_port,
                    fields={
                        "frame": _integer(frame),
                        "method": method,
                        "host": host,
                        "uri_raw": uri_raw,
                        "uri_decoded": uri_decoded,
                    },
                )
            if want_flags:
                for value in extract_flags(unquote(" ".join((host, uri_raw)), errors="replace")):
                    yield Finding(
                        rule_id="pcap.flag_candidate",
                        title="패킷 HTTP 필드의 플래그 형태 문자열 후보",
                        observation=f"플래그 형태 문자열을 관측했습니다: {value}",
                        interpretation=(
                            "평문 HTTP 필드의 후보이며 정답 여부는 frame 원문 확인이 필요합니다."
                        ),
                        confidence="medium",
                        evidence=evidence,
                        fields={"frame": _integer(frame), "value": value},
                    )
            if packets % PROGRESS_INTERVAL == 0:
                yield progress("pcap.parse", packets, "패킷 필드 집계 중")

        yield Finding(
            rule_id="pcap.summary",
            title="패킷 기본 요약",
            observation=(
                f"패킷 {packets:,}개에서 프로토콜 {len(protocol_counts):,}종, "
                f"IP {len(ip_counts):,}개, DNS 질의 {sum(dns_counts.values()):,}건, "
                f"HTTP 요청 {sum(http_counts.values()):,}건을 관측했습니다."
            ),
            interpretation=(
                "기본 필드 집계이며 TCP 스트림 완전 재조립이나 객체 추출 결과가 아닙니다."
            ),
            confidence="high",
            fields={
                "packets": packets,
                "protocols": dict(protocol_counts.most_common(100)),
                "ips": dict(ip_counts.most_common(100)),
                "ports": dict(port_counts.most_common(100)),
                "dns_queries": dict(dns_counts.most_common(100)),
                "http_requests": dict(http_counts.most_common(100)),
                "malformed_rows": malformed_rows,
                "tshark_version": self._tshark_version,
                "name_resolution_disabled": True,
                "tshark_fields": list(_FIELDS),
                "output_limited": output_limited,
            },
        )
        if malformed_rows:
            yield Diagnostic(
                level="warning",
                stage="pcap.parse",
                message=f"TShark 출력 {malformed_rows:,}행을 필드 수 불일치로 생략했습니다.",
                next_action="TShark 버전과 진단 로그를 확인하세요.",
            )
        yield progress("pcap", packets, "패킷 기본 분석 완료")
