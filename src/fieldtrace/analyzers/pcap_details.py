"""Explicit high-cost TShark details kept separate from the basic PCAP pass."""

from __future__ import annotations

import csv
import io
from collections.abc import Iterator
from pathlib import Path

from fieldtrace.analyzers._common import limit_diagnostic, limit_reason, preview
from fieldtrace.core.models import AnalysisContext, AnalysisItem, Diagnostic, Event, EvidenceRef

_OUTPUT_LIMIT_MARKER = "[FieldTrace: 출력 제한으로 나머지 생략]"
_MAX_STREAMS = 5


def _follow_argv(tshark_path: str, path: Path, stream_id: int) -> list[str]:
    return [
        tshark_path,
        "-n",
        "-r",
        str(path),
        "-q",
        "-z",
        f"follow,tcp,ascii,{stream_id}",
    ]


def _objects_argv(tshark_path: str, path: Path) -> list[str]:
    fields = (
        "frame.number",
        "tcp.stream",
        "http.content_type",
        "http.content_length",
        "http.file_data",
    )
    argv = [
        tshark_path,
        "-n",
        "-r",
        str(path),
        "-Y",
        "http.file_data",
        "-o",
        "tcp.desegment_tcp_streams:TRUE",
        "-o",
        "http.desegment_body:TRUE",
        "-T",
        "fields",
        "-E",
        "separator=\t",
        "-E",
        "quote=d",
    ]
    for field_name in fields:
        argv.extend(("-e", field_name))
    return argv


def _frame_evidence(context: AnalysisContext, frame: str, summary: str) -> EvidenceRef:
    value, truncated = preview(summary, context.budget.max_preview_chars)
    return EvidenceRef(
        source_id=context.source_id,
        kind="pcap_frame",
        locator=f"frame:{frame}",
        preview=value,
        truncated=truncated,
    )


def tcp_stream_items(
    context: AnalysisContext, tshark_path: str, stream_ids: set[int]
) -> Iterator[AnalysisItem]:
    for stream_id in sorted(stream_ids)[:_MAX_STREAMS]:
        reason = limit_reason(context, 0)
        if reason:
            yield limit_diagnostic(reason, 0)
            return
        try:
            code, stdout, stderr = context.external_runner.run(
                _follow_argv(tshark_path, context.input_path, stream_id),
                cancel=context.cancel,
                timeout=min(context.budget.max_seconds or 30.0, 30.0),
                max_output_bytes=256 * 1024,
                env={"TZ": "UTC", "LC_ALL": "C"},
            )
        except Exception as exc:
            yield Diagnostic(
                "warning",
                "pcap.stream",
                f"TCP stream {stream_id} 재조립 보기를 만들지 못했습니다: {exc}",
                "기본 패킷 결과를 확인하고 TShark 버전을 점검하세요.",
                repr(exc),
            )
            continue
        limited = _OUTPUT_LIMIT_MARKER in stdout or _OUTPUT_LIMIT_MARKER in stderr
        stdout = stdout.replace(f"\n{_OUTPUT_LIMIT_MARKER}", "")
        evidence_text, truncated = preview(stdout, context.budget.max_preview_chars)
        evidence = EvidenceRef(
            source_id=context.source_id,
            kind="tcp_stream",
            locator=f"tcp.stream:{stream_id}",
            preview=evidence_text,
            truncated=truncated or limited,
        )
        if code != 0:
            yield Diagnostic(
                "warning",
                "pcap.stream",
                f"TCP stream {stream_id} 보기의 TShark 종료 코드가 {code}입니다.",
                "해당 stream은 누락되거나 불완전할 수 있습니다.",
                stderr[:500] or None,
            )
            continue
        detail, detail_truncated = preview(stdout, context.decode_max_output_chars)
        yield Event(
            category="network.tcp_stream",
            summary=f"TShark TCP stream {stream_id} 재조립 보기(완전성 미확정)",
            evidence=evidence,
            fields={
                "tcp_stream": stream_id,
                "reassembly_engine": "tshark follow,tcp,ascii",
                "completeness": "unknown",
                "output_limited": limited or detail_truncated,
                "stream_preview": detail,
            },
        )
    if len(stream_ids) > _MAX_STREAMS:
        yield Diagnostic(
            "warning",
            "pcap.stream",
            f"TCP stream {len(stream_ids):,}개 중 {_MAX_STREAMS}개만 상세 표시했습니다.",
            "확인할 stream ID를 좁혀 별도 분석하세요.",
        )


def http_object_items(
    context: AnalysisContext, tshark_path: str, *, analyzer: str
) -> Iterator[AnalysisItem]:
    if context.artifact_sink is None:
        yield Diagnostic(
            "error",
            "pcap.objects",
            "core 파생 파일 저장소가 없어 HTTP 객체 추출을 생략했습니다.",
            "사례 폴더 쓰기 권한을 확인하세요.",
        )
        return
    try:
        code, stdout, stderr = context.external_runner.run(
            _objects_argv(tshark_path, context.input_path),
            cancel=context.cancel,
            timeout=min(context.budget.max_seconds or 60.0, 60.0),
            max_output_bytes=64 * 1024 * 1024,
            env={"TZ": "UTC", "LC_ALL": "C"},
        )
    except Exception as exc:
        yield Diagnostic(
            "error",
            "pcap.objects",
            f"TShark HTTP 객체 필드 추출에 실패했습니다: {exc}",
            "TShark 버전과 사례 폴더 쓰기 권한을 확인하세요.",
            repr(exc),
        )
        return
    if code != 0:
        yield Diagnostic(
            "error",
            "pcap.objects",
            f"TShark HTTP 객체 추출 종료 코드 {code}: {stderr[:500]}",
            "지원 필드와 캡처 손상 여부를 확인하세요.",
        )
    if _OUTPUT_LIMIT_MARKER in stdout or _OUTPUT_LIMIT_MARKER in stderr:
        stdout = stdout.replace(f"\n{_OUTPUT_LIMIT_MARKER}", "")
        yield Diagnostic(
            "warning",
            "budget",
            "HTTP 객체용 TShark 출력 제한에 도달해 일부 본문만 처리합니다.",
            "더 작은 캡처로 나누거나 필요한 stream을 좁히세요.",
        )
    fields = ("frame", "stream", "content_type", "content_length", "data")
    for row in csv.reader(io.StringIO(stdout), delimiter="\t", quotechar='"'):
        if len(row) != len(fields) or not row[-1]:
            continue
        values = dict(zip(fields, row, strict=True))
        hex_data = values["data"].replace(":", "")
        try:
            data = bytes.fromhex(hex_data)
        except ValueError:
            yield Diagnostic(
                "warning",
                "pcap.objects",
                f"frame {values['frame']}의 HTTP 본문 바이트를 해석하지 못했습니다.",
                "해당 frame 원문을 TShark에서 직접 확인하세요.",
            )
            continue
        try:
            declared_length = int(values["content_length"])
        except ValueError:
            declared_length = None
        if declared_length is not None and declared_length != len(data):
            yield Diagnostic(
                "warning",
                "pcap.objects",
                f"frame {values['frame']} HTTP 본문은 선언 {declared_length:,}바이트와 "
                f"복원 {len(data):,}바이트가 다릅니다.",
                "추출물이 불완전할 수 있으므로 원본 stream을 확인하세요.",
            )
        evidence = _frame_evidence(
            context,
            values["frame"] or "?",
            (
                f"HTTP body stream {values['stream'] or '?'}; "
                f"content-type={values['content_type'] or 'unknown'}; "
                "TShark 재조립 결과이며 누락 여부는 별도 확인 필요"
            ),
        )
        try:
            artifact = context.artifact_sink.write_bytes(
                f"http-stream-{values['stream'] or 'unknown'}-frame-{values['frame']}.bin",
                data,
                kind="http.object",
                analyzer=analyzer,
                evidence=evidence,
            )
        except (OSError, ValueError) as exc:
            yield Diagnostic(
                "warning",
                "pcap.objects",
                f"frame {values['frame']}의 HTTP 객체를 저장하지 못했습니다: {exc}",
                "사례 폴더 용량과 권한, 추출 제한을 확인하세요.",
                repr(exc),
            )
            continue
        yield artifact
