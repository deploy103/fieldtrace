"""Streaming Windows EVTX adapter backed by the reviewed python-evtx library."""

from __future__ import annotations

from collections import Counter
from collections.abc import Callable, Iterator
from contextlib import AbstractContextManager
from datetime import UTC, datetime
from typing import Any, Protocol
from xml.etree import ElementTree

from fieldtrace.analyzers._common import (
    PROGRESS_INTERVAL,
    extract_flags,
    limit_diagnostic,
    limit_reason,
    progress,
    requested,
)
from fieldtrace.analyzers.decoding import DecodeTracker, decoded_items
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

try:
    from Evtx.Evtx import Evtx as _Evtx
except ImportError:  # pragma: no cover - exercised only in an incomplete installation
    _Evtx = None

_MAGIC = b"ElfFile\x00"
_SECURITY_PROVIDER = "microsoft-windows-security-auditing"
_SYSMON_PROVIDER = "microsoft-windows-sysmon"
_POWERSHELL_PROVIDER = "microsoft-windows-powershell"
_SERVICE_PROVIDER = "service control manager"
_PID_LINK_WINDOW_SECONDS = 300.0
_MAX_PROCESS_GUIDS = 50_000
_MAX_PROCESS_PIDS = 50_000
_MAX_PID_HISTORY = 16


class _Record(Protocol):
    def xml(self) -> str: ...

    def record_num(self) -> int: ...


class _Reader(Protocol):
    def records(self) -> Iterator[_Record]: ...


type ReaderFactory = Callable[[str], AbstractContextManager[_Reader]]


def _local_name(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _first(parent: ElementTree.Element, name: str) -> ElementTree.Element | None:
    return next((element for element in parent.iter() if _local_name(element.tag) == name), None)


def _text(parent: ElementTree.Element, name: str) -> str | None:
    element = _first(parent, name)
    if element is None or element.text is None:
        return None
    value = element.text.strip()
    return value or None


def _event_data(root: ElementTree.Element) -> dict[str, Any]:
    """Flatten version-tolerant EventData/UserData leaves without dropping duplicates."""

    values: dict[str, Any] = {}
    unnamed = 0
    for container_name in ("EventData", "UserData"):
        container = _first(root, container_name)
        if container is None:
            continue
        for element in container.iter():
            if element is container or list(element):
                continue
            value = (element.text or "").strip()
            if not value:
                continue
            name = element.attrib.get("Name") or _local_name(element.tag)
            if name == "Data" and "Name" not in element.attrib:
                unnamed += 1
                name = f"data_{unnamed}"
            existing = values.get(name)
            if existing is None:
                values[name] = value
            elif isinstance(existing, list):
                existing.append(value)
            else:
                values[name] = [existing, value]
    return values


def _string_value(fields: dict[str, Any], *names: str) -> str | None:
    folded = {key.casefold(): value for key, value in fields.items()}
    for name in names:
        value = folded.get(name.casefold())
        if isinstance(value, list):
            value = next((item for item in value if isinstance(item, str) and item), None)
        if isinstance(value, str) and value not in {"-", "::", "0.0.0.0"}:
            return value
    return None


def _port(fields: dict[str, Any], *names: str) -> int | None:
    value = _string_value(fields, *names)
    try:
        parsed = int(value) if value is not None else None
    except ValueError:
        return None
    return parsed if parsed is not None and 0 <= parsed <= 65_535 else None


def _pid(value: str | None) -> int | None:
    if value is None:
        return None
    try:
        parsed = int(value, 0)
    except ValueError:
        return None
    return parsed if parsed >= 0 else None


def _epoch(timestamp_utc: str | None) -> float | None:
    if timestamp_utc is None:
        return None
    try:
        return datetime.fromisoformat(timestamp_utc).timestamp()
    except ValueError:
        return None


def _process_identity(
    provider: str | None, fields: dict[str, Any]
) -> tuple[str | None, str | None, int | None, int | None]:
    provider_key = (provider or "").casefold()
    if provider_key == _SYSMON_PROVIDER:
        return (
            _string_value(fields, "ProcessGuid"),
            _string_value(fields, "ParentProcessGuid"),
            _pid(_string_value(fields, "ProcessId")),
            _pid(_string_value(fields, "ParentProcessId")),
        )
    if provider_key == _SECURITY_PROVIDER:
        return (
            None,
            None,
            _pid(_string_value(fields, "NewProcessId")),
            _pid(_string_value(fields, "ProcessId")),
        )
    return None, None, None, None


def _link_process_parent(
    fields: dict[str, Any],
    *,
    provider: str | None,
    timestamp_utc: str | None,
    record_id: str,
    guid_index: dict[str, dict[str, Any]],
    pid_index: dict[int, list[dict[str, Any]]],
) -> tuple[str, int]:
    guid, parent_guid, pid, parent_pid = _process_identity(provider, fields)
    link_method = "none"
    parent: dict[str, Any] | None = None
    ambiguous = False
    if parent_guid:
        parent = guid_index.get(parent_guid.casefold())
        link_method = "process_guid" if parent is not None else "process_guid_unresolved"
    elif parent_pid is not None:
        current_epoch = _epoch(timestamp_utc)
        if current_epoch is None:
            link_method = "pid_without_time"
        else:
            candidates = [
                item
                for item in pid_index.get(parent_pid, ())
                if item["epoch"] is not None
                and 0 <= current_epoch - item["epoch"] <= _PID_LINK_WINDOW_SECONDS
            ]
            identities = {item["identity"] for item in candidates}
            if len(identities) == 1:
                parent = candidates[-1]
                link_method = "pid_time_window"
            elif len(identities) > 1:
                link_method = "pid_reuse_ambiguous"
                ambiguous = True
            else:
                link_method = "pid_unresolved"
    fields.update(
        {
            "process_guid": guid,
            "parent_process_guid": parent_guid,
            "process_id": pid,
            "parent_process_id": parent_pid,
            "parent_link_method": link_method,
            "parent_link_ambiguous": ambiguous,
            "parent_link_window_seconds": _PID_LINK_WINDOW_SECONDS,
            "parent_record_id": parent.get("record_id") if parent else None,
            "parent_image": parent.get("image") if parent else None,
        }
    )
    identity = guid.casefold() if guid else f"record:{record_id}"
    current = {
        "identity": identity,
        "record_id": record_id,
        "epoch": _epoch(timestamp_utc),
        "image": _string_value(fields, "Image", "NewProcessName"),
    }
    evictions = 0
    if guid:
        guid_key = guid.casefold()
        if guid_key not in guid_index and len(guid_index) >= _MAX_PROCESS_GUIDS:
            guid_index.pop(next(iter(guid_index)))
            evictions += 1
        guid_index[guid_key] = current
    if pid is not None:
        if pid not in pid_index and len(pid_index) >= _MAX_PROCESS_PIDS:
            pid_index.pop(next(iter(pid_index)))
            evictions += 1
        history = pid_index.setdefault(pid, [])
        history.append(current)
        if len(history) > _MAX_PID_HISTORY:
            del history[:-_MAX_PID_HISTORY]
    return link_method, evictions


def _timestamp(raw: str | None) -> tuple[str | None, str]:
    if not raw:
        return None, "unknown"
    normalized = raw[:-1] + "+00:00" if raw.endswith(("Z", "z")) else raw
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError:
        return None, "invalid"
    if parsed.tzinfo is None:
        return None, "unknown"
    return parsed.astimezone(UTC).isoformat(), "explicit"


def _classify(provider: str | None, channel: str | None, event_id: int | None) -> str:
    provider_key = (provider or "").casefold()
    channel_key = (channel or "").casefold()
    if provider_key == _SECURITY_PROVIDER and channel_key == "security":
        return {
            4624: "auth.login_success",
            4625: "auth.login_failure",
            4688: "process.create",
        }.get(event_id, "evtx.record")
    if provider_key == _SYSMON_PROVIDER and "sysmon" in channel_key:
        return {1: "process.create", 3: "network.connect"}.get(event_id, "evtx.record")
    if provider_key == _POWERSHELL_PROVIDER and "powershell" in channel_key:
        return {4104: "powershell.script"}.get(event_id, "evtx.record")
    if provider_key == _SERVICE_PROVIDER and channel_key == "system":
        return {7045: "service.install"}.get(event_id, "evtx.record")
    return "evtx.record"


def _summary(category: str, event_id: int | None, fields: dict[str, Any]) -> str:
    user = _string_value(fields, "TargetUserName", "User", "UserName")
    image = _string_value(fields, "Image", "NewProcessName", "ImagePath")
    source_ip = _string_value(fields, "IpAddress", "SourceIp")
    if category == "auth.login_success":
        return f"Windows 로그인 성공 관측: {user or '사용자 미상'} @ {source_ip or '주소 미상'}"
    if category == "auth.login_failure":
        return f"Windows 로그인 실패 관측: {user or '사용자 미상'} @ {source_ip or '주소 미상'}"
    if category == "process.create":
        return f"프로세스 생성 관측: {image or '실행 파일 미상'}"
    if category == "network.connect":
        destination = _string_value(fields, "DestinationIp") or "목적지 미상"
        return f"Sysmon 네트워크 연결 관측: {source_ip or '출발지 미상'} → {destination}"
    if category == "powershell.script":
        return "PowerShell 스크립트 블록 관측"
    if category == "service.install":
        service = _string_value(fields, "ServiceName") or "서비스명 미상"
        return f"Windows 서비스 등록 관측: {service}"
    return f"Windows 이벤트 레코드 관측: Event ID {event_id if event_id is not None else '미상'}"


def _task_selected(context: AnalysisContext, category: str) -> bool:
    if not context.selected_tasks:
        return True
    if category.startswith("auth."):
        return requested(context, "login_activity", "auth", "login", "logins")
    if category == "network.connect":
        return requested(context, "network_summary", "network", "ip", "domain")
    if category in {"process.create", "powershell.script", "service.install"}:
        return requested(context, "executed_commands", "commands", "command", "execution")
    return requested(context, "literal_search", "flags", "flag", "strings", "literal")


class EvtxAnalyzer:
    name = "evtx"
    formats = (SourceFormat.EVTX,)
    tasks = ("login_activity", "executed_commands", "network_summary", "literal_search")

    def __init__(self, reader_factory: ReaderFactory | None = None) -> None:
        self._reader_factory = reader_factory

    def probe(self, sample: bytes, metadata: ProbeMetadata) -> ProbeResult:
        del metadata
        if sample[: len(_MAGIC)] == _MAGIC:
            return ProbeResult(SourceFormat.EVTX, 1.0, "Windows EVTX file magic 값 확인", self.name)
        return ProbeResult(SourceFormat.UNKNOWN, 0.0, "EVTX magic 값이 없음", self.name)

    def capabilities(self, environment: Environment) -> Capability:
        available = self._reader_factory is not None or _Evtx is not None
        return Capability(
            available=available,
            reason=(
                "python-evtx를 사용한 Windows 이벤트 분석 가능"
                + (
                    f" ({environment.python_evtx_version})"
                    if environment.python_evtx_version
                    else ""
                )
                if available
                else "python-evtx 패키지가 설치되지 않음"
            ),
            features=self.tasks,
        )

    def analyze(self, context: AnalysisContext) -> Iterator[AnalysisItem]:
        reader_factory = self._reader_factory or _Evtx
        if reader_factory is None:
            yield Diagnostic(
                "error",
                "evtx.read",
                "python-evtx 패키지가 없어 EVTX를 읽을 수 없습니다.",
                "준비 환경에서 uv sync를 실행한 뒤 다시 분석하세요.",
            )
            return

        processed = 0
        parse_failures = 0
        counts: Counter[str] = Counter()
        process_links: Counter[str] = Counter()
        process_guid_index: dict[str, dict[str, Any]] = {}
        process_pid_index: dict[int, list[dict[str, Any]]] = {}
        process_cache_evictions = 0
        decode_tracker = DecodeTracker()
        yield progress("evtx", 0, "Windows 이벤트 레코드를 읽는 중")
        try:
            with reader_factory(str(context.input_path)) as reader:
                for record in reader.records():
                    reason = limit_reason(context, processed)
                    if reason:
                        yield limit_diagnostic(reason, processed)
                        break
                    if context.cancel.is_set():
                        yield limit_diagnostic("cancelled", processed)
                        break
                    processed += 1
                    try:
                        fallback_record_id = str(record.record_num())
                    except Exception:
                        fallback_record_id = str(processed)
                    xml = ""
                    try:
                        xml = record.xml()
                        if len(xml) > context.budget.max_line_bytes:
                            evidence = EvidenceRef(
                                source_id=context.source_id,
                                kind="evtx",
                                locator=f"channel:Unknown;record:{fallback_record_id}",
                                preview=xml[: context.budget.max_preview_chars],
                                truncated=True,
                            )
                            yield Event(
                                category="evtx.oversized_record",
                                summary="크기 제한을 초과해 해석하지 않은 EVTX 레코드",
                                evidence=evidence,
                                fields={"raw_preserved": True, "record_id": fallback_record_id},
                            )
                            yield Diagnostic(
                                "warning",
                                "evtx.parse",
                                f"EVTX record {fallback_record_id} XML이 "
                                f"{context.budget.max_line_bytes:,}자 제한을 초과했습니다.",
                                "제한 원문은 보존했으며 필요하면 별도 도구로 확인하세요.",
                            )
                            parse_failures += 1
                            continue
                        root = ElementTree.fromstring(xml)
                    except Exception as exc:
                        parse_failures += 1
                        preview_limit = max(1, context.budget.max_preview_chars)
                        yield Event(
                            category="evtx.unparsed",
                            summary="XML을 해석하지 못한 EVTX 레코드 원문",
                            evidence=EvidenceRef(
                                source_id=context.source_id,
                                kind="evtx",
                                locator=f"channel:Unknown;record:{fallback_record_id}",
                                preview=xml[:preview_limit],
                                truncated=len(xml) > preview_limit,
                            ),
                            fields={"raw_preserved": bool(xml), "record_id": fallback_record_id},
                        )
                        yield Diagnostic(
                            "warning",
                            "evtx.parse",
                            f"EVTX {processed}번째 레코드 XML을 해석하지 못했습니다.",
                            "다른 레코드는 계속 분석하며 손상 여부를 확인하세요.",
                            repr(exc),
                        )
                        continue

                    system = _first(root, "System")
                    if system is None:
                        system = root
                    provider_element = _first(system, "Provider")
                    provider = (
                        provider_element.attrib.get("Name")
                        if provider_element is not None
                        else None
                    )
                    channel = _text(system, "Channel") or "Unknown"
                    event_id_text = _text(system, "EventID")
                    try:
                        event_id = int(event_id_text) if event_id_text is not None else None
                    except ValueError:
                        event_id = None
                    record_id_text = _text(system, "EventRecordID")
                    if record_id_text is None:
                        record_id_text = fallback_record_id
                    raw_time = None
                    time_element = _first(system, "TimeCreated")
                    if time_element is not None:
                        raw_time = time_element.attrib.get("SystemTime")
                    timestamp_utc, timezone_status = _timestamp(raw_time)
                    fields = _event_data(root)
                    fields.update(
                        {
                            "event_id": event_id,
                            "record_id": record_id_text,
                            "channel": channel,
                            "provider": provider,
                            "computer": _text(system, "Computer"),
                        }
                    )
                    preview_limit = max(1, context.budget.max_preview_chars)
                    preview = xml[:preview_limit]
                    evidence = EvidenceRef(
                        source_id=context.source_id,
                        kind="evtx",
                        locator=f"channel:{channel};record:{record_id_text}",
                        preview=preview,
                        truncated=len(xml) > len(preview),
                    )
                    category = _classify(provider, channel, event_id)
                    counts[category] += 1
                    if category == "process.create":
                        method, evictions = _link_process_parent(
                            fields,
                            provider=provider,
                            timestamp_utc=timestamp_utc,
                            record_id=record_id_text,
                            guid_index=process_guid_index,
                            pid_index=process_pid_index,
                        )
                        process_links[method] += 1
                        process_cache_evictions += evictions
                    if _task_selected(context, category):
                        yield Event(
                            category=category,
                            summary=_summary(category, event_id, fields),
                            evidence=evidence,
                            timestamp_raw=raw_time,
                            timestamp_utc=timestamp_utc,
                            timezone_status=timezone_status,
                            src_ip=_string_value(fields, "IpAddress", "SourceIp"),
                            dst_ip=_string_value(fields, "DestinationIp"),
                            src_port=_port(fields, "SourcePort"),
                            dst_port=_port(fields, "DestinationPort"),
                            user=_string_value(fields, "TargetUserName", "User", "UserName"),
                            fields=fields,
                        )
                    if requested(context, "literal_search", "flags", "flag", "strings", "literal"):
                        for value in extract_flags(xml, context.flag_prefixes):
                            yield Finding(
                                rule_id="evtx.flag_candidate",
                                title="EVTX 플래그 형태 문자열 후보",
                                observation=value,
                                interpretation="정답 여부는 원본 이벤트 문맥에서 확인해야 합니다.",
                                confidence="medium",
                                evidence=evidence,
                                fields={"value": value, "event_id": event_id},
                            )
                        yield from decoded_items(
                            context,
                            xml,
                            evidence,
                            rule_prefix="evtx",
                            tracker=decode_tracker,
                        )
                    if processed % PROGRESS_INTERVAL == 0:
                        yield progress("evtx", processed, f"{processed:,}개 레코드 처리")
        except (OSError, ValueError) as exc:
            yield Diagnostic(
                "error",
                "evtx.read",
                f"EVTX 파일을 읽지 못했습니다: {exc}",
                "원본이 EVTX인지, 파일 권한과 손상 여부를 확인하세요.",
                repr(exc),
            )
        except Exception as exc:
            yield Diagnostic(
                "error",
                "evtx.read",
                f"EVTX 레코드 열거 중 실패했습니다: {exc}",
                "저장된 부분 결과를 확인하고 파일 손상 여부를 점검하세요.",
                repr(exc),
            )

        if processed:
            observation = ", ".join(
                f"{category} {count:,}건" for category, count in sorted(counts.items())
            )
            yield Finding(
                rule_id="evtx.activity_summary",
                title="Windows 이벤트 분석 요약",
                observation=observation or f"레코드 {processed:,}건",
                interpretation=(
                    "provider와 channel이 알려진 조합만 의미별로 분류했으며, "
                    "나머지는 일반 EVTX 레코드입니다."
                ),
                confidence="high",
                fields={
                    "records": processed,
                    "parse_failures": parse_failures,
                    "categories": dict(counts),
                },
            )
        if process_links:
            yield Finding(
                rule_id="evtx.process_tree_summary",
                title="Windows 프로세스 부모 연결 요약",
                observation=", ".join(
                    f"{method} {count:,}건" for method, count in sorted(process_links.items())
                ),
                interpretation=(
                    "ProcessGuid를 우선했고, GUID가 없을 때만 5분 범위에서 PID 후보가 "
                    "하나인 경우 연결했습니다. 미해결·모호 연결은 확정하지 않았습니다."
                ),
                confidence="high",
                fields={
                    "methods": dict(process_links),
                    "pid_window_seconds": _PID_LINK_WINDOW_SECONDS,
                    "cache_evictions": process_cache_evictions,
                    "guid_cache_limit": _MAX_PROCESS_GUIDS,
                    "pid_cache_limit": _MAX_PROCESS_PIDS,
                },
            )
        if process_cache_evictions:
            yield Diagnostic(
                "warning",
                "evtx.process",
                f"프로세스 부모 연결 캐시 제한으로 오래된 항목을 "
                f"{process_cache_evictions:,}회 제거했습니다.",
                "부모 연결이 꼭 필요하면 EVTX 범위를 나눠 다시 분석하세요.",
            )
        yield progress("evtx", processed, f"EVTX {processed:,}개 레코드 처리 완료")
