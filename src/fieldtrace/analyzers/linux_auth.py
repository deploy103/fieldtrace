"""Streaming parser for representative OpenSSH and sudo syslog lines."""

from __future__ import annotations

import re
from collections import Counter
from collections.abc import Iterator
from datetime import UTC, datetime
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

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
from fieldtrace.analyzers.decoding import DecodeTracker, decoded_items
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

_SYSLOG_RE = re.compile(
    r"^(?P<timestamp>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+(?P<message>.*)$"
)
_SSH_RE = re.compile(
    r"(?:sshd(?:\[\d+\])?:\s*)?"
    r"(?P<result>Accepted|Failed)\s+"
    r"(?P<method>password|publickey|keyboard-interactive|none)\s+for\s+"
    r"(?:(?P<invalid>invalid user)\s+)?(?P<user>\S+)\s+from\s+"
    r"(?P<ip>\S+)\s+port\s+(?P<port>\d+)(?:\s+(?P<protocol>\S+))?",
    re.IGNORECASE,
)
_SUDO_RE = re.compile(
    r"(?:sudo(?:\[\d+\])?:\s*)?(?P<actor>[^:\s]+)\s*:\s*"
    r"(?P<body>.*?)(?:;\s*)COMMAND=(?P<command>.+)$"
)
_KEY_VALUE_RE = re.compile(r"(?:^|;\s*)(?P<key>TTY|PWD|USER)=(?P<value>[^;]*)")
_MONTHS = {
    "Jan": 1,
    "Feb": 2,
    "Mar": 3,
    "Apr": 4,
    "May": 5,
    "Jun": 6,
    "Jul": 7,
    "Aug": 8,
    "Sep": 9,
    "Oct": 10,
    "Nov": 11,
    "Dec": 12,
}


def _normalize_syslog_timestamp(
    raw: str | None, year: int | None, timezone_name: str | None
) -> tuple[str | None, str]:
    if raw is None or year is None or timezone_name is None:
        return None, "unknown"
    try:
        month_name, day_text, time_text = raw.split()
        hour_text, minute_text, second_text = time_text.split(":")
        naive = datetime(
            year,
            _MONTHS[month_name],
            int(day_text),
            int(hour_text),
            int(minute_text),
            int(second_text),
        )
        zone = ZoneInfo(timezone_name)
    except (KeyError, ValueError, ZoneInfoNotFoundError):
        return None, "invalid_assumption"

    candidates = [naive.replace(tzinfo=zone, fold=fold) for fold in (0, 1)]
    valid = [
        candidate.astimezone(UTC).astimezone(zone).replace(tzinfo=None) == naive
        for candidate in candidates
    ]
    offsets = {candidate.utcoffset() for candidate in candidates}
    if not any(valid):
        return None, "nonexistent_local_time"
    if all(valid) and len(offsets) > 1:
        return None, "ambiguous_local_time"
    selected = candidates[valid.index(True)]
    return selected.astimezone(UTC).isoformat(), "assumed"


class LinuxAuthAnalyzer:
    name = "linux_auth"
    formats = (SourceFormat.LINUX_AUTH,)

    def probe(self, sample: bytes, metadata: ProbeMetadata) -> ProbeResult:
        inspected = bounded_sample(sample)
        encoding, reason = text_encoding(inspected)
        if encoding is None:
            return ProbeResult(SourceFormat.UNKNOWN, 0.0, reason, self.name)
        try:
            decoded = decode_sample(inspected, encoding)
        except UnicodeDecodeError:
            return ProbeResult(SourceFormat.UNKNOWN, 0.0, "지원 텍스트 디코딩 실패", self.name)
        lines = [line for line in decoded.splitlines()[:60] if line.strip()]
        ssh = sum("sshd" in line and _SSH_RE.search(line) is not None for line in lines)
        sudo = sum("sudo" in line and "COMMAND=" in line for line in lines)
        matches = ssh + sudo
        if matches:
            return ProbeResult(
                SourceFormat.LINUX_AUTH,
                min(0.99, 0.76 + 0.23 * (matches / len(lines))),
                f"OpenSSH/sudo 인증 로그 내용 {matches}/{len(lines)}줄 일치",
                self.name,
            )
        suffix_clue = metadata.path.name.casefold() in {"auth.log", "secure"}
        return ProbeResult(
            SourceFormat.UNKNOWN,
            0.2 if suffix_clue else 0.0,
            "OpenSSH 또는 sudo 내용 패턴이 확인되지 않음",
            self.name,
        )

    def capabilities(self, environment: Environment) -> Capability:
        del environment
        return Capability(
            available=True,
            reason="OpenSSH 로그인과 sudo 스트리밍 분석 사용 가능",
            features=("login_activity", "executed_commands", "literal_search"),
        )

    def analyze(self, context: AnalysisContext) -> Iterator[AnalysisItem]:
        processed = 0
        unparsed = 0
        counters: Counter[str] = Counter()
        users: Counter[str] = Counter()
        source_ips: Counter[str] = Counter()
        decode_tracker = DecodeTracker()
        want_auth = requested(context, "login_activity", "auth", "login", "logins")
        want_commands = requested(
            context, "executed_commands", "commands", "command", "sudo", "execution"
        )
        want_flags = requested(
            context, "literal_search", "flags", "flag", "strings", "literal", "literals"
        )
        yield progress("linux_auth", 0, "인증 로그를 읽는 중")

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
            syslog_match = _SYSLOG_RE.match(item.text)
            timestamp_raw = syslog_match.group("timestamp") if syslog_match else None
            timestamp_utc, timezone_status = _normalize_syslog_timestamp(
                timestamp_raw,
                context.time_policy.assumed_year,
                context.time_policy.timezone,
            )
            time_fields = {
                "year_missing": timestamp_raw is not None,
                "assumed_year": (
                    context.time_policy.assumed_year if timezone_status == "assumed" else None
                ),
                "assumed_timezone": (
                    context.time_policy.timezone if timezone_status == "assumed" else None
                ),
            }
            message = syslog_match.group("message") if syslog_match else item.text
            ssh_match = _SSH_RE.search(message)
            sudo_match = _SUDO_RE.search(message)
            matched = False

            if ssh_match is not None:
                matched = True
                successful = ssh_match.group("result").casefold() == "accepted"
                category = "auth.login_success" if successful else "auth.login_failure"
                counters["success" if successful else "failure"] += 1
                user = ssh_match.group("user")
                src_ip = ssh_match.group("ip")
                users[user] += 1
                source_ips[src_ip] += 1
                if want_auth or want_flags:
                    yield Event(
                        category=category,
                        summary=(
                            f"SSH 로그인 {'성공' if successful else '실패'}: {user} @ {src_ip}"
                        ),
                        evidence=evidence,
                        timestamp_raw=timestamp_raw,
                        timestamp_utc=timestamp_utc,
                        timezone_status=timezone_status,
                        src_ip=src_ip,
                        src_port=int(ssh_match.group("port")),
                        user=user,
                        fields={
                            "result": "success" if successful else "failure",
                            "method": ssh_match.group("method").casefold(),
                            "invalid_user": ssh_match.group("invalid") is not None,
                            "protocol": ssh_match.group("protocol"),
                            **time_fields,
                        },
                    )

            if sudo_match is not None:
                matched = True
                counters["sudo"] += 1
                actor = sudo_match.group("actor")
                command = sudo_match.group("command").strip()
                values = {
                    match.group("key").casefold(): match.group("value").strip()
                    for match in _KEY_VALUE_RE.finditer(sudo_match.group("body"))
                }
                users[actor] += 1
                if want_commands or want_flags:
                    yield Event(
                        category="auth.sudo_command",
                        summary=f"sudo 명령 관측: {actor} → {command}",
                        evidence=evidence,
                        timestamp_raw=timestamp_raw,
                        timestamp_utc=timestamp_utc,
                        timezone_status=timezone_status,
                        user=actor,
                        fields={
                            "command": command,
                            "run_as_user": values.get("user"),
                            "working_directory": values.get("pwd"),
                            "tty": values.get("tty"),
                            **time_fields,
                        },
                    )

            if not matched:
                unparsed += 1
                # Unknown auth formats remain searchable and retain exact line evidence.
                yield Event(
                    category="linux_auth.unparsed",
                    summary="지원 인증 로그 형식으로 해석하지 못한 원문",
                    evidence=evidence,
                    timestamp_raw=timestamp_raw,
                    timestamp_utc=timestamp_utc,
                    timezone_status=timezone_status,
                    fields={"raw_preserved": True, **time_fields},
                )

            if want_flags:
                for value in extract_flags(item.text, context.flag_prefixes):
                    yield Finding(
                        rule_id="linux_auth.flag_candidate",
                        title="인증 로그의 플래그 형태 문자열 후보",
                        observation=f"플래그 형태 문자열을 관측했습니다: {value}",
                        interpretation=(
                            "로그 문자열 후보이며 정답 여부는 원문 문맥 확인이 필요합니다."
                        ),
                        confidence="medium",
                        evidence=evidence,
                        fields={"value": value},
                    )
                yield from decoded_items(
                    context,
                    item.text,
                    evidence,
                    rule_prefix="linux_auth",
                    tracker=decode_tracker,
                )
            if processed % PROGRESS_INTERVAL == 0:
                yield progress("linux_auth", processed, "인증 이벤트 집계 중")

        yield Finding(
            rule_id="linux_auth.summary",
            title="인증 및 sudo 집계",
            observation=(
                f"SSH 성공 {counters['success']:,}건, 실패 {counters['failure']:,}건, "
                f"sudo 명령 {counters['sudo']:,}건을 관측했습니다. 미해석 {unparsed:,}줄입니다."
            ),
            interpretation="관측 횟수 요약이며 계정 침해 여부를 확정하지 않습니다.",
            confidence="high",
            fields={
                "processed_lines": processed,
                "success": counters["success"],
                "failure": counters["failure"],
                "sudo": counters["sudo"],
                "unparsed": unparsed,
                "users": dict(users.most_common(50)),
                "source_ips": dict(source_ips.most_common(50)),
            },
        )
        if unparsed:
            ratio = unparsed / processed if processed else 0.0
            yield Diagnostic(
                level="warning",
                stage="parse",
                message=f"지원하지 않는 인증 로그 형식 비율: {ratio:.1%} ({unparsed:,}줄)",
                next_action="미해석 줄은 원문으로 보존되었습니다. generic text 분석도 확인하세요.",
            )
        yield progress("linux_auth", processed, "인증 로그 분석 완료")
