"""Small, explainable network candidate rules; none assert an attack occurred."""

from __future__ import annotations

import re

DNS_QUERY_LENGTH = 100
DNS_LABEL_LENGTH = 50
DNS_FREQUENCY = 20

_SQL_RE = re.compile(
    r"(?i)(?:\bunion\s+(?:all\s+)?select\b|\bselect\b.+\bfrom\b|\bor\s+1\s*=\s*1\b)"
)
_SENSITIVE_PATHS = ("/etc/passwd", "/proc/self/", "win.ini", "web.config", ".env")


def dns_length_reasons(query: str) -> list[str]:
    reasons: list[str] = []
    normalized = query.rstrip(".")
    if len(normalized) >= DNS_QUERY_LENGTH:
        reasons.append(f"전체 질의 길이 {len(normalized)}자")
    longest = max((len(label) for label in normalized.split(".")), default=0)
    if longest >= DNS_LABEL_LENGTH:
        reasons.append(f"가장 긴 라벨 {longest}자")
    return reasons


def http_request_reasons(method: str, uri_raw: str, uri_decoded: str) -> list[str]:
    reasons: list[str] = []
    lowered = uri_decoded.casefold()
    raw_lowered = uri_raw.casefold()
    if "../" in lowered or "..\\" in lowered or "%2e%2e" in raw_lowered:
        reasons.append("상위 경로 이동 표현")
    matched_paths = [path for path in _SENSITIVE_PATHS if path in lowered]
    if matched_paths:
        reasons.append(f"민감 경로 문자열 {matched_paths[0]}")
    if _SQL_RE.search(uri_decoded):
        reasons.append("SQL 문법 형태 문자열")
    if any(marker in uri_decoded for marker in (";", "|", "$(", "`")):
        reasons.append("명령 연결에 쓰일 수 있는 구분자")
    if "%00" in raw_lowered or "\x00" in uri_decoded:
        reasons.append("NUL 바이트 표현")
    if method.upper() in {"TRACE", "CONNECT"}:
        reasons.append(f"검토가 필요한 HTTP 메서드 {method.upper()}")
    return reasons
