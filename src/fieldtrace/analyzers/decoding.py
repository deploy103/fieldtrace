"""Conservative, bounded decoding helpers for analyst-visible candidates."""

from __future__ import annotations

import base64
import binascii
import re
from collections.abc import Iterator
from dataclasses import dataclass
from urllib.parse import unquote

from fieldtrace.analyzers._common import extract_flags
from fieldtrace.core.models import AnalysisContext, Event, EvidenceRef, Finding

_BASE64_RE = re.compile(r"(?<![A-Za-z0-9+/])(?:[A-Za-z0-9+/]{8,}={0,2})(?![A-Za-z0-9+/=])")
_HEX_RE = re.compile(r"(?<![0-9A-Fa-f])(?:[0-9A-Fa-f]{2}){4,}(?![0-9A-Fa-f])")
_URL_RE = re.compile(r"[^\s\"'<>]{0,4096}%[0-9A-Fa-f]{2}[^\s\"'<>]{0,4096}")
_MAX_ENCODED_CHARS = 8_192


@dataclass(frozen=True, slots=True)
class DecodedValue:
    original: str
    encoded: str
    transformation: str
    result: str
    depth: int
    chain: tuple[str, ...]
    truncated: bool = False


@dataclass(slots=True)
class DecodeTracker:
    emitted: int = 0


def _readable_utf8(value: bytes) -> str | None:
    try:
        decoded = value.decode("utf-8")
    except UnicodeDecodeError:
        return None
    if not decoded or "\x00" in decoded:
        return None
    readable = sum(character.isprintable() or character in "\t\r\n" for character in decoded)
    if readable / len(decoded) < 0.85:
        return None
    return decoded


def _decode_once(value: str) -> list[tuple[str, str]]:
    results: list[tuple[str, str]] = []
    if len(value) > _MAX_ENCODED_CHARS:
        return results
    if re.search(r"%[0-9A-Fa-f]{2}", value):
        decoded = unquote(value, errors="replace")
        if decoded != value:
            results.append(("url", decoded))
    if _BASE64_RE.fullmatch(value):
        padded = value + "=" * (-len(value) % 4)
        try:
            decoded_bytes = base64.b64decode(padded, validate=True)
        except (binascii.Error, ValueError):
            pass
        else:
            decoded = _readable_utf8(decoded_bytes)
            if decoded is not None and decoded != value:
                results.append(("base64", decoded))
    if _HEX_RE.fullmatch(value) and any(character.casefold() in "abcdef" for character in value):
        try:
            decoded_bytes = bytes.fromhex(value)
        except ValueError:
            pass
        else:
            decoded = _readable_utf8(decoded_bytes)
            if decoded is not None and decoded != value:
                results.append(("hex", decoded))
    return results


def _encoded_candidates(text: str) -> list[str]:
    values: list[str] = []
    for pattern in (_URL_RE, _BASE64_RE, _HEX_RE):
        for match in pattern.finditer(text):
            value = match.group(0).strip(".,;:()[]")
            if value and value not in values:
                values.append(value)
    return values


def decode_candidates(
    text: str,
    *,
    max_depth: int = 2,
    max_output_chars: int = 4_096,
    max_candidates: int = 20,
) -> list[DecodedValue]:
    """Decode only plausible tokens and stop at all configured expansion limits."""

    if max_depth <= 0 or max_output_chars <= 0 or max_candidates <= 0:
        return []
    queue: list[tuple[str, str, int, tuple[str, ...]]] = [
        (candidate, candidate, 1, ()) for candidate in _encoded_candidates(text)
    ]
    results: list[DecodedValue] = []
    seen_steps: set[tuple[str, str, tuple[str, ...]]] = set()
    while queue and len(results) < max_candidates:
        original, encoded, depth, chain = queue.pop(0)
        if depth > max_depth:
            continue
        for transformation, decoded in _decode_once(encoded):
            next_chain = (*chain, transformation)
            key = (original, decoded, next_chain)
            if key in seen_steps:
                continue
            seen_steps.add(key)
            truncated = len(decoded) > max_output_chars
            displayed = decoded[:max_output_chars]
            results.append(
                DecodedValue(
                    original=original[:max_output_chars],
                    encoded=encoded[:max_output_chars],
                    transformation=transformation,
                    result=displayed,
                    depth=depth,
                    chain=next_chain,
                    truncated=truncated or len(original) > max_output_chars,
                )
            )
            if len(results) >= max_candidates:
                break
            if not truncated and depth < max_depth:
                nested = _encoded_candidates(decoded)
                if decoded not in nested:
                    nested.insert(0, decoded)
                queue.extend((original, value, depth + 1, next_chain) for value in nested)
    return results


def decoded_items(
    context: AnalysisContext,
    text: str,
    evidence: EvidenceRef,
    *,
    rule_prefix: str,
    tracker: DecodeTracker | None = None,
) -> Iterator[Event | Finding]:
    """Create traceable analysis items for bounded transforms and decoded flags."""

    active_tracker = tracker or DecodeTracker()
    remaining = context.decode_max_candidates - active_tracker.emitted
    if remaining <= 0:
        return
    for candidate in decode_candidates(
        text,
        max_depth=context.decode_max_depth,
        max_output_chars=context.decode_max_output_chars,
        max_candidates=remaining,
    ):
        active_tracker.emitted += 1
        fields = {
            "original": candidate.original,
            "encoded": candidate.encoded,
            "transformation": candidate.transformation,
            "chain": list(candidate.chain),
            "result": candidate.result,
            "depth": candidate.depth,
            "truncated": candidate.truncated,
        }
        chain = " → ".join(candidate.chain)
        yield Event(
            category="indicator.decoded",
            summary=f"제한 디코딩 관측({chain}): {candidate.result}",
            evidence=evidence,
            fields=fields,
        )
        for value in extract_flags(candidate.result, context.flag_prefixes):
            yield Finding(
                rule_id=f"{rule_prefix}.decoded_flag_candidate",
                title="디코딩 결과의 플래그 형태 문자열 후보",
                observation=(
                    f"{candidate.original} 문자열을 {chain} 변환한 결과에서 {value}를 관측했습니다."
                ),
                interpretation="제한된 변환 결과이며 정답 여부는 원본 근거에서 확인해야 합니다.",
                confidence="medium",
                evidence=evidence,
                fields={**fields, "value": value},
            )
