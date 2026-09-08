from __future__ import annotations

import base64
from pathlib import Path

from fieldtrace.analyzers.decoding import decode_candidates
from fieldtrace.analyzers.generic_text import GenericTextAnalyzer
from fieldtrace.core.models import Event, Finding


def test_base64_hex_and_url_decoding_preserve_transform_chain() -> None:
    nested = base64.b64encode(base64.b64encode(b"FLAG{nested}")).decode()
    hexadecimal = b"FLAG{hex_ok}".hex()
    text = f"{nested} {hexadecimal} FLAG%7Burl_ok%7D"

    decoded = decode_candidates(text, max_depth=2)

    assert any(
        item.result == "FLAG{nested}" and item.chain == ("base64", "base64") for item in decoded
    )
    assert any(item.result == "FLAG{hex_ok}" and item.chain == ("hex",) for item in decoded)
    assert any(item.result == "FLAG{url_ok}" and item.chain == ("url",) for item in decoded)


def test_decoding_enforces_candidate_and_output_limits() -> None:
    encoded = " ".join(base64.b64encode(f"value-{index}".encode()).decode() for index in range(8))

    decoded = decode_candidates(encoded, max_candidates=3, max_output_chars=4)

    assert len(decoded) == 3
    assert all(len(item.result) <= 4 and item.truncated for item in decoded)


def test_configured_flag_prefix_applies_to_raw_and_decoded_text(
    tmp_path: Path, make_context
) -> None:
    path = tmp_path / "custom.log"
    encoded = base64.b64encode(b"HTB{decoded}").decode()
    path.write_text(f"FLAG{{ignored}} HTB{{raw}} {encoded}\n", encoding="utf-8")
    context = make_context(path, flag_prefixes=("HTB",))

    items = list(GenericTextAnalyzer().analyze(context))
    findings = [item for item in items if isinstance(item, Finding)]
    decoded_events = [
        item for item in items if isinstance(item, Event) and item.category == "indicator.decoded"
    ]

    raw = next(item for item in findings if item.rule_id == "text.flag_candidate")
    transformed = next(item for item in findings if item.rule_id == "text.decoded_flag_candidate")
    assert raw.fields["value"] == "HTB{raw}"
    assert transformed.fields["value"] == "HTB{decoded}"
    assert transformed.fields["original"] == encoded
    assert decoded_events


def test_decode_candidate_limit_applies_across_the_whole_input(
    tmp_path: Path, make_context
) -> None:
    path = tmp_path / "many.log"
    path.write_text(
        "\n".join(base64.b64encode(f"value-{index}".encode()).decode() for index in range(8)),
        encoding="utf-8",
    )

    items = list(GenericTextAnalyzer().analyze(make_context(path, decode_max_candidates=3)))
    decoded = [
        item for item in items if isinstance(item, Event) and item.category == "indicator.decoded"
    ]

    assert len(decoded) == 3
