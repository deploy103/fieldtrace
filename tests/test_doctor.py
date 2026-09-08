from __future__ import annotations

from pathlib import Path

from fieldtrace.core.config import PathSettings, RuntimeConfig
from fieldtrace.core.doctor import run_doctor


class TSharkDoctorRunner:
    fields = (
        "frame.number",
        "frame.time_epoch",
        "frame.protocols",
        "ip.src",
        "ip.dst",
        "ipv6.src",
        "ipv6.dst",
        "tcp.srcport",
        "tcp.dstport",
        "udp.srcport",
        "udp.dstport",
        "dns.qry.name",
        "http.request.method",
        "http.host",
        "http.request.uri",
        "_ws.col.protocol",
    )

    def run(self, argv: list[str], **_kwargs: object) -> tuple[int, str, str]:
        if argv[1:] == ["--version"]:
            return 0, "TShark (Wireshark) 4.2.2\n", ""
        if argv[1:] == ["-G", "fields"]:
            output = "".join(
                f"F\tSynthetic\t{field}\tFT_STRING\tparent\t\t0x0\t\n"
                for field in self.fields
            )
            return 0, output, ""
        raise AssertionError(f"예상하지 않은 doctor 명령: {argv}")


def test_doctor_accepts_official_lowercase_protocol_pseudo_field(
    tmp_path: Path, monkeypatch
) -> None:
    monkeypatch.setattr(
        "fieldtrace.core.doctor.shutil.which",
        lambda command: "/usr/bin/tshark" if command == "tshark" else None,
    )
    config = RuntimeConfig(paths=PathSettings(cases=tmp_path / "cases"))

    result = run_doctor(config, runner=TSharkDoctorRunner())  # type: ignore[arg-type]

    assert result.ready
    assert not result.degraded
    field_check = next(check for check in result.checks if check.name == "TShark 필드")
    assert field_check.ok
    assert field_check.detail == "필수 필드 확인"
