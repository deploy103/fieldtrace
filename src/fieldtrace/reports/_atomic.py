"""Atomic report writes that do not leave a successful-looking partial file."""

from __future__ import annotations

import os
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager, suppress
from pathlib import Path
from typing import TextIO


class OutputWriteError(OSError):
    """A report write failure with a field-friendly recovery action."""

    def __init__(self, output: Path, exc: OSError) -> None:
        detail = str(exc).strip() or type(exc).__name__
        folded = detail.casefold()
        self.stage = "보고서 저장"
        if exc.errno == 28 or "disk full" in folded or "no space" in folded:
            self.reason = f"보고서를 저장할 디스크 공간이 부족합니다: {output}"
            self.next_action = "출력 디스크 공간을 확보하고 보고서 저장을 다시 실행하세요."
        elif exc.errno in {13, 30}:
            self.reason = f"보고서 출력 경로에 쓸 수 없습니다: {output}"
            self.next_action = "쓰기 가능한 출력 경로를 지정하세요."
        else:
            self.reason = f"보고서를 완전하게 저장하지 못했습니다: {detail}"
            self.next_action = "출력 경로, 권한, 디스크 상태를 확인하고 다시 실행하세요."
        super().__init__(f"{self.reason} 다음 행동: {self.next_action}")


@contextmanager
def atomic_text_output(
    output: Path,
    *,
    encoding: str,
    newline: str | None = None,
) -> Iterator[TextIO]:
    temporary: Path | None = None
    stream: TextIO | None = None
    try:
        output.parent.mkdir(parents=True, exist_ok=True)
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=f".{output.name}.", suffix=".part", dir=output.parent
        )
        temporary = Path(temporary_name)
        try:
            stream = os.fdopen(descriptor, "w", encoding=encoding, newline=newline)
        except BaseException:
            os.close(descriptor)
            raise
        with stream:
            yield stream
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, output)
    except OSError as exc:
        if stream is not None and not stream.closed:
            stream.close()
        if temporary is not None:
            with suppress(OSError):
                temporary.unlink(missing_ok=True)
        raise OutputWriteError(output, exc) from exc
    except BaseException:
        if stream is not None and not stream.closed:
            stream.close()
        if temporary is not None:
            with suppress(OSError):
                temporary.unlink(missing_ok=True)
        raise
