"""Cancellation-aware external tool execution without a shell."""

from __future__ import annotations

import os
import selectors
import signal
import subprocess
import tempfile
import time
from contextlib import suppress
from pathlib import Path
from threading import Event


class ExternalToolError(RuntimeError):
    """Base class for controlled external tool failures."""


class ExternalToolTimeout(ExternalToolError):
    pass


class ExternalToolCancelled(ExternalToolError):
    pass


class SafeExternalRunner:
    def __init__(self, *, default_timeout: float = 120, default_max_output: int = 8_388_608):
        self.default_timeout = default_timeout
        self.default_max_output = default_max_output

    def run(
        self,
        argv: list[str],
        *,
        cancel: Event,
        timeout: float | None = None,
        max_output_bytes: int | None = None,
        env: dict[str, str] | None = None,
    ) -> tuple[int, str, str]:
        if not argv or not all(isinstance(arg, str) and "\x00" not in arg for arg in argv):
            raise ValueError("외부 명령 argv는 NUL 없는 문자열 배열이어야 합니다.")
        limit = self.default_max_output if max_output_bytes is None else max_output_bytes
        if limit <= 0:
            raise ValueError("max_output_bytes는 0보다 커야 합니다.")
        if cancel.is_set():
            raise ExternalToolCancelled("사용자가 외부 도구 실행을 취소했습니다.")
        deadline = time.monotonic() + (self.default_timeout if timeout is None else timeout)
        safe_env = self._environment(env)
        isolated_home = tempfile.TemporaryDirectory(prefix="fieldtrace-tool-")
        safe_env["HOME"] = isolated_home.name
        safe_env["XDG_CONFIG_HOME"] = isolated_home.name
        if os.name == "nt":
            safe_env["USERPROFILE"] = isolated_home.name
        creationflags = 0
        start_new_session = os.name != "nt"
        if os.name == "nt":
            creationflags = subprocess.CREATE_NEW_PROCESS_GROUP
        try:
            process = subprocess.Popen(
                argv,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                shell=False,
                env=safe_env,
                start_new_session=start_new_session,
                creationflags=creationflags,
            )
        except OSError as exc:
            isolated_home.cleanup()
            raise ExternalToolError(
                f"외부 도구를 시작할 수 없습니다: {Path(argv[0]).name}: {exc}"
            ) from exc
        assert process.stdout is not None
        assert process.stderr is not None
        selector = selectors.DefaultSelector()
        selector.register(process.stdout, selectors.EVENT_READ, "stdout")
        selector.register(process.stderr, selectors.EVENT_READ, "stderr")
        buffers = {"stdout": bytearray(), "stderr": bytearray()}
        truncated = {"stdout": False, "stderr": False}
        timed_out = False
        drain_deadline: float | None = None
        try:
            while selector.get_map():
                if cancel.is_set():
                    self._terminate(process)
                    raise ExternalToolCancelled("사용자가 외부 도구 실행을 취소했습니다.")
                if not timed_out and time.monotonic() >= deadline:
                    self._terminate(process)
                    timed_out = True
                    drain_deadline = time.monotonic() + 1
                if drain_deadline is not None and time.monotonic() >= drain_deadline:
                    for key in list(selector.get_map().values()):
                        selector.unregister(key.fileobj)
                    break
                for key, _mask in selector.select(timeout=0.1):
                    chunk = os.read(key.fileobj.fileno(), 65_536)
                    if not chunk:
                        selector.unregister(key.fileobj)
                        continue
                    target = buffers[key.data]
                    remaining = limit - len(target)
                    if remaining > 0:
                        target.extend(chunk[:remaining])
                    if len(chunk) > remaining:
                        truncated[key.data] = True
            return_code = 124 if timed_out else process.wait(timeout=1)
        finally:
            selector.close()
            process.stdout.close()
            process.stderr.close()
            if process.poll() is None:
                self._terminate(process)
            isolated_home.cleanup()
        decoded: list[str] = []
        for name in ("stdout", "stderr"):
            value = buffers[name].decode("utf-8", errors="replace")
            if truncated[name]:
                value += "\n[FieldTrace: 출력 제한으로 나머지 생략]"
            decoded.append(value)
        if truncated["stdout"]:
            decoded[1] += "\n[FieldTrace: stdout 출력 제한 도달]"
        if timed_out:
            decoded[1] += (
                f"\n[FieldTrace: 외부 도구 제한 시간({timeout or self.default_timeout:g}초) 초과]"
            )
        return return_code, decoded[0], decoded[1]

    @staticmethod
    def _environment(overrides: dict[str, str] | None) -> dict[str, str]:
        allowed = ("PATH", "SYSTEMROOT", "WINDIR", "TMPDIR", "TEMP", "TMP")
        result = {key: os.environ[key] for key in allowed if key in os.environ}
        result.update({"LC_ALL": "C.UTF-8", "LANG": "C.UTF-8"})
        if overrides:
            if any("\x00" in key or "\x00" in value for key, value in overrides.items()):
                raise ValueError("환경 변수에는 NUL을 넣을 수 없습니다.")
            result.update(overrides)
        return result

    @staticmethod
    def _terminate(process: subprocess.Popen[bytes]) -> None:
        if os.name == "nt" and process.poll() is not None:
            return
        if os.name != "nt":
            try:
                os.killpg(process.pid, signal.SIGTERM)
                process.wait(timeout=1)
            except (OSError, subprocess.TimeoutExpired):
                pass
            # A child may exit while descendants in its process group retain
            # our pipes. Always clean the remaining group after the grace time.
            with suppress(OSError):
                os.killpg(process.pid, signal.SIGKILL)
        else:
            try:
                process.terminate()
                process.wait(timeout=1)
            except (OSError, subprocess.TimeoutExpired):
                try:
                    process.kill()
                    process.wait(timeout=1)
                except (OSError, subprocess.TimeoutExpired):
                    pass
