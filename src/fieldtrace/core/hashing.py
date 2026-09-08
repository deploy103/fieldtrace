"""Streaming, cancellable SHA-256 jobs."""

from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass
from pathlib import Path
from threading import Event, Lock, Thread


@dataclass(frozen=True, slots=True)
class HashResult:
    status: str
    sha256: str | None
    bytes_read: int
    error: str | None = None


class HashJob:
    """A background hash whose progress may be polled while analysis starts."""

    def __init__(
        self,
        path: Path,
        cancel: Event,
        *,
        expected_size: int | None = None,
        expected_mtime_ns: int | None = None,
        chunk_size: int = 1_048_576,
    ) -> None:
        self.path = path
        self.cancel = cancel
        if expected_size is None or expected_mtime_ns is None:
            initial = path.stat()
            expected_size = initial.st_size if expected_size is None else expected_size
            expected_mtime_ns = (
                initial.st_mtime_ns if expected_mtime_ns is None else expected_mtime_ns
            )
        self.expected_size = expected_size
        self.expected_mtime_ns = expected_mtime_ns
        self.chunk_size = chunk_size
        self._done = Event()
        self._lock = Lock()
        self._bytes_read = 0
        self._result: HashResult | None = None
        self._thread = Thread(target=self._work, name=f"fieldtrace-hash-{path.name}", daemon=True)

    def start(self) -> HashJob:
        self._thread.start()
        return self

    @property
    def done(self) -> bool:
        return self._done.is_set()

    @property
    def bytes_read(self) -> int:
        with self._lock:
            return self._bytes_read

    def result(self, timeout: float | None = None) -> HashResult | None:
        if not self._done.wait(timeout):
            return None
        return self._result

    def _work(self) -> None:
        digest = hashlib.sha256()
        try:
            with self.path.open("rb") as stream:
                before = os.fstat(stream.fileno())
                if not self._matches_expected(before):
                    self._result = HashResult(
                        "changed", None, 0, "해시 시작 전에 입력 상태가 변경됨"
                    )
                    return
                while not self.cancel.is_set():
                    chunk = stream.read(self.chunk_size)
                    if not chunk:
                        after = os.fstat(stream.fileno())
                        path_after = self.path.stat()
                        stable_identity = (after.st_dev, after.st_ino) == (
                            path_after.st_dev,
                            path_after.st_ino,
                        )
                        if not self._matches_expected(after) or not stable_identity:
                            self._result = HashResult(
                                "changed",
                                None,
                                self.bytes_read,
                                "해시 도중 입력 상태가 변경됨",
                            )
                        else:
                            self._result = HashResult(
                                "complete", digest.hexdigest(), self.bytes_read
                            )
                        return
                    digest.update(chunk)
                    with self._lock:
                        self._bytes_read += len(chunk)
            self._result = HashResult("cancelled", None, self.bytes_read)
        except OSError as exc:
            self._result = HashResult("failed", None, self.bytes_read, str(exc))
        finally:
            self._done.set()

    def _matches_expected(self, stat: os.stat_result) -> bool:
        return stat.st_size == self.expected_size and stat.st_mtime_ns == self.expected_mtime_ns


def start_hash(
    path: Path | str,
    cancel: Event,
    *,
    expected_size: int,
    expected_mtime_ns: int,
) -> HashJob:
    return HashJob(
        Path(path).expanduser().resolve(),
        cancel,
        expected_size=expected_size,
        expected_mtime_ns=expected_mtime_ns,
    ).start()
