"""Core-owned, bounded persistence for analyzer-derived byte artifacts."""

from __future__ import annotations

import hashlib
import re
from pathlib import Path

from .models import Artifact, EvidenceRef

_SAFE_NAME = re.compile(r"[^A-Za-z0-9._-]+")


class SafeArtifactSink:
    def __init__(self, directory: Path, *, max_artifact_bytes: int = 32 * 1024 * 1024) -> None:
        self.directory = directory.resolve()
        self.max_artifact_bytes = max_artifact_bytes

    def write_bytes(
        self,
        suggested_name: str,
        data: bytes,
        *,
        kind: str,
        analyzer: str,
        evidence: EvidenceRef,
    ) -> Artifact:
        if len(data) > self.max_artifact_bytes:
            raise ValueError(
                f"파생 파일 {len(data):,}바이트가 개별 제한 "
                f"{self.max_artifact_bytes:,}바이트를 초과합니다."
            )
        name = _SAFE_NAME.sub("_", Path(suggested_name).name).strip("._") or "artifact.bin"
        self.directory.mkdir(parents=True, exist_ok=True)
        stem = Path(name).stem[:100] or "artifact"
        suffix = Path(name).suffix[:20]
        candidate = self.directory / f"{stem}{suffix}"
        counter = 1
        while candidate.exists():
            candidate = self.directory / f"{stem}-{counter}{suffix}"
            counter += 1
        with candidate.open("xb") as stream:
            stream.write(data)
        return Artifact(
            path=str(candidate),
            sha256=hashlib.sha256(data).hexdigest(),
            kind=kind,
            analyzer=analyzer,
            evidence=evidence,
        )
