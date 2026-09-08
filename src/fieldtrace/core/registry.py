"""Explicit analyzer registration and capability selection."""

from __future__ import annotations

from dataclasses import dataclass

from .models import Analyzer, Capability, Environment, SourceFormat


@dataclass(frozen=True, slots=True)
class AnalyzerChoice:
    analyzer: Analyzer
    capability: Capability


class AnalyzerRegistry:
    """An explicit registry; it never imports or executes arbitrary plugins."""

    def __init__(self, analyzers: tuple[Analyzer, ...] = ()) -> None:
        self._analyzers: dict[str, Analyzer] = {}
        for analyzer in analyzers:
            self.register(analyzer)

    def register(self, analyzer: Analyzer) -> None:
        if not analyzer.name or analyzer.name in self._analyzers:
            raise ValueError(f"중복되거나 비어 있는 분석기 이름: {analyzer.name!r}")
        if not analyzer.formats:
            raise ValueError(f"분석기 {analyzer.name}에 지원 형식이 없습니다.")
        self._analyzers[analyzer.name] = analyzer

    def all(self) -> tuple[Analyzer, ...]:
        return tuple(self._analyzers.values())

    def get(self, name: str) -> Analyzer:
        try:
            return self._analyzers[name]
        except KeyError as exc:
            raise KeyError(f"등록되지 않은 분석기: {name}") from exc

    def candidates(self, source_format: SourceFormat) -> tuple[Analyzer, ...]:
        return tuple(
            analyzer for analyzer in self._analyzers.values() if source_format in analyzer.formats
        )

    def available(
        self,
        source_format: SourceFormat,
        environment: Environment,
        *,
        selected_tasks: frozenset[str] = frozenset(),
    ) -> tuple[list[AnalyzerChoice], list[tuple[Analyzer, Capability]]]:
        usable: list[AnalyzerChoice] = []
        unavailable: list[tuple[Analyzer, Capability]] = []
        for analyzer in self.candidates(source_format):
            try:
                capability = analyzer.capabilities(environment)
            except Exception as exc:
                capability = Capability(False, f"기능 확인 실패: {exc}")
            if capability.available and self._matches_tasks(analyzer, capability, selected_tasks):
                usable.append(AnalyzerChoice(analyzer, capability))
            elif not capability.available:
                unavailable.append((analyzer, capability))
        return usable, unavailable

    @staticmethod
    def _matches_tasks(
        analyzer: Analyzer, capability: Capability, selected_tasks: frozenset[str]
    ) -> bool:
        if not selected_tasks:
            return True
        declared = set(capability.features)
        declared.update(getattr(analyzer, "tasks", ()))
        # General analyzers with no task declaration remain eligible so custom
        # searches still retain their raw evidence foundation.
        return not declared or bool(declared & selected_tasks)
