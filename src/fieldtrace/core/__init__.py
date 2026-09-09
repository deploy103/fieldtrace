"""Core services and stable public interfaces."""

from .cases import (
    CASE_DB_NAME,
    CaseInUseError,
    CasePaths,
    case_analysis_lock,
    case_paths,
    create_case,
    prepare_case,
)
from .config import ConfigError, RuntimeConfig, load_config
from .db import SCHEMA_VERSION, CaseDatabaseError, CaseStore, SchemaError
from .detector import DetectionResult, FormatDetector
from .doctor import DoctorCheck, DoctorResult, detect_environment, run_doctor
from .registry import AnalyzerRegistry
from .runner import (
    ExternalToolCancelled,
    ExternalToolError,
    ExternalToolTimeout,
    SafeExternalRunner,
)
from .search import CorrelationEntry, EvidenceDetail, SearchHit, TimelineEntry
from .service import FieldTraceService, InputError, builtin_registry, exit_code

__all__ = [
    "CASE_DB_NAME",
    "SCHEMA_VERSION",
    "AnalyzerRegistry",
    "CaseDatabaseError",
    "CaseInUseError",
    "CasePaths",
    "CaseStore",
    "ConfigError",
    "CorrelationEntry",
    "DetectionResult",
    "DoctorCheck",
    "DoctorResult",
    "EvidenceDetail",
    "ExternalToolCancelled",
    "ExternalToolError",
    "ExternalToolTimeout",
    "FieldTraceService",
    "FormatDetector",
    "InputError",
    "RuntimeConfig",
    "SafeExternalRunner",
    "SchemaError",
    "SearchHit",
    "TimelineEntry",
    "builtin_registry",
    "case_analysis_lock",
    "case_paths",
    "create_case",
    "detect_environment",
    "exit_code",
    "load_config",
    "prepare_case",
    "run_doctor",
]
