"""OpenCanary event analytics package.

The package contains the normalization, ingestion, correlation, and SQLite
persistence layers.  The command-line entry point is available with::

    python -m opencanary_analytics
"""

from .models import Aggregate, Alert, NormalizedEvent, ProcessResult, RiskAssessment, RuleHit
from .pipeline import AnalyticsPipeline, PipelineStats
from .storage import SQLiteStore

__all__ = [
    "Aggregate",
    "Alert",
    "AnalyticsPipeline",
    "NormalizedEvent",
    "PipelineStats",
    "ProcessResult",
    "RiskAssessment",
    "RuleHit",
    "SQLiteStore",
]

__version__ = "0.1.0"
