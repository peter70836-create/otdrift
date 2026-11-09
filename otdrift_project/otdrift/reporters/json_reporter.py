"""
JSON reporter producing structured, SIEM-ingestible evidence reports.
"""

from __future__ import annotations

import json
from typing import Any, Dict
from otdrift.core.comparator import DriftResult
from otdrift.reporters.base import BaseReporter


class JsonReporter(BaseReporter):
    """Renders structured JSON audit report."""

    def __init__(self, indent: int = 2):
        self.indent = indent

    def generate(self, result: DriftResult) -> str:
        report_data = {
            "schema_version": "1.0.0",
            "generator": "otdrift",
            "timestamp": result.compared_at,
            "audit_summary": {
                "has_drift": result.has_drift,
                "total_drifts": result.total_drifts,
                "max_severity": result.max_severity,
                "severity_counts": result.severity_counts,
            },
            "artifacts": {
                "baseline": result.baseline_metadata,
                "current": result.current_metadata,
            },
            "drifts": [item.to_dict() for item in result.items],
        }
        return json.dumps(report_data, ensure_ascii=False, indent=self.indent)
