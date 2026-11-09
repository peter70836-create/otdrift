"""
Core configuration drift comparison engine using DeepDiff.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
import deepdiff

from otdrift.core.normalizer import parse_deepdiff_path


class ChangeType(str, Enum):
    MODIFIED = "MODIFIED"
    ADDED = "ADDED"
    REMOVED = "REMOVED"
    TYPE_CHANGED = "TYPE_CHANGED"
    LIST_CHANGED = "LIST_CHANGED"


@dataclass
class DriftItem:
    """Represents an individual parameter difference."""
    path: str
    change_type: ChangeType
    baseline_value: Any
    current_value: Any
    description: str = ""
    # Enriched fields added by rule engine & distance calculator
    severity: str = "INFO"
    risk_score: int = 0
    drift_distance: float = 0.0
    mitre_technique_id: str = "N/A"
    mitre_technique_name: str = "Unmapped"
    mitre_tactic: str = "N/A"
    threat_description: str = ""
    remediation: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "path": self.path,
            "change_type": self.change_type.value,
            "baseline_value": self.baseline_value,
            "current_value": self.current_value,
            "description": self.description,
            "severity": self.severity,
            "risk_score": self.risk_score,
            "drift_distance": self.drift_distance,
            "mitre": {
                "technique_id": self.mitre_technique_id,
                "technique_name": self.mitre_technique_name,
                "tactic": self.mitre_tactic,
            },
            "threat_description": self.threat_description,
            "remediation": self.remediation,
        }


@dataclass
class DriftResult:
    """Encapsulates the complete comparison result between baseline and current configs."""
    baseline_metadata: Dict[str, Any]
    current_metadata: Dict[str, Any]
    items: List[DriftItem] = field(default_factory=list)
    compared_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    raw_deepdiff: Dict[str, Any] = field(default_factory=dict)
    total_drift_distance: float = 0.0
    w_sted_distance: float = 0.0
    normalized_drift_index: float = 0.0
    normalized_risk_score: int = 0

    @property
    def has_drift(self) -> bool:
        return len(self.items) > 0

    @property
    def total_drifts(self) -> int:
        return len(self.items)

    @property
    def max_severity(self) -> str:
        order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
        for s in order:
            if any(item.severity == s for item in self.items):
                return s
        return "CLEAN" if not self.items else "INFO"

    @property
    def severity_counts(self) -> Dict[str, int]:
        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for item in self.items:
            counts[item.severity] = counts.get(item.severity, 0) + 1
        return counts

    def to_dict(self) -> Dict[str, Any]:
        return {
            "compared_at": self.compared_at,
            "has_drift": self.has_drift,
            "total_drifts": self.total_drifts,
            "total_drift_distance": self.total_drift_distance,
            "w_sted_distance": self.w_sted_distance,
            "normalized_drift_index": self.normalized_drift_index,
            "normalized_risk_score": self.normalized_risk_score,
            "max_severity": self.max_severity,
            "severity_counts": self.severity_counts,
            "baseline": self.baseline_metadata,
            "current": self.current_metadata,
            "drifts": [item.to_dict() for item in self.items],
        }


class DriftComparator:
    """Performs structured deep difference calculation on configurations."""

    def __init__(self, ignore_order: bool = True, report_repetition: bool = True):
        self.ignore_order = ignore_order
        self.report_repetition = report_repetition

    def compare(
        self,
        baseline: Dict[str, Any],
        current: Dict[str, Any],
        baseline_meta: Optional[Dict[str, Any]] = None,
        current_meta: Optional[Dict[str, Any]] = None,
    ) -> DriftResult:
        """Execute deep diff comparison between baseline and current dictionary."""
        diff = deepdiff.DeepDiff(
            baseline,
            current,
            ignore_order=self.ignore_order,
            report_repetition=self.report_repetition,
            verbose_level=2,
        )

        items: List[DriftItem] = []

        # 1. Values Changed
        if "values_changed" in diff:
            for raw_path, change in diff["values_changed"].items():
                clean_path = parse_deepdiff_path(raw_path)
                old_val = change.get("old_value")
                new_val = change.get("new_value")
                items.append(
                    DriftItem(
                        path=clean_path,
                        change_type=ChangeType.MODIFIED,
                        baseline_value=old_val,
                        current_value=new_val,
                        description=f"Value modified from '{old_val}' to '{new_val}'",
                    )
                )

        # 2. Type Changes
        if "type_changes" in diff:
            for raw_path, change in diff["type_changes"].items():
                clean_path = parse_deepdiff_path(raw_path)
                old_val = change.get("old_value")
                new_val = change.get("new_value")
                items.append(
                    DriftItem(
                        path=clean_path,
                        change_type=ChangeType.TYPE_CHANGED,
                        baseline_value=old_val,
                        current_value=new_val,
                        description=(
                            f"Type altered from {type(old_val).__name__} to {type(new_val).__name__}"
                        ),
                    )
                )

        # 3. Dictionary Items Added
        if "dictionary_item_added" in diff:
            for item in diff["dictionary_item_added"]:
                clean_path = parse_deepdiff_path(item)
                if clean_path.startswith("_") or "._" in clean_path:
                    continue
                val = diff.get("tree_results", {}).get(item) if "tree_results" in diff else None
                # Retrieve from current dict if needed
                from otdrift.core.normalizer import get_nested_value
                val = get_nested_value(current, clean_path, default=None)
                items.append(
                    DriftItem(
                        path=clean_path,
                        change_type=ChangeType.ADDED,
                        baseline_value=None,
                        current_value=val,
                        description="New parameter added in current configuration",
                    )
                )

        # 4. Dictionary Items Removed
        if "dictionary_item_removed" in diff:
            for item in diff["dictionary_item_removed"]:
                clean_path = parse_deepdiff_path(item)
                from otdrift.core.normalizer import get_nested_value
                val = get_nested_value(baseline, clean_path, default=None)
                items.append(
                    DriftItem(
                        path=clean_path,
                        change_type=ChangeType.REMOVED,
                        baseline_value=val,
                        current_value=None,
                        description="Baseline parameter removed from current configuration",
                    )
                )

        # 5. Iterable / List Items Added
        if "iterable_item_added" in diff:
            for raw_path, val in diff["iterable_item_added"].items():
                clean_path = parse_deepdiff_path(raw_path)
                items.append(
                    DriftItem(
                        path=clean_path,
                        change_type=ChangeType.LIST_CHANGED,
                        baseline_value=None,
                        current_value=val,
                        description=f"Item added to array: {val}",
                    )
                )

        # 6. Iterable / List Items Removed
        if "iterable_item_removed" in diff:
            for raw_path, val in diff["iterable_item_removed"].items():
                clean_path = parse_deepdiff_path(raw_path)
                items.append(
                    DriftItem(
                        path=clean_path,
                        change_type=ChangeType.LIST_CHANGED,
                        baseline_value=val,
                        current_value=None,
                        description=f"Item removed from array: {val}",
                    )
                )

        # Sort items predictably by path
        items.sort(key=lambda x: x.path)

        return DriftResult(
            baseline_metadata=baseline_meta or {},
            current_metadata=current_meta or {},
            items=items,
            raw_deepdiff=dict(diff) if isinstance(diff, dict) else {},
        )


def compare_configs(
    baseline: Dict[str, Any],
    current: Dict[str, Any],
    baseline_meta: Optional[Dict[str, Any]] = None,
    current_meta: Optional[Dict[str, Any]] = None,
) -> DriftResult:
    """Convenience functional wrapper for DriftComparator."""
    comparator = DriftComparator()
    return comparator.compare(
        baseline, current, baseline_meta=baseline_meta, current_meta=current_meta
    )
