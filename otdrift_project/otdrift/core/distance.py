"""
Semantic and Weighted Drift Distance Calculator for Industrial OT/ICS Systems.
Implements formal mathematical distance metrics addressing physical process invariants.
"""

from __future__ import annotations

import math
from typing import Any, Dict, List, Optional
from otdrift.core.comparator import DriftItem


class LayerWeightRegistry:
    """Default hierarchical criticality weights aligned with ISA-95/Purdue model."""

    # Default weights by path prefix aligned with Purdue hierarchy
    PREFIX_WEIGHTS: Dict[str, float] = {
        # Level 1/0: Safety and Physical Process Invariants (Criticality: Highest)
        "safety_interlocks": 3.0,
        "safety_and_integrity": 3.0,
        "system_integrity": 3.0,
        "process_machining": 2.5,
        "tool_offset": 2.5,
        "process_registers": 2.5,
        # Level 1.5/2: Industrial Gateways, OpenWrt & Protocols
        "openwrt_gateway": 2.0,
        "firewall": 2.0,
        "uci_config": 2.0,
        "comm_policy": 2.0,
        "protocols": 2.0,
        # Level 2/3: Management & Administration
        "management": 1.5,
        # Level 3/Base: Network Topology & Assets
        "network": 1.0,
        "device_info": 0.5,
    }

    DEFAULT_WEIGHT: float = 1.0

    @classmethod
    def get_weight(cls, path: str, custom_weights: Optional[Dict[str, float]] = None) -> float:
        """Resolve the safety/operational criticality weight for a given parameter path."""
        weights = {**cls.PREFIX_WEIGHTS, **(custom_weights or {})}
        clean_path = path.lower().strip()

        # Check prefix matches
        for prefix, weight in weights.items():
            if clean_path.startswith(prefix.lower()):
                return weight

        return cls.DEFAULT_WEIGHT


class DriftDistanceCalculator:
    """
    Computes formal quantitative drift distance between baseline and current states.
    
    Formula:
      D(S0, St) = sum( w(p) * delta(v0, vt) )
    """

    def __init__(self, custom_weights: Optional[Dict[str, float]] = None):
        self.custom_weights = custom_weights or {}

    def calculate_delta(self, baseline_val: Any, current_val: Any) -> float:
        """
        Calculate normalized deviation delta in range [0.0, 1.0].
        
        - For identical values: 0.0
        - For numeric values: relative percentage deviation, capped at 1.0
        - For booleans / strings / lists: discrete jump of 1.0
        """
        if baseline_val == current_val:
            return 0.0

        # Numeric relative difference
        if isinstance(baseline_val, (int, float)) and isinstance(current_val, (int, float)):
            # Handle booleans separately since bool is a subclass of int in Python
            if isinstance(baseline_val, bool) or isinstance(current_val, bool):
                return 1.0

            denom = abs(baseline_val)
            if denom == 0:
                # If baseline is 0, absolute diff determines magnitude
                return min(1.0, abs(current_val))
            
            relative_diff = abs(current_val - baseline_val) / denom
            return min(1.0, float(relative_diff))

        # Boolean or discrete state flip
        if isinstance(baseline_val, bool) or isinstance(current_val, bool):
            return 1.0

        # List modifications (e.g. whitelist added/removed)
        if isinstance(baseline_val, list) and isinstance(current_val, list):
            b_set = set(str(x) for x in baseline_val)
            c_set = set(str(x) for x in current_val)
            union_len = len(b_set | c_set)
            if union_len == 0:
                return 0.0
            # Jaccard distance = 1 - (intersection / union)
            intersection_len = len(b_set & c_set)
            return 1.0 - (intersection_len / union_len)

        # Categorical string change or type change
        return 1.0

    def calculate_item_distance(self, item: DriftItem) -> float:
        """Calculate weighted semantic distance for a single drift item."""
        weight = LayerWeightRegistry.get_weight(item.path, self.custom_weights)
        delta = self.calculate_delta(item.baseline_value, item.current_value)
        return round(weight * delta, 4)

    def quantify_drifts(self, items: List[DriftItem]) -> Dict[str, Any]:
        """
        Enrich all drift items with calculated distances and compute aggregate metrics.
        Returns a summary dict with total_distance and normalized_risk_score.
        """
        total_distance = 0.0
        max_possible_distance = 0.0

        for item in items:
            weight = LayerWeightRegistry.get_weight(item.path, self.custom_weights)
            delta = self.calculate_delta(item.baseline_value, item.current_value)
            dist = round(weight * delta, 4)
            
            # Attach distance directly to item
            item.risk_score = max(item.risk_score, int(min(100, dist * 30)))
            total_distance += dist
            max_possible_distance += weight

        total_distance = round(total_distance, 4)

        # Normalize score into [0, 100] using a saturating transfer curve
        # A distance of 5.0+ represents critical compound compromise (Score -> 100)
        if total_distance == 0.0:
            normalized_score = 0
            ndi = 0.0
        else:
            normalized_score = min(100, int(round((1.0 - math.exp(-total_distance / 2.5)) * 100)))
            ndi = round(min(1.0, 1.0 - math.exp(-total_distance / 2.5)), 4)

        return {
            "total_drift_distance": total_distance,
            "w_sted_distance": total_distance,
            "normalized_drift_index": ndi,
            "normalized_risk_score": normalized_score,
            "drift_count": len(items),
        }
