"""
Base reporter abstract class.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path
from typing import Optional
from otdrift.core.comparator import DriftResult


class BaseReporter(ABC):
    """Abstract interface for audit report generators."""

    @abstractmethod
    def generate(self, result: DriftResult) -> str:
        """Render report as a string."""
        pass

    def save(self, result: DriftResult, output_path: str | Path) -> None:
        """Render and save report to disk."""
        content = self.generate(result)
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
