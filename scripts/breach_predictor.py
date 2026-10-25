"""Predictive breach likelihood scoring."""
from __future__ import annotations
import logging
from typing import Any
logger = logging.getLogger(__name__)

class BreachPredictor:
    def score(self, finding: dict[str, Any]) -> float:
        base = finding.get("threat_score", 0) / 100.0
        cves = finding.get("cves", [])
        if cves:
            base += 0.1
        return min(1.0, base)
