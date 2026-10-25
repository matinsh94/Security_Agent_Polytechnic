"""Zero-day vulnerability prediction heuristic."""
from __future__ import annotations
import logging
from typing import Any
logger = logging.getLogger(__name__)

class ZeroDayPredictor:
    def predict(self, text: str) -> float:
        text_l = (text or "").lower()
        score = 0.0
        if "zero-day" in text_l or "0day" in text_l:
            score += 0.5
        if "unpatched" in text_l:
            score += 0.3
        return min(1.0, score)
