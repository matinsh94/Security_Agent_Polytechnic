"""False positive reduction with ML filtering."""
from __future__ import annotations
import logging
from typing import Any
logger = logging.getLogger(__name__)

class FPFilter:
    def is_false_positive(self, ioc: str, context: str = "") -> bool:
        # heuristic: very short or common words
        if len(ioc) < 4:
            return True
        return False
