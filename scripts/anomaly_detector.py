"""Anomaly detection in threat patterns."""
from __future__ import annotations
import logging, statistics
from typing import Any
logger = logging.getLogger(__name__)

class AnomalyDetector:
    def __init__(self):
        self.model = None
        try:
            from sklearn.ensemble import IsolationForest
            self.model = IsolationForest(contamination=0.1, random_state=42)
        except Exception:
            self.model = None

    def detect(self, series: list[float]) -> list[bool]:
        if not series:
            return []
        if self.model is not None and len(series) >= 10:
            try:
                import numpy as np
                X = np.array(series).reshape(-1, 1)
                preds = self.model.fit_predict(X)
                return [p == -1 for p in preds]
            except Exception as e:
                logger.warning("isolation forest failed: %s", e)
        # z-score fallback
        if len(series) < 2:
            return [False] * len(series)
        mean = statistics.mean(series)
        stdev = statistics.pstdev(series) or 1.0
        return [abs((x - mean) / stdev) > 2.0 for x in series]
