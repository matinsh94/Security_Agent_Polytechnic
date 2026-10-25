"""Custom threat classification model."""
from __future__ import annotations
import logging, os, pickle
from typing import Any
logger = logging.getLogger(__name__)

class ThreatClassifier:
    def __init__(self, model_path: str = "data/threat_classifier.pkl"):
        self.model_path = model_path
        self.model = None
        self._load()

    def _load(self):
        if os.path.exists(self.model_path):
            try:
                with open(self.model_path, "rb") as f:
                    self.model = pickle.load(f)
            except Exception as e:
                logger.warning("model load failed: %s", e)

    def train(self, texts: list[str], labels: list[int]) -> None:
        try:
            from sklearn.pipeline import Pipeline
            from sklearn.feature_extraction.text import TfidfVectorizer
            from sklearn.linear_model import LogisticRegression
            pipe = Pipeline([("tfidf", TfidfVectorizer()), ("clf", LogisticRegression(max_iter=200))])
            pipe.fit(texts, labels)
            self.model = pipe
            os.makedirs(os.path.dirname(self.model_path) or ".", exist_ok=True)
            with open(self.model_path, "wb") as f:
                pickle.dump(pipe, f)
        except Exception as e:
            logger.warning("training failed: %s", e)

    def predict(self, text: str) -> int:
        if self.model is None:
            return 0
        try:
            return int(self.model.predict([text])[0])
        except Exception:
            return 0
