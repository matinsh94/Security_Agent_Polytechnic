"""SIEM connector for Splunk HEC, ELK, and Sumo Logic."""
from __future__ import annotations
import json, logging, os
from typing import Any
try:
    import requests
except ImportError:
    requests = None

logger = logging.getLogger(__name__)

class SIEMConnector:
    def __init__(self):
        self.splunk_hec_url = os.getenv("SPLUNK_HEC_URL")
        self.splunk_hec_token = os.getenv("SPLUNK_HEC_TOKEN")
        self.elk_url = os.getenv("ELK_URL")
        self.sumo_url = os.getenv("SUMO_LOGIC_URL")
        self.timeout = int(os.getenv("FEED_TIMEOUT", "15"))

    def send(self, events: list[dict[str, Any]]) -> dict[str, bool]:
        normalized = [{"event": e, "source": "cti-platform"} for e in events]
        results = {}
        if self.splunk_hec_url and self.splunk_hec_token:
            results["splunk"] = self._send_with_retry(self._send_splunk, normalized)
        if self.elk_url:
            results["elk"] = self._send_with_retry(self._send_elk, normalized)
        if self.sumo_url:
            results["sumo"] = self._send_with_retry(self._send_sumo, normalized)
        if not results:
            logger.info("SIEM not configured; skipping")
        return results

    def _send_with_retry(self, fn, events, attempts=3):
        for i in range(attempts):
            if fn(events):
                return True
        return False

    def _post(self, url, headers, payload):
        if requests is None:
            return False
        try:
            r = requests.post(url, headers=headers, json=payload, timeout=self.timeout)
            return r.status_code < 300
        except Exception as e:
            logger.error("SIEM post failed: %s", e)
            return False

    def _send_splunk(self, events):
        payload = [{"event": e} for e in events]
        return self._post(self.splunk_hec_url, {"Authorization": f"Splunk {self.splunk_hec_token}"}, payload)

    def _send_elk(self, events):
        return self._post(f"{self.elk_url}/_bulk", {"Content-Type": "application/json"}, {"docs": events})

    def _send_sumo(self, events):
        return self._post(self.sumo_url, {"Content-Type": "application/json"}, events)
