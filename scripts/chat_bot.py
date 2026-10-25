"""Chat bot for Slack/Teams/Discord real-time alerts."""
from __future__ import annotations
import json, logging, os
from typing import Any
try:
    import requests
except ImportError:
    requests = None
logger = logging.getLogger(__name__)

class ChatBot:
    def __init__(self):
        self.slack_webhook = os.getenv("SLACK_WEBHOOK_URL")
        self.discord_webhook = os.getenv("DISCORD_WEBHOOK_URL")
        self.teams_webhook = os.getenv("TEAMS_WEBHOOK_URL")

    def send(self, message: str, channel: str | None = None) -> dict[str, bool]:
        results = {}
        targets = [("slack", self.slack_webhook), ("discord", self.discord_webhook), ("teams", self.teams_webhook)]
        for name, url in targets:
            if url and (channel is None or channel == name):
                results[name] = self._post(url, {"text": message} if name != "discord" else {"content": message})
        return results

    def _post(self, url, payload):
        if requests is None:
            return False
        try:
            r = requests.post(url, json=payload, timeout=15)
            return r.status_code < 300
        except Exception as e:
            logger.error("Chat bot post failed: %s", e)
            return False
