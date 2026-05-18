"""Optional alerting system for Telegram, Discord, and Slack."""

from __future__ import annotations

import json
import logging
import os
from typing import Optional

try:
    import requests
except ImportError:
    requests = None  # type: ignore


logger = logging.getLogger(__name__)


class Alerter:
    """Send threat intelligence alerts to multiple channels."""

    def __init__(self) -> None:
        """Initialize alerter with API credentials from environment."""
        self.telegram_bot_token = os.getenv('TELEGRAM_BOT_TOKEN')
        self.telegram_chat_id = os.getenv('TELEGRAM_CHAT_ID')
        self.discord_webhook = os.getenv('DISCORD_WEBHOOK_URL')
        self.slack_webhook = os.getenv('SLACK_WEBHOOK_URL')

    def send_critical_alert(self, title: str, threat_score: int, cve_id: str | None = None) -> bool:
        """Send alert for critical threats (score >= 90)."""
        if threat_score < 90:
            return False

        message = self._format_critical_message(title, threat_score, cve_id)

        results = {
            'telegram': self.send_telegram(message) if self.telegram_bot_token else False,
            'discord': self.send_discord(message) if self.discord_webhook else False,
            'slack': self.send_slack(message) if self.slack_webhook else False,
        }

        return any(results.values())

    def send_high_alert(self, title: str, threat_score: int, cve_id: str | None = None) -> bool:
        """Send alert for high threats (70-89)."""
        if threat_score < 70 or threat_score >= 90:
            return False

        message = self._format_high_message(title, threat_score, cve_id)

        results = {
            'telegram': self.send_telegram(message) if self.telegram_bot_token else False,
            'discord': self.send_discord(message) if self.discord_webhook else False,
            'slack': self.send_slack(message) if self.slack_webhook else False,
        }

        return any(results.values())

    def send_telegram(self, message: str) -> bool:
        """Send alert via Telegram."""
        if not requests or not self.telegram_bot_token or not self.telegram_chat_id:
            logger.warning("Telegram not configured or requests unavailable")
            return False

        url = f"https://api.telegram.org/bot{self.telegram_bot_token}/sendMessage"
        payload = {
            'chat_id': self.telegram_chat_id,
            'text': message,
            'parse_mode': 'HTML',
        }

        try:
            response = requests.post(url, json=payload, timeout=10)
            if response.status_code == 200:
                logger.info("Telegram alert sent successfully")
                return True
            else:
                logger.error(f"Telegram alert failed: {response.status_code} {response.text}")
                return False
        except Exception as error:
            logger.error(f"Telegram error: {error}")
            return False

    def send_discord(self, message: str) -> bool:
        """Send alert via Discord webhook."""
        if not requests or not self.discord_webhook:
            logger.warning("Discord not configured or requests unavailable")
            return False

        payload = {
            'content': message,
            'username': 'CTI Agent',
        }

        try:
            response = requests.post(self.discord_webhook, json=payload, timeout=10)
            if response.status_code in (200, 204):
                logger.info("Discord alert sent successfully")
                return True
            else:
                logger.error(f"Discord alert failed: {response.status_code} {response.text}")
                return False
        except Exception as error:
            logger.error(f"Discord error: {error}")
            return False

    def send_slack(self, message: str) -> bool:
        """Send alert via Slack webhook."""
        if not requests or not self.slack_webhook:
            logger.warning("Slack not configured or requests unavailable")
            return False

        payload = {
            'text': message,
            'username': 'CTI Agent',
        }

        try:
            response = requests.post(self.slack_webhook, json=payload, timeout=10)
            if response.status_code in (200, 204):
                logger.info("Slack alert sent successfully")
                return True
            else:
                logger.error(f"Slack alert failed: {response.status_code} {response.text}")
                return False
        except Exception as error:
            logger.error(f"Slack error: {error}")
            return False

    @staticmethod
    def _format_critical_message(title: str, threat_score: int, cve_id: str | None = None) -> str:
        """Format critical alert message."""
        cve_text = f" ({cve_id})" if cve_id else ""
        message = (
            f"🚨 <b>CRITICAL THREAT DETECTED</b> 🚨\n\n"
            f"<b>Threat</b>: {title}{cve_text}\n"
            f"<b>Score</b>: {threat_score}/100\n"
            f"<b>Action</b>: Immediate investigation required"
        )
        return message

    @staticmethod
    def _format_high_message(title: str, threat_score: int, cve_id: str | None = None) -> str:
        """Format high severity alert message."""
        cve_text = f" ({cve_id})" if cve_id else ""
        message = (
            f"⚠️ <b>HIGH SEVERITY THREAT</b> ⚠️\n\n"
            f"<b>Threat</b>: {title}{cve_text}\n"
            f"<b>Score</b>: {threat_score}/100\n"
            f"<b>Action</b>: Review and assess impact"
        )
        return message

    def batch_alert(self, findings: list[dict]) -> dict[str, int]:
        """Send alerts for batch of findings."""
        results = {
            'critical': 0,
            'high': 0,
            'total_sent': 0,
        }

        for finding in findings:
            threat_score = finding.get('threat_score', 0)
            title = finding.get('title', '')
            cve_id = finding.get('cve_id')

            if threat_score >= 90:
                if self.send_critical_alert(title, threat_score, cve_id):
                    results['critical'] += 1
                    results['total_sent'] += 1
            elif threat_score >= 70:
                if self.send_high_alert(title, threat_score, cve_id):
                    results['high'] += 1
                    results['total_sent'] += 1

        return results

    def test_connection(self) -> dict[str, bool]:
        """Test alerting channel connections."""
        status = {
            'telegram': False,
            'discord': False,
            'slack': False,
        }

        if self.telegram_bot_token and self.telegram_chat_id:
            status['telegram'] = self.send_telegram("✓ CTI Agent test message")

        if self.discord_webhook:
            status['discord'] = self.send_discord("✓ CTI Agent test message")

        if self.slack_webhook:
            status['slack'] = self.send_slack("✓ CTI Agent test message")

        return status
