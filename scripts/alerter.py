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
        self.telegram_webhook_url = os.getenv('TELEGRAM_WEBHOOK_URL')
        self.discord_webhook = os.getenv('DISCORD_WEBHOOK_URL')
        self.slack_webhook = os.getenv('SLACK_WEBHOOK_URL')

    @staticmethod
    def _severity_rank(severity: str) -> int:
        return {"critical": 4, "high": 3, "medium": 2, "low": 1}.get(str(severity).lower(), 0)

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

    def _dispatch(self, message: str) -> bool:
        delivered = False
        if self.telegram_bot_token or self.telegram_webhook_url:
            delivered = self.send_telegram(message) or delivered
        if self.discord_webhook:
            delivered = self.send_discord(message) or delivered
        if self.slack_webhook:
            delivered = self.send_slack(message) or delivered
        return delivered

    def send_telegram(self, message: str) -> bool:
        """Send alert via Telegram."""
        if not requests:
            logger.warning("Telegram not configured or requests unavailable")
            return False

        try:
            if self.telegram_webhook_url:
                response = requests.post(self.telegram_webhook_url, json={"text": message}, timeout=10)
            elif self.telegram_bot_token and self.telegram_chat_id:
                url = f"https://api.telegram.org/bot{self.telegram_bot_token}/sendMessage"
                payload = {
                    'chat_id': self.telegram_chat_id,
                    'text': message,
                    'parse_mode': 'HTML',
                }
                response = requests.post(url, json=payload, timeout=10)
            else:
                logger.warning("Telegram not configured or requests unavailable")
                return False

            if response.status_code in (200, 201, 204):
                logger.info("Telegram alert sent successfully")
                return True
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
            severity = str(finding.get('severity', '')).lower()
            threat_score = int(finding.get('threat_score', 0))
            title = finding.get('title', '')
            cve_id = finding.get('cve_id')

            should_alert = self._severity_rank(severity) >= self._severity_rank('high') or threat_score >= 70

            if not should_alert:
                continue

            message = self.format_finding_message(finding)
            if severity == 'critical' or threat_score >= 90:
                if self._dispatch(message):
                    results['critical'] += 1
                    results['total_sent'] += 1
            else:
                if self._dispatch(message):
                    results['high'] += 1
                    results['total_sent'] += 1

        return results

    @staticmethod
    def format_finding_message(finding: dict) -> str:
        cve_id = finding.get('cve_id') or 'N/A'
        severity = str(finding.get('severity', 'unknown')).upper()
        cvss_score = finding.get('cvss_score', 0.0)
        summary = finding.get('description', '') or finding.get('summary', '') or finding.get('title', '')
        action = finding.get('remediation_en') or finding.get('remediation_secondary') or 'Investigate, contain, and patch affected systems.'
        return (
            f"<b>Threat</b>: {finding.get('title', 'Unnamed threat')}\n"
            f"<b>CVE</b>: {cve_id}\n"
            f"<b>Severity</b>: {severity}\n"
            f"<b>CVSS</b>: {cvss_score}\n"
            f"<b>Summary</b>: {summary}\n"
            f"<b>Recommended action</b>: {action}"
        )

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
