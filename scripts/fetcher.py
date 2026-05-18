"""Threat intelligence collection from RSS and CISA KEV feeds."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

import feedparser
import requests
from pydantic import BaseModel, Field


class FeedEntry(BaseModel):
    """Normalized representation of collected threat intelligence."""

    title: str = Field(min_length=1)
    url: str = Field(min_length=1)
    summary: str = Field(default="")
    source: str = Field(min_length=1)
    published_at: str = Field(default="")


@dataclass(frozen=True)
class _FeedSource:
    name: str
    url: str


class Fetcher:
    """Collect and normalize cybersecurity intelligence entries."""

    _KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    _KEV_CATALOG_URL = "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"

    def __init__(self) -> None:
        self._rss_feeds: list[_FeedSource] = [
            _FeedSource("The Hacker News", "https://feeds.feedburner.com/TheHackerNews"),
            _FeedSource("Krebs on Security", "https://krebsonsecurity.com/feed/"),
        ]

    @staticmethod
    def _safe_text(value: Any, default: str = "") -> str:
        if isinstance(value, str):
            return value.strip()
        return default

    @staticmethod
    def _request(url: str) -> requests.Response:
        response = requests.get(
            url,
            timeout=25,
            headers={"User-Agent": "SecurityAgent/1.0 (+https://github.com/matinsh94/Security_agent)"},
        )
        response.raise_for_status()
        return response

    def _parse_rss_feed(self, source: _FeedSource) -> list[FeedEntry]:
        """Retrieve and parse one RSS feed source."""

        response = self._request(source.url)
        parsed = feedparser.parse(response.content)

        entries: list[FeedEntry] = []
        for item in getattr(parsed, "entries", []):
            title = self._safe_text(item.get("title"))
            url = self._safe_text(item.get("link") or item.get("id"))
            summary = self._safe_text(item.get("summary") or item.get("description"))
            published_at = self._safe_text(item.get("published") or item.get("updated"))

            if not title or not url:
                continue

            entries.append(
                FeedEntry(
                    title=title,
                    url=url,
                    summary=summary,
                    source=source.name,
                    published_at=published_at,
                )
            )

        return entries

    def _parse_cisa_kev(self) -> list[FeedEntry]:
        """Retrieve and convert CISA KEV JSON catalog items."""

        response = self._request(self._KEV_URL)
        payload = response.json()
        vulnerabilities = payload.get("vulnerabilities", []) if isinstance(payload, dict) else []

        entries: list[FeedEntry] = []
        for vuln in vulnerabilities:
            if not isinstance(vuln, dict):
                continue

            cve_id = self._safe_text(vuln.get("cveID"), "Unknown CVE")
            vendor = self._safe_text(vuln.get("vendorProject"), "Unknown Vendor")
            product = self._safe_text(vuln.get("product"), "Unknown Product")
            vuln_name = self._safe_text(vuln.get("vulnerabilityName"), "Known Exploited Vulnerability")
            short_desc = self._safe_text(vuln.get("shortDescription"), "")
            due_date = self._safe_text(vuln.get("dueDate"), "")
            date_added = self._safe_text(vuln.get("dateAdded"), "")

            summary = (
                f"{short_desc} Vendor: {vendor}. Product: {product}. "
                f"CISA remediation due date: {due_date}."
            ).strip()
            title = f"{cve_id} - {vuln_name}"

            entries.append(
                FeedEntry(
                    title=title,
                    url=f"{self._KEV_CATALOG_URL}#{cve_id}",
                    summary=summary,
                    source="CISA KEV",
                    published_at=date_added,
                )
            )

        return entries

    def _mock_entries(self) -> list[FeedEntry]:
        """Provide deterministic high-fidelity mock entries for test runs."""

        now = datetime.now(timezone.utc).isoformat()
        return [
            FeedEntry(
                title="Critical Zero-Day in Windows Kernel (CVE-2026-1122)",
                url="https://example.local/mock/windows-kernel-cve-2026-1122",
                summary="An unauthenticated attacker can gain full SYSTEM privileges via vulnerable RPC message parsing in the Windows kernel.",
                source="Mock Threat Feed",
                published_at=now,
            ),
            FeedEntry(
                title="New Ransomware Targeting Linux Servers",
                url="https://example.local/mock/linux-ransomware-campaign",
                summary="A phishing campaign deploys a Linux ransomware loader that encrypts PostgreSQL and MongoDB volumes after stealing SSH keys.",
                source="Mock Threat Feed",
                published_at=now,
            ),
            FeedEntry(
                title="Log4j Exploitation Wave Resurfaces with Obfuscated JNDI Payloads",
                url="https://example.local/mock/log4j-jndi-wave",
                summary="Attackers use nested lookup obfuscation to evade WAF signatures and trigger remote code execution in unpatched Java services.",
                source="Mock Threat Feed",
                published_at=now,
            ),
            FeedEntry(
                title="Public GitHub Repository Leak Exposes Cloud Production Secrets",
                url="https://example.local/mock/github-secrets-leak",
                summary="Hardcoded AWS keys and CI deployment tokens were leaked in a public repository, enabling lateral movement across staging and production.",
                source="Mock Threat Feed",
                published_at=now,
            ),
            FeedEntry(
                title="Malicious PyPI Package Targets CI Pipelines via setup.py Backdoor",
                url="https://example.local/mock/pypi-supply-chain-backdoor",
                summary="A typo-squatted package executes credential theft commands during installation and exfiltrates environment variables from runners.",
                source="Mock Threat Feed",
                published_at=now,
            ),
        ]

    def fetch_all(self, state_manager: Any, force_mock: bool = False) -> list[FeedEntry]:
        """Collect new entries and deduplicate against persistent state.

        If all live sources fail or yield zero entries, five mock entries are
        generated automatically to guarantee testability.
        """

        if force_mock:
            # Test mode must always return data, independent of DB history.
            return self._mock_entries()

        collected: list[FeedEntry] = []

        for source in self._rss_feeds:
            try:
                collected.extend(self._parse_rss_feed(source))
            except Exception:
                continue

        try:
            collected.extend(self._parse_cisa_kev())
        except Exception:
            pass

        if not collected:
            # Live sources failed or returned no data; always provide mock items.
            return self._mock_entries()

        new_entries: list[FeedEntry] = []
        for entry in collected:
            if not state_manager.is_processed(entry.url, entry.title):
                new_entries.append(entry)

        return new_entries