"""Threat intelligence collection from RSS and CISA KEV feeds."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from html import unescape
from typing import Any, Iterable
from urllib.parse import urlsplit, urlunsplit

import feedparser
import requests
from bs4 import BeautifulSoup


@dataclass(slots=True)
class FeedEntry:
    """Normalized representation of collected threat intelligence."""

    title: str
    url: str
    summary: str
    source: str
    published_at: str

    def to_dict(self) -> dict[str, str]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class _FeedSource:
    name: str
    url: str


class Fetcher:
    """Collect and normalize cybersecurity intelligence entries."""

    _KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    _KEV_CATALOG_URL = "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"
    _USER_AGENT = "SecurityAgent/1.0 (+https://github.com/matinsh94/Security_Agent_Polytechnic)"

    def __init__(self, session: requests.Session | None = None) -> None:
        self._session = session or requests.Session()
        self._session.headers.update({"User-Agent": self._USER_AGENT})
        self._rss_feeds: list[_FeedSource] = [
            _FeedSource("The Hacker News", "https://feeds.feedburner.com/TheHackersNews"),
            _FeedSource("Krebs on Security", "https://krebsonsecurity.com/feed/"),
        ]

    @staticmethod
    def _safe_text(value: Any, default: str = "") -> str:
        if isinstance(value, str):
            return value.strip()
        if value is None:
            return default
        return str(value).strip() or default

    @staticmethod
    def _canonical_url(url: str) -> str:
        split = urlsplit(url.strip())
        path = split.path.rstrip("/") or "/"
        return urlunsplit((split.scheme, split.netloc, path, split.query, ""))

    @staticmethod
    def _clean_html(value: str) -> str:
        text = unescape(value or "")
        soup = BeautifulSoup(text, "html.parser")
        return " ".join(soup.stripped_strings).strip()

    def _request(self, url: str) -> requests.Response:
        response = self._session.get(url, timeout=25)
        response.raise_for_status()
        return response

    def _parse_rss_feed(self, source: _FeedSource, limit: int = 10) -> list[FeedEntry]:
        """Retrieve and parse one RSS feed source."""

        response = self._request(source.url)
        parsed = feedparser.parse(response.content)

        entries: list[FeedEntry] = []
        for item in list(getattr(parsed, "entries", []))[:limit]:
            title = self._safe_text(item.get("title"))
            url = self._safe_text(item.get("link") or item.get("id"))
            summary = self._clean_html(self._safe_text(item.get("summary") or item.get("description")))
            published_at = self._safe_text(item.get("published") or item.get("updated") or item.get("date"))

            if not title or not url:
                continue

            entries.append(
                FeedEntry(
                    title=title,
                    url=self._canonical_url(url),
                    summary=summary,
                    source=source.name,
                    published_at=published_at,
                )
            )

        return entries

    def _parse_cisa_kev(self, limit: int = 15) -> list[FeedEntry]:
        """Retrieve and convert CISA KEV JSON catalog items."""

        response = self._request(self._KEV_URL)
        payload = response.json()
        vulnerabilities = payload.get("vulnerabilities", []) if isinstance(payload, dict) else []

        entries: list[FeedEntry] = []
        for vuln in list(vulnerabilities)[:limit]:
            if not isinstance(vuln, dict):
                continue

            cve_id = self._safe_text(vuln.get("cveID"), "Unknown CVE")
            vendor = self._safe_text(vuln.get("vendorProject"), "Unknown Vendor")
            product = self._safe_text(vuln.get("product"), "Unknown Product")
            vuln_name = self._safe_text(vuln.get("vulnerabilityName"), "Known Exploited Vulnerability")
            short_desc = self._clean_html(self._safe_text(vuln.get("shortDescription"), ""))
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
                summary=(
                    "An unauthenticated attacker can gain full SYSTEM privileges via vulnerable RPC message parsing in the Windows kernel."
                ),
                source="Mock Threat Feed",
                published_at=now,
            ),
            FeedEntry(
                title="New Ransomware Targeting Linux Servers",
                url="https://example.local/mock/linux-ransomware-campaign",
                summary=(
                    "A phishing campaign deploys a Linux ransomware loader that encrypts PostgreSQL and MongoDB volumes after stealing SSH keys."
                ),
                source="Mock Threat Feed",
                published_at=now,
            ),
            FeedEntry(
                title="Log4j Exploitation Wave Resurfaces with Obfuscated JNDI Payloads",
                url="https://example.local/mock/log4j-jndi-wave",
                summary=(
                    "Attackers use nested lookup obfuscation to evade WAF signatures and trigger remote code execution in unpatched Java services."
                ),
                source="Mock Threat Feed",
                published_at=now,
            ),
            FeedEntry(
                title="Public GitHub Repository Leak Exposes Cloud Production Secrets",
                url="https://example.local/mock/github-secrets-leak",
                summary=(
                    "Hardcoded AWS keys and CI deployment tokens were leaked in a public repository, enabling lateral movement across staging and production."
                ),
                source="Mock Threat Feed",
                published_at=now,
            ),
            FeedEntry(
                title="Malicious PyPI Package Targets CI Pipelines via setup.py Backdoor",
                url="https://example.local/mock/pypi-supply-chain-backdoor",
                summary=(
                    "A typo-squatted package executes credential theft commands during installation and exfiltrates environment variables from runners."
                ),
                source="Mock Threat Feed",
                published_at=now,
            ),
        ]

    @staticmethod
    def _dedupe(entries: Iterable[FeedEntry]) -> list[FeedEntry]:
        seen: set[tuple[str, str]] = set()
        deduped: list[FeedEntry] = []
        for entry in entries:
            fingerprint = (entry.url, entry.title)
            if fingerprint in seen:
                continue
            seen.add(fingerprint)
            deduped.append(entry)
        return deduped

    def fetch_all(self, state_manager: Any, force_mock: bool = False) -> list[FeedEntry]:
        """Collect new entries and deduplicate against persistent state."""

        if force_mock:
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
            return self._mock_entries()

        fresh_entries: list[FeedEntry] = []
        for entry in self._dedupe(collected):
            if not state_manager.is_processed(entry.url, entry.title):
                fresh_entries.append(entry)

        return fresh_entries