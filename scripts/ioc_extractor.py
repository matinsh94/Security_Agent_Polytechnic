"""IOC extraction engine for threat intelligence."""

from __future__ import annotations

import re
from dataclasses import dataclass
import ipaddress
from urllib.parse import urlsplit, urlunsplit


@dataclass(slots=True)
class IOC:
    """Represents a single Indicator of Compromise."""

    ioc_type: str
    value: str
    confidence: float = 0.8


class IOCExtractor:
    """Extract and normalize IOCs from security intelligence text."""

    IPV4_PATTERN = r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"
    DOMAIN_PATTERN = r"(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,63}"
    URL_PATTERN = r"https?://[^\s<>\"{}|\\^`\[\]]+"
    EMAIL_PATTERN = r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"
    CVE_PATTERN = r"\bCVE-\d{4}-\d{4,}\b"
    SHA1_PATTERN = r"\b[a-fA-F0-9]{40}\b"
    SHA256_PATTERN = r"\b[a-fA-F0-9]{64}\b"
    MD5_PATTERN = r"\b[a-fA-F0-9]{32}\b"

    def __init__(self) -> None:
        self.patterns = {
            "ipv4": re.compile(self.IPV4_PATTERN),
            "domain": re.compile(self.DOMAIN_PATTERN, re.IGNORECASE),
            "url": re.compile(self.URL_PATTERN, re.IGNORECASE),
            "email": re.compile(self.EMAIL_PATTERN),
            "cve": re.compile(self.CVE_PATTERN, re.IGNORECASE),
            "sha1": re.compile(self.SHA1_PATTERN, re.IGNORECASE),
            "sha256": re.compile(self.SHA256_PATTERN, re.IGNORECASE),
            "md5": re.compile(self.MD5_PATTERN, re.IGNORECASE),
        }

    def extract(self, text: str) -> list[IOC]:
        """Extract IOCs from text and return a deduplicated structured list."""

        extracted: list[IOC] = []
        seen: set[tuple[str, str]] = set()
        url_hosts: set[str] = set()

        def add_ioc(ioc_type: str, value: str, confidence: float) -> None:
            normalized = self._normalize_value(ioc_type, value)
            if not normalized:
                return
            fingerprint = (ioc_type, normalized)
            if fingerprint in seen:
                return
            seen.add(fingerprint)
            if ioc_type == "url":
                host = urlsplit(normalized).netloc.lower()
                if host:
                    url_hosts.add(host)
            extracted.append(IOC(ioc_type=ioc_type, value=normalized, confidence=confidence))

        for match in self.patterns["cve"].finditer(text):
            add_ioc("cve", match.group(0), 0.99)

        for match in self.patterns["url"].finditer(text):
            add_ioc("url", match.group(0), 0.93)

        for match in self.patterns["ipv4"].finditer(text):
            value = match.group(0)
            if self._is_valid_public_ipv4(value):
                add_ioc("ipv4", value, 0.95)

        for match in self.patterns["email"].finditer(text):
            value = match.group(0)
            if not self._is_internal_email(value):
                add_ioc("email", value, 0.88)

        for match in self.patterns["sha256"].finditer(text):
            add_ioc("sha256", match.group(0), 0.99)

        for match in self.patterns["sha1"].finditer(text):
            add_ioc("sha1", match.group(0), 0.92)

        for match in self.patterns["md5"].finditer(text):
            add_ioc("md5", match.group(0), 0.84)

        for match in self.patterns["domain"].finditer(text):
            domain = self._normalize_domain(match.group(0))
            if not domain or self._is_internal_domain(domain) or domain in url_hosts:
                continue
            if any(domain == host or domain.endswith(f".{host}") for host in url_hosts):
                continue
            if self._is_valid_domain(domain):
                add_ioc("domain", domain, 0.76)

        return extracted

    def extract_by_type(self, text: str, ioc_type: str) -> list[IOC]:
        """Extract IOCs of a specific type."""

        return [ioc for ioc in self.extract(text) if ioc.ioc_type == ioc_type]

    @staticmethod
    def _normalize_value(ioc_type: str, value: str) -> str:
        text = (value or "").strip()
        if not text:
            return ""

        if ioc_type in {"sha1", "sha256", "md5", "cve"}:
            return text.lower() if ioc_type != "cve" else text.upper()
        if ioc_type == "email":
            return text.lower()
        if ioc_type == "domain":
            return IOCExtractor._normalize_domain(text)
        if ioc_type == "url":
            return IOCExtractor._normalize_url(text)
        return text

    @staticmethod
    def _normalize_domain(domain: str) -> str:
        return domain.strip().rstrip(".").lower()

    @staticmethod
    def _normalize_url(url: str) -> str:
        split = urlsplit(url.strip())
        path = split.path.rstrip("/") or "/"
        return urlunsplit((split.scheme.lower(), split.netloc.lower(), path, split.query, ""))

    @staticmethod
    def _is_valid_public_ipv4(ip: str) -> bool:
        try:
            ip_obj = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return (
            ip_obj.version == 4
            and not ip_obj.is_private
            and not ip_obj.is_loopback
            and not ip_obj.is_link_local
            and not ip_obj.is_multicast
            and not ip_obj.is_reserved
        )

    @staticmethod
    def _is_valid_domain(domain: str) -> bool:
        labels = domain.split('.')
        if len(labels) < 2:
            return False
        if any(not label or len(label) > 63 or label.startswith('-') or label.endswith('-') for label in labels):
            return False
        if all(label.isdigit() for label in labels):
            return False
        if len(labels[-1]) < 2:
            return False
        return True

    @staticmethod
    def _is_internal_email(email: str) -> bool:
        internal_domains = {"localhost", "example.com", "example.org", "example.net", "test.com", "invalid"}
        domain = email.split("@", 1)[1].lower() if "@" in email else ""
        return domain in internal_domains or domain.endswith(".local")

    @staticmethod
    def _is_internal_domain(domain: str) -> bool:
        internal_domains = {"localhost", "example.com", "example.org", "example.net", "test.com", "invalid", "local"}
        return domain.lower() in internal_domains or domain.endswith(".local")
