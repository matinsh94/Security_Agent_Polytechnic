"""IOC (Indicator of Compromise) extraction engine for threat intelligence."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Iterator


@dataclass
class IOC:
    """Represents a single Indicator of Compromise."""
    
    ioc_type: str
    value: str
    confidence: float = 0.8


class IOCExtractor:
    """Extract and normalize IOCs from security intelligence text."""

    # Regular expressions for IOC patterns
    IPV4_PATTERN = r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
    DOMAIN_PATTERN = r'(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,}'
    URL_PATTERN = r'https?://[^\s<>"{}|\\^`\[\]]+'
    EMAIL_PATTERN = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
    SHA256_PATTERN = r'\b[a-fA-F0-9]{64}\b'
    MD5_PATTERN = r'\b[a-fA-F0-9]{32}\b'
    POWERSHELL_PATTERN = r'[A-Za-z0-9+/]{50,}={0,2}'  # Base64-like patterns

    def __init__(self) -> None:
        """Initialize IOC extractor with compiled regex patterns."""
        self.patterns = {
            'ipv4': re.compile(self.IPV4_PATTERN, re.IGNORECASE),
            'domain': re.compile(self.DOMAIN_PATTERN, re.IGNORECASE),
            'url': re.compile(self.URL_PATTERN, re.IGNORECASE),
            'email': re.compile(self.EMAIL_PATTERN),
            'sha256': re.compile(self.SHA256_PATTERN, re.IGNORECASE),
            'md5': re.compile(self.MD5_PATTERN, re.IGNORECASE),
        }

    def extract(self, text: str) -> list[IOC]:
        """Extract all IOCs from text and return deduplicated list."""
        iocs_list: list[IOC] = []
        seen = set()

        # Extract IPv4 addresses
        for match in self.patterns['ipv4'].finditer(text):
            ioc_value = match.group(0)
            if ioc_value not in seen and not self._is_private_ip(ioc_value):
                iocs_list.append(IOC(ioc_type='ipv4', value=ioc_value, confidence=0.95))
                seen.add(ioc_value)

        # Extract SHA256 hashes (high confidence)
        for match in self.patterns['sha256'].finditer(text):
            ioc_value = match.group(0).lower()
            if ioc_value not in seen:
                iocs_list.append(IOC(ioc_type='sha256', value=ioc_value, confidence=0.98))
                seen.add(ioc_value)

        # Extract MD5 hashes (medium confidence)
        for match in self.patterns['md5'].finditer(text):
            ioc_value = match.group(0).lower()
            if ioc_value not in seen:
                iocs_list.append(IOC(ioc_type='md5', value=ioc_value, confidence=0.85))
                seen.add(ioc_value)

        # Extract URLs
        for match in self.patterns['url'].finditer(text):
            ioc_value = match.group(0)
            if ioc_value not in seen:
                iocs_list.append(IOC(ioc_type='url', value=ioc_value, confidence=0.90))
                seen.add(ioc_value)

        # Extract email addresses
        for match in self.patterns['email'].finditer(text):
            ioc_value = match.group(0).lower()
            if ioc_value not in seen and not self._is_internal_email(ioc_value):
                iocs_list.append(IOC(ioc_type='email', value=ioc_value, confidence=0.88))
                seen.add(ioc_value)

        # Extract domains (lower confidence, after URLs to avoid duplicates)
        for match in self.patterns['domain'].finditer(text):
            ioc_value = match.group(0).lower()
            # Skip if already extracted as part of URL
            if ioc_value not in seen and not any(ioc_value in ioc.value for ioc in iocs_list if ioc.ioc_type == 'url'):
                iocs_list.append(IOC(ioc_type='domain', value=ioc_value, confidence=0.75))
                seen.add(ioc_value)

        return iocs_list

    def extract_by_type(self, text: str, ioc_type: str) -> list[IOC]:
        """Extract IOCs of a specific type."""
        if ioc_type == 'ipv4':
            return self._extract_ipv4(text)
        elif ioc_type == 'domain':
            return self._extract_domains(text)
        elif ioc_type == 'url':
            return self._extract_urls(text)
        elif ioc_type == 'email':
            return self._extract_emails(text)
        elif ioc_type == 'sha256':
            return self._extract_sha256(text)
        elif ioc_type == 'md5':
            return self._extract_md5(text)
        else:
            return []

    def _extract_ipv4(self, text: str) -> list[IOC]:
        """Extract IPv4 addresses."""
        iocs_list: list[IOC] = []
        for match in self.patterns['ipv4'].finditer(text):
            value = match.group(0)
            if not self._is_private_ip(value):
                iocs_list.append(IOC(ioc_type='ipv4', value=value, confidence=0.95))
        return iocs_list

    def _extract_domains(self, text: str) -> list[IOC]:
        """Extract domains."""
        iocs_list: list[IOC] = []
        for match in self.patterns['domain'].finditer(text):
            value = match.group(0).lower()
            if not self._is_internal_domain(value):
                iocs_list.append(IOC(ioc_type='domain', value=value, confidence=0.75))
        return iocs_list

    def _extract_urls(self, text: str) -> list[IOC]:
        """Extract URLs."""
        iocs_list: list[IOC] = []
        for match in self.patterns['url'].finditer(text):
            value = match.group(0)
            iocs_list.append(IOC(ioc_type='url', value=value, confidence=0.90))
        return iocs_list

    def _extract_emails(self, text: str) -> list[IOC]:
        """Extract email addresses."""
        iocs_list: list[IOC] = []
        for match in self.patterns['email'].finditer(text):
            value = match.group(0).lower()
            if not self._is_internal_email(value):
                iocs_list.append(IOC(ioc_type='email', value=value, confidence=0.88))
        return iocs_list

    def _extract_sha256(self, text: str) -> list[IOC]:
        """Extract SHA256 hashes."""
        iocs_list: list[IOC] = []
        for match in self.patterns['sha256'].finditer(text):
            value = match.group(0).lower()
            iocs_list.append(IOC(ioc_type='sha256', value=value, confidence=0.98))
        return iocs_list

    def _extract_md5(self, text: str) -> list[IOC]:
        """Extract MD5 hashes."""
        iocs_list: list[IOC] = []
        for match in self.patterns['md5'].finditer(text):
            value = match.group(0).lower()
            iocs_list.append(IOC(ioc_type='md5', value=value, confidence=0.85))
        return iocs_list

    @staticmethod
    def _is_private_ip(ip: str) -> bool:
        """Check if IP is private/RFC1918."""
        private_ranges = [
            r'^10\.',
            r'^172\.(1[6-9]|2[0-9]|3[01])\.',
            r'^192\.168\.',
            r'^127\.',
            r'^169\.254\.',
        ]
        return any(re.match(pattern, ip) for pattern in private_ranges)

    @staticmethod
    def _is_internal_email(email: str) -> bool:
        """Check if email is internal/example."""
        internal_domains = ['localhost', 'example.com', 'example.org', 'example.net', 'test.com', 'invalid']
        domain = email.split('@')[1].lower() if '@' in email else ''
        return domain in internal_domains

    @staticmethod
    def _is_internal_domain(domain: str) -> bool:
        """Check if domain is internal/reserved."""
        internal_domains = [
            'localhost',
            'example.com',
            'example.org',
            'example.net',
            'test.com',
            'invalid',
            'local',
        ]
        return domain.lower() in internal_domains or domain.endswith('.local')
