"""Enrichment layer for NVD, CISA KEV, and MITRE ATT&CK integration."""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from typing import Optional

try:
    import requests
except ImportError:
    requests = None  # type: ignore


logger = logging.getLogger(__name__)


@dataclass
class CVEInfo:
    """CVE enrichment information."""
    
    cve_id: str
    cvss_score: float = 0.0
    cvss_vector: str = ""
    description: str = ""
    published_date: str = ""
    nist_severity: str = ""


@dataclass
class MITREMapping:
    """MITRE ATT&CK mapping."""
    
    tactic: str
    technique_id: str
    technique_name: str


class Enricher:
    """Enrich threat intelligence with external data sources."""

    def __init__(self, timeout: int = 15) -> None:
        """Initialize enricher with API timeout."""
        self.timeout = timeout
        self.nvd_base_url = "https://services.nvd.nist.gov/rest/json/cves/1.0"
        self.kev_url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

    def enrich_cve(self, cve_id: str) -> CVEInfo | None:
        """Enrich CVE from NVD."""
        if not requests:
            logger.warning("requests library not available; skipping NVD enrichment")
            return None

        cve_info = CVEInfo(cve_id=cve_id)

        # Try to parse CVSS from local description first (heuristic)
        # In production, would call NVD API
        logger.debug(f"Enriching CVE {cve_id} (mock mode)")

        return cve_info

    def check_kev(self, cve_id: str) -> bool:
        """Check if CVE is in CISA KEV list."""
        if not requests:
            logger.warning("requests library not available; skipping KEV check")
            return False

        # In production, would fetch and check against KEV list
        logger.debug(f"Checking KEV for {cve_id} (mock mode)")

        return False

    def get_mitre_mappings(self, cve_id: str) -> list[MITREMapping]:
        """Get MITRE ATT&CK mappings for a CVE."""
        # Heuristic-based mapping from CVE description/type
        mappings: list[MITREMapping] = []

        # Map based on attack type keywords
        if 'remote code execution' in cve_id.lower() or 'rce' in cve_id.lower():
            mappings.append(MITREMapping(
                tactic='Execution',
                technique_id='T1190',
                technique_name='Exploit Public-Facing Application'
            ))
            mappings.append(MITREMapping(
                tactic='Initial Access',
                technique_id='T1190',
                technique_name='Exploit Public-Facing Application'
            ))

        if 'privilege escalation' in cve_id.lower():
            mappings.append(MITREMapping(
                tactic='Privilege Escalation',
                technique_id='T1548',
                technique_name='Abuse Elevation Control Mechanism'
            ))

        if 'denial of service' in cve_id.lower() or 'dos' in cve_id.lower():
            mappings.append(MITREMapping(
                tactic='Impact',
                technique_id='T1499',
                technique_name='Endpoint Denial of Service'
            ))

        return mappings

    def extract_cve_id(self, text: str) -> str | None:
        """Extract CVE ID from text."""
        match = re.search(r'(CVE-\d{4}-\d{4,})', text, re.IGNORECASE)
        if match:
            return match.group(1).upper()
        return None

    def extract_cvss_score(self, text: str) -> float:
        """Extract CVSS score from text."""
        # Look for "CVSS: 9.8" or "9.8" pattern
        patterns = [
            r'CVSS[:\s]*v?3\.1[:\s]*(\d+\.\d+)',
            r'CVSS[:\s]*(\d+\.\d+)',
            r'Score[:\s]*(\d+\.\d+)',
        ]

        for pattern in patterns:
            match = re.search(pattern, text, re.IGNORECASE)
            if match:
                try:
                    return float(match.group(1))
                except (ValueError, IndexError):
                    continue

        return 0.0

    def classify_vulnerability_type(self, title: str, description: str) -> str:
        """Classify vulnerability type."""
        text = (title + ' ' + description).lower()

        if 'remote code execution' in text or 'rce' in text:
            return 'Remote Code Execution'
        elif 'privilege escalation' in text:
            return 'Privilege Escalation'
        elif 'authentication' in text or 'bypass' in text:
            return 'Authentication Bypass'
        elif 'injection' in text:
            return 'Injection'
        elif 'xss' in text or 'cross-site' in text:
            return 'Cross-Site Scripting'
        elif 'sql' in text:
            return 'SQL Injection'
        elif 'denial' in text or 'dos' in text:
            return 'Denial of Service'
        elif 'buffer overflow' in text:
            return 'Buffer Overflow'
        elif 'information disclosure' in text or 'leak' in text:
            return 'Information Disclosure'
        else:
            return 'Other'

    def map_to_nist_severity(self, cvss_score: float) -> str:
        """Map CVSS score to NIST severity."""
        if cvss_score >= 9.0:
            return 'CRITICAL'
        elif cvss_score >= 7.0:
            return 'HIGH'
        elif cvss_score >= 4.0:
            return 'MEDIUM'
        elif cvss_score > 0:
            return 'LOW'
        else:
            return 'UNKNOWN'

    def detect_affected_systems(self, text: str) -> list[str]:
        """Extract affected system/software names from text."""
        # Simple keyword-based detection
        systems: list[str] = []
        system_keywords = {
            'Windows': ['windows', 'winrar', 'microsoft'],
            'Linux': ['linux', 'ubuntu', 'debian', 'redhat'],
            'macOS': ['macos', 'osx', 'mac os'],
            'Apache': ['apache'],
            'Nginx': ['nginx'],
            'Java': ['java'],
            'PHP': ['php'],
            'Python': ['python'],
            'Node.js': ['node', 'nodejs'],
            'WordPress': ['wordpress'],
            'Drupal': ['drupal'],
        }

        text_lower = text.lower()
        for system, keywords in system_keywords.items():
            if any(keyword in text_lower for keyword in keywords):
                systems.append(system)

        return list(set(systems))  # Remove duplicates

    def detect_remediation_guidance(self, title: str, description: str) -> dict[str, str]:
        """Generate basic remediation guidance."""
        guidance = {
            'english': 'Apply security patches, implement access controls, monitor for suspicious activity.',
            'persian': 'به‌روزرسانی‌های امنیتی را اعمال کنید، کنترل دسترسی را پیاده‌سازی کنید، فعالیت‌های مریب را نظارت کنید.'
        }

        # Customize based on threat type
        text = (title + ' ' + description).lower()

        if 'remote' in text and 'code execution' in text:
            guidance['english'] = 'Patch immediately, restrict network exposure, enable EDR solutions.'
            guidance['persian'] = 'بلافاصله وصله بزنید، تعریض شبکه را محدود کنید، راه‌حل‌های EDR را فعال کنید.'

        elif 'ransomware' in text:
            guidance['english'] = 'Isolate affected systems, verify offline backups, enforce MFA, scan for artifacts.'
            guidance['persian'] = 'سیستم‌های آلوده را جداسازی کنید، نسخه‌های پشتیبان را تأیید کنید، MFA را اعمال کنید.'

        elif 'privilege escalation' in text:
            guidance['english'] = 'Apply patches, limit privileged access, audit account privileges.'
            guidance['persian'] = 'وصله‌ها را اعمال کنید، دسترسی ویژه را محدود کنید، امتیازات حساب را بررسی کنید.'

        return guidance

    def batch_enrich(self, cve_ids: list[str]) -> dict[str, CVEInfo]:
        """Enrich multiple CVEs (with mock fallback)."""
        results = {}
        for cve_id in cve_ids:
            enriched = self.enrich_cve(cve_id)
            if enriched:
                results[cve_id] = enriched
        return results
