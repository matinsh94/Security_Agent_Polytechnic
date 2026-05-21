"""Enrichment layer for NVD, CISA KEV, and MITRE ATT&CK integration."""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from functools import lru_cache
from typing import Any, Optional
from urllib.parse import urlencode

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
    kev_status: bool = False
    exploitation_status: str = "unknown"


@dataclass
class MITREMapping:
    """MITRE ATT&CK mapping."""
    
    tactic: str
    technique_id: str
    technique_name: str


class Enricher:
    """Enrich threat intelligence with external data sources."""

    def __init__(self, timeout: int = 15, session: Any | None = None) -> None:
        """Initialize enricher with API timeout."""
        self.timeout = timeout
        self.nvd_base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        self.kev_url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
        self._session = session or (requests.Session() if requests else None)
        self._kev_cache: set[str] | None = None
        self._cve_cache: dict[str, CVEInfo] = {}

    def _request_json(self, url: str, params: dict[str, str] | None = None) -> dict[str, Any] | None:
        if not self._session:
            return None

        response = self._session.get(url, params=params, timeout=self.timeout)
        response.raise_for_status()
        payload = response.json()
        return payload if isinstance(payload, dict) else None

    @staticmethod
    def _severity_from_score(score: float) -> str:
        if score >= 9.0:
            return "CRITICAL"
        if score >= 7.0:
            return "HIGH"
        if score >= 4.0:
            return "MEDIUM"
        if score > 0:
            return "LOW"
        return "UNKNOWN"

    @staticmethod
    def _extract_description(payload: dict[str, Any]) -> str:
        descriptions = payload.get("descriptions")
        if isinstance(descriptions, list):
            for entry in descriptions:
                if isinstance(entry, dict) and str(entry.get("lang", "")).lower() == "en":
                    return str(entry.get("value", "")).strip()
        return ""

    @staticmethod
    def _extract_cvss(payload: dict[str, Any]) -> tuple[float, str]:
        metrics = payload.get("metrics")
        if not isinstance(metrics, dict):
            return 0.0, ""

        for metric_key in ("cvssMetricV31", "cvssMetricV30"):
            metric_list = metrics.get(metric_key)
            if isinstance(metric_list, list) and metric_list:
                metric = metric_list[0]
                if isinstance(metric, dict):
                    data = metric.get("cvssData", {})
                    if isinstance(data, dict):
                        score = data.get("baseScore", 0.0)
                        vector = data.get("vectorString", "")
                        try:
                            return float(score), str(vector)
                        except (TypeError, ValueError):
                            return 0.0, str(vector)
        return 0.0, ""

    def enrich_cve(self, cve_id: str) -> CVEInfo | None:
        """Enrich CVE from NVD."""
        normalized = cve_id.upper().strip()
        if not self.extract_cve_id(normalized):
            return None

        if normalized in self._cve_cache:
            return self._cve_cache[normalized]

        kev_status = self.check_kev(normalized)
        payload = None
        if self._session:
            try:
                payload = self._request_json(self.nvd_base_url, params={"cveId": normalized})
            except Exception as error:
                logger.debug("NVD enrichment failed for %s: %s", normalized, error)

        cve_info = CVEInfo(
            cve_id=normalized,
            kev_status=kev_status,
            exploitation_status="known exploited" if kev_status else "unknown",
        )

        if payload:
            vulnerabilities = payload.get("vulnerabilities")
            if isinstance(vulnerabilities, list) and vulnerabilities:
                vuln = vulnerabilities[0]
                if isinstance(vuln, dict):
                    cve_payload = vuln.get("cve") if isinstance(vuln.get("cve"), dict) else vuln
                    if isinstance(cve_payload, dict):
                        cve_info.description = self._extract_description(cve_payload)
                        cve_info.cvss_score, cve_info.cvss_vector = self._extract_cvss(cve_payload)
                        cve_info.published_date = str(cve_payload.get("published", "")).strip()
                        cve_info.nist_severity = self._severity_from_score(cve_info.cvss_score)

        if not cve_info.cvss_score:
            cve_info.cvss_score = self.extract_cvss_score(normalized)
            cve_info.nist_severity = self.map_to_nist_severity(cve_info.cvss_score)

        if not cve_info.nist_severity:
            cve_info.nist_severity = self.map_to_nist_severity(cve_info.cvss_score)

        self._cve_cache[normalized] = cve_info
        return cve_info

    def check_kev(self, cve_id: str) -> bool:
        """Check if CVE is in CISA KEV list."""
        normalized = cve_id.upper().strip()
        if not self.extract_cve_id(normalized):
            return False

        if self._kev_cache is None:
            self._kev_cache = set()
            if self._session:
                try:
                    payload = self._request_json(self.kev_url)
                except Exception as error:
                    logger.debug("KEV fetch failed: %s", error)
                    payload = None

                vulnerabilities = payload.get("vulnerabilities", []) if isinstance(payload, dict) else []
                if isinstance(vulnerabilities, list):
                    for vuln in vulnerabilities:
                        if isinstance(vuln, dict):
                            cve_value = str(vuln.get("cveID", "")).strip().upper()
                            if cve_value:
                                self._kev_cache.add(cve_value)

        return normalized in (self._kev_cache or set())

    def get_mitre_mappings(self, cve_id: str) -> list[MITREMapping]:
        """Get MITRE ATT&CK mappings for a CVE or vulnerability description."""
        mappings: list[MITREMapping] = []
        text = cve_id.lower()

        keyword_mappings = [
            ("remote code execution", [
                MITREMapping(tactic="Execution", technique_id="T1203", technique_name="Exploitation for Client Execution"),
                MITREMapping(tactic="Initial Access", technique_id="T1190", technique_name="Exploit Public-Facing Application"),
            ]),
            ("rce", [
                MITREMapping(tactic="Execution", technique_id="T1203", technique_name="Exploitation for Client Execution"),
                MITREMapping(tactic="Initial Access", technique_id="T1190", technique_name="Exploit Public-Facing Application"),
            ]),
            ("privilege escalation", [
                MITREMapping(tactic="Privilege Escalation", technique_id="T1548", technique_name="Abuse Elevation Control Mechanism"),
            ]),
            ("authentication bypass", [
                MITREMapping(tactic="Initial Access", technique_id="T1190", technique_name="Exploit Public-Facing Application"),
            ]),
            ("injection", [
                MITREMapping(tactic="Execution", technique_id="T1059", technique_name="Command and Scripting Interpreter"),
            ]),
            ("denial of service", [
                MITREMapping(tactic="Impact", technique_id="T1499", technique_name="Endpoint Denial of Service"),
            ]),
            ("dos", [
                MITREMapping(tactic="Impact", technique_id="T1499", technique_name="Endpoint Denial of Service"),
            ]),
            ("ransomware", [
                MITREMapping(tactic="Impact", technique_id="T1486", technique_name="Data Encrypted for Impact"),
                MITREMapping(tactic="Discovery", technique_id="T1083", technique_name="File and Directory Discovery"),
            ]),
            ("supply chain", [
                MITREMapping(tactic="Initial Access", technique_id="T1195", technique_name="Supply Chain Compromise"),
            ]),
        ]

        for keyword, keyword_mapped in keyword_mappings:
            if keyword in text:
                mappings.extend(keyword_mapped)

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
            'english': 'Apply security patches, implement access controls, and monitor for suspicious activity.',
            'secondary': 'Apply security patches, implement access controls, and monitor for suspicious activity.'
        }

        # Customize based on threat type
        text = (title + ' ' + description).lower()

        if 'remote' in text and 'code execution' in text:
            guidance['english'] = 'Patch immediately, restrict network exposure, enable EDR solutions.'
            guidance['secondary'] = 'Patch immediately, restrict network exposure, enable EDR solutions.'

        elif 'ransomware' in text:
            guidance['english'] = 'Isolate affected systems, verify offline backups, enforce MFA, scan for artifacts.'
            guidance['secondary'] = 'Isolate affected systems, verify offline backups, enforce MFA, and scan for artifacts.'

        elif 'privilege escalation' in text:
            guidance['english'] = 'Apply patches, limit privileged access, audit account privileges.'
            guidance['secondary'] = 'Apply patches, limit privileged access, and audit account privileges.'

        return guidance

    def batch_enrich(self, cve_ids: list[str]) -> dict[str, CVEInfo]:
        """Enrich multiple CVEs (with mock fallback)."""
        results = {}
        for cve_id in cve_ids:
            enriched = self.enrich_cve(cve_id)
            if enriched:
                results[cve_id] = enriched
        return results
