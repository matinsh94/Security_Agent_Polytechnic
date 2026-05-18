"""Threat scoring engine (0-100 risk model) for CTI analysis."""

from __future__ import annotations

import re


class ThreatScorer:
    """Score threats on 0-100 scale using weighted intelligence signals."""

    def __init__(self) -> None:
        """Initialize threat scorer with weights."""
        self.weights = {
            'cvss_score': 0.30,
            'active_exploitation': 0.25,
            'malware_association': 0.20,
            'attack_surface': 0.15,
            'ransomware_linkage': 0.10,
        }

    def score(
        self,
        title: str,
        description: str,
        cvss_score: float = 0.0,
        has_public_exploit: bool = False,
        is_in_kev: bool = False,
        is_ransomware: bool = False,
        is_mass_exploitation: bool = False,
    ) -> int:
        """Calculate threat score (0-100) using weighted signals."""

        # Extract CVSS component (normalized 0-100)
        cvss_component = self._normalize_cvss(cvss_score)

        # Exploitation activity (KEV listing, public PoC, mass exploitation)
        exploitation_component = self._score_exploitation(
            has_public_exploit=has_public_exploit,
            is_in_kev=is_in_kev,
            is_mass_exploitation=is_mass_exploitation,
        )

        # Malware association detection
        malware_component = self._score_malware_association(title, description)

        # Attack surface scoring
        attack_surface_component = self._score_attack_surface(title, description)

        # Ransomware linkage
        ransomware_component = self._score_ransomware(is_ransomware, title, description)

        # Calculate weighted score
        raw_score = (
            self.weights['cvss_score'] * cvss_component +
            self.weights['active_exploitation'] * exploitation_component +
            self.weights['malware_association'] * malware_component +
            self.weights['attack_surface'] * attack_surface_component +
            self.weights['ransomware_linkage'] * ransomware_component
        )

        # Apply auto-escalation rules
        final_score = self._apply_escalation_rules(
            raw_score,
            is_in_kev=is_in_kev,
            is_ransomware=is_ransomware,
            has_public_exploit=has_public_exploit,
        )

        return int(min(100, max(0, final_score)))

    def classify_severity(self, score: int) -> str:
        """Classify severity based on threat score."""
        if score >= 90:
            return 'critical'
        elif score >= 70:
            return 'high'
        elif score >= 50:
            return 'medium'
        else:
            return 'low'

    def _normalize_cvss(self, cvss_score: float) -> float:
        """Normalize CVSS 0-10 to 0-100."""
        return min(100, max(0, cvss_score * 10))

    def _score_exploitation(
        self,
        has_public_exploit: bool,
        is_in_kev: bool,
        is_mass_exploitation: bool,
    ) -> float:
        """Score based on active exploitation signals."""
        score = 0.0

        if is_in_kev:
            score += 50.0  # KEV listing is significant

        if has_public_exploit:
            score += 35.0  # Public PoC available

        if is_mass_exploitation:
            score += 15.0  # Active mass exploitation

        return min(100, score)

    def _score_malware_association(self, title: str, description: str) -> float:
        """Detect malware family associations."""
        text = (title + ' ' + description).lower()

        malware_keywords = [
            'trojan', 'ransomware', 'worm', 'botnet', 'backdoor',
            'spyware', 'adware', 'rootkit', 'malware', 'virus',
            'dropper', 'loader', 'stealer', 'cryptolocker',
        ]

        detected = sum(1 for keyword in malware_keywords if keyword in text)

        # Scale: 1 keyword = 20, 2+ = 100
        if detected == 0:
            return 0.0
        elif detected == 1:
            return 20.0
        else:
            return 100.0

    def _score_attack_surface(self, title: str, description: str) -> float:
        """Score public-facing attack surface exposure."""
        text = (title + ' ' + description).lower()

        public_facing_keywords = [
            'internet-facing', 'public', 'web application', 'api', 'rce',
            'remote code execution', 'network-accessible', 'web server',
            'browser', 'default credentials', 'pre-auth',
        ]

        detected = sum(1 for keyword in public_facing_keywords if keyword in text)

        if detected >= 2:
            return 100.0
        elif detected == 1:
            return 60.0
        else:
            return 20.0

    def _score_ransomware(self, is_ransomware: bool, title: str, description: str) -> float:
        """Score ransomware-related threats."""
        if is_ransomware:
            return 100.0

        text = (title + ' ' + description).lower()
        ransomware_keywords = ['ransomware', 'encryption', 'locked', 'payment', 'decryption']

        detected = sum(1 for keyword in ransomware_keywords if keyword in text)

        if detected >= 2:
            return 80.0
        elif detected == 1:
            return 40.0
        else:
            return 0.0

    def _apply_escalation_rules(
        self,
        score: float,
        is_in_kev: bool = False,
        is_ransomware: bool = False,
        has_public_exploit: bool = False,
    ) -> float:
        """Apply auto-escalation rules based on priority signals."""
        escalated_score = score

        # KEV listed forces at least 'high' severity (70)
        if is_in_kev and escalated_score < 70:
            escalated_score = 70

        # Ransomware forces at least 'critical' (90)
        if is_ransomware and escalated_score < 90:
            escalated_score = 90

        # Public exploit boosts by 15 points
        if has_public_exploit and escalated_score < 100:
            escalated_score += 15

        return min(100, escalated_score)

    def detect_kev_signals(self, title: str, description: str) -> bool:
        """Heuristically detect if vulnerability appears to be in CISA KEV."""
        text = (title + ' ' + description).lower()
        kev_signals = [
            'known exploited',
            'cisa',
            'exploitation campaign',
            'active exploitation',
            'in the wild',
        ]
        return any(signal in text for signal in kev_signals)

    def detect_mass_exploitation(self, title: str, description: str) -> bool:
        """Detect mass exploitation signals."""
        text = (title + ' ' + description).lower()
        mass_exploitation_signals = [
            'mass exploitation',
            'widespread attacks',
            'thousands of',
            'multiple organizations',
            'global campaign',
            'automated attacks',
        ]
        return any(signal in text for signal in mass_exploitation_signals)

    def score_from_cvss_string(self, cvss_string: str) -> dict:
        """Parse CVSS string and extract numeric score."""
        # Pattern: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" or "9.8" or "Score: 9.8"
        match = re.search(r'(\d+\.\d+)', cvss_string)
        if match:
            return {
                'cvss_score': float(match.group(1)),
                'has_public_exploit': 'public' in cvss_string.lower(),
            }
        return {'cvss_score': 0.0, 'has_public_exploit': False}
