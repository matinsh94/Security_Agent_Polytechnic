"""Threat actor attribution via OSINT (mock fallback)."""
from __future__ import annotations
import logging
from typing import Any
logger = logging.getLogger(__name__)

KNOWN_GROUPS = {
    "apt28": ["CVE-2023", "phishing"],
    "lazarus": ["ransomware", "crypto"],
}

class ThreatActorAttribution:
    def attribute(self, text: str, cves: list[str] | None = None) -> list[str]:
        text_l = (text or "").lower()
        actors = []
        for g, kws in KNOWN_GROUPS.items():
            if any(k in text_l for k in kws):
                actors.append(g)
        if not actors and cves:
            actors.append("unknown")
        return actors
