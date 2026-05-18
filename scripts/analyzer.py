"""AI threat analyzer with DeepSeek API and robust mock fallback."""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from typing import Literal, Sequence

import requests
from pydantic import BaseModel, Field, ValidationError

from scripts.fetcher import FeedEntry


Severity = Literal["low", "medium", "high", "critical"]


class AnalysisItem(BaseModel):
    """Structured threat analysis for one feed entry."""

    title: str
    source: str
    severity: Severity
    vulnerability_type: str
    cvss_score: float = Field(ge=0.0, le=10.0)
    confidence: float = Field(ge=0.0, le=1.0)
    attack_vector: str
    affected_assets: list[str]
    iocs: list[str]
    summary: str
    remediation: str
    url: str


class AnalysisResult(BaseModel):
    """Container for a full analyzer run."""

    generated_at: str
    provider: str
    used_mock_ai: bool
    total_items: int
    items: list[AnalysisItem]


class Analyzer:
    """Analyze collected entries with DeepSeek or a deterministic mock model."""

    def __init__(
        self,
        api_key: str | None = None,
        model: str = "deepseek-chat",
        base_url: str = "https://api.deepseek.com/chat/completions",
    ) -> None:
        self.api_key = api_key or os.getenv("DEEPSEEK_API_KEY", "")
        self.model = model
        self.base_url = base_url

    def analyze(self, entries: Sequence[FeedEntry], use_mock_ai: bool = False) -> AnalysisResult:
        """Analyze entries and return structured results.

        Falls back to a realistic mock result if `use_mock_ai=True`, if no API
        key is configured, or if the DeepSeek call fails.
        """

        if use_mock_ai or not self.api_key:
            return self._mock_analysis(entries)

        try:
            return self._analyze_with_deepseek(entries)
        except Exception:
            return self._mock_analysis(entries)

    def _analyze_with_deepseek(self, entries: Sequence[FeedEntry]) -> AnalysisResult:
        prompt_entries = [entry.model_dump() for entry in entries]

        system_prompt = (
            "You are a senior threat intelligence analyst. "
            "Return ONLY strict JSON with this schema: "
            "{\"items\": [{\"title\": str, \"source\": str, \"severity\": \"low|medium|high|critical\", "
            "\"vulnerability_type\": str, \"cvss_score\": float, \"confidence\": float, "
            "\"attack_vector\": str, \"affected_assets\": [str], \"iocs\": [str], "
            "\"summary\": str, \"remediation\": str, \"url\": str}]} "
            "All text fields must be in English."
        )

        user_prompt = (
            "Analyze these threat entries and estimate realistic security risk details. "
            "Keep cvss_score between 0 and 10 and confidence between 0 and 1. "
            "All text output must be English only.\n"
            f"Entries:\n{json.dumps(prompt_entries, ensure_ascii=False)}"
        )

        response = requests.post(
            self.base_url,
            timeout=45,
            headers={
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json",
            },
            json={
                "model": self.model,
                "temperature": 0.2,
                "messages": [
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt},
                ],
                "response_format": {"type": "json_object"},
            },
        )
        response.raise_for_status()

        payload = response.json()
        content = payload.get("choices", [{}])[0].get("message", {}).get("content", "")
        parsed = json.loads(content)
        items = parsed.get("items", []) if isinstance(parsed, dict) else []

        validated_items: list[AnalysisItem] = []
        for item in items:
            validated_items.append(AnalysisItem.model_validate(item))

        return AnalysisResult(
            generated_at=datetime.now(timezone.utc).isoformat(),
            provider="deepseek",
            used_mock_ai=False,
            total_items=len(validated_items),
            items=validated_items,
        )

    def _mock_analysis(self, entries: Sequence[FeedEntry]) -> AnalysisResult:
        """Return deterministic mock AI output in English."""

        fallback_items: list[AnalysisItem] = []
        for entry in entries:
            fallback_items.append(self._build_mock_item(entry))

        return AnalysisResult(
            generated_at=datetime.now(timezone.utc).isoformat(),
            provider="mock-ai",
            used_mock_ai=True,
            total_items=len(fallback_items),
            items=fallback_items,
        )

    def _build_mock_item(self, entry: FeedEntry) -> AnalysisItem:
        title_lower = entry.title.lower()

        if "zero-day" in title_lower or "kernel" in title_lower:
            severity: Severity = "critical"
            vulnerability_type = "Windows kernel zero-day"
            cvss = 9.8
            vector = "Remote code execution through crafted RPC requests"
            assets = ["Domain Controllers", "Windows Servers", "Tier-0 Endpoints"]
            iocs = ["Abnormal RPC traffic spikes", "Unexpected LSASS child process", "Event ID 4688 anomalies"]
            summary = (
                "This threat indicates a Windows kernel zero-day that can grant SYSTEM-level execution via malformed "
                "RPC handling. Successful exploitation can bypass endpoint controls, enable credential theft from memory, "
                "and accelerate lateral movement in flat network segments."
            )
            remediation = (
                "Immediately deploy the vendor patch, restrict RPC exposure at host and network firewalls, enable behavior-based "
                "detections for abnormal process execution, rotate privileged credentials, and perform incident-response memory "
                "forensics on high-value systems."
            )
        elif "ransomware" in title_lower:
            severity = "high"
            vulnerability_type = "Ransomware campaign"
            cvss = 8.9
            vector = "Phishing foothold followed by SSH pivot and mass encryption"
            assets = ["Linux Application Servers", "Database Volumes", "Backup Repositories"]
            iocs = ["Bulk file extension changes", "High entropy writes", "Unauthorized scheduled jobs"]
            summary = (
                "The campaign starts with phishing and moves laterally using stolen SSH material. The payload stops database "
                "services and encrypts critical file systems while attempting to reduce traceability through log tampering."
            )
            remediation = (
                "Rotate SSH keys, disable password-based SSH authentication, validate offline backup recovery, deploy file integrity "
                "monitoring, enforce least privilege on database accounts, and isolate impacted hosts immediately."
            )
        elif "log4j" in title_lower:
            severity = "high"
            vulnerability_type = "Remote code execution in logging dependency"
            cvss = 9.0
            vector = "JNDI injection through headers and user-controlled fields"
            assets = ["Java API Gateways", "Legacy Microservices", "Logging Infrastructure"]
            iocs = ["${jndi: patterns in logs", "Unexpected LDAP egress", "Unusual JVM child processes"]
            summary = (
                "The attack pattern uses obfuscated JNDI payloads embedded in request metadata to trigger remote code execution "
                "in unpatched Java workloads, followed by callback traffic to attacker-controlled infrastructure."
            )
            remediation = (
                "Upgrade to a fixed logging library version, disable vulnerable lookup behavior, block outbound LDAP/RMI where "
                "unneeded, harden WAF signatures for obfuscated payloads, and run software composition analysis across transitive dependencies."
            )
        elif "github" in title_lower or "leak" in title_lower:
            severity = "high"
            vulnerability_type = "Secret exposure"
            cvss = 8.2
            vector = "Credential leakage in public source repository"
            assets = ["Cloud IAM Accounts", "CI/CD Tokens", "Container Registries"]
            iocs = ["Unexpected cloud API usage", "Token reuse from unknown ASN", "Bulk repository cloning"]
            summary = (
                "Public repository exposure of operational secrets can compromise build and deployment trust boundaries. "
                "Attackers may use leaked cloud keys and CI tokens to publish malicious artifacts or exfiltrate sensitive data."
            )
            remediation = (
                "Revoke and rotate all exposed credentials, purge secrets from repository history, enforce repository secret scanning, "
                "tighten IAM policies, and investigate cloud audit logs for unauthorized activity."
            )
        else:
            severity = "high"
            vulnerability_type = "Supply-chain package compromise"
            cvss = 8.5
            vector = "Malicious package execution during dependency installation"
            assets = ["Build Runners", "Developer Workstations", "Private Package Mirrors"]
            iocs = ["Network beacons during install", "Encoded shell payloads", "Credential file access attempts"]
            summary = (
                "The threat abuses software supply-chain trust by executing malicious code during package installation to steal "
                "tokens and environment secrets, then propagates persistence into CI pipelines and downstream releases."
            )
            remediation = (
                "Block suspicious packages, enforce signed internal mirrors, isolate installation environments from secrets, "
                "pin dependency versions, apply strict dependency risk gates, and rotate CI credentials."
            )

        try:
            return AnalysisItem(
                title=entry.title,
                source=entry.source,
                severity=severity,
                vulnerability_type=vulnerability_type,
                cvss_score=cvss,
                confidence=0.88,
                attack_vector=vector,
                affected_assets=assets,
                iocs=iocs,
                summary=summary,
                remediation=remediation,
                url=entry.url,
            )
        except ValidationError as error:
            raise RuntimeError(f"Failed to build mock analysis item for {entry.title!r}: {error}") from error