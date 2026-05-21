"""AI threat analyzer with DeepSeek API and robust mock fallback."""

from __future__ import annotations

import json
import os
import re
from dataclasses import asdict, dataclass
from dataclasses import replace
from datetime import datetime, timezone
from typing import Any, Iterable, Sequence

import requests

from scripts.fetcher import FeedEntry


Severity = str


@dataclass(slots=True)
class AnalysisItem:
    """Structured threat analysis for one feed entry."""

    title: str
    source: str
    url: str
    published_at: str
    severity: Severity
    vulnerability_type: str
    cvss_score: float
    confidence: float
    attack_vector: str
    affected_assets: list[str]
    iocs: list[str]
    summary_en: str
    summary_fa: str
    remediation_en: str
    remediation_fa: str
    exploitation_likelihood: str = "medium"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class AnalysisResult:
    """Container for a full analyzer run."""

    generated_at: str
    provider: str
    used_mock_ai: bool
    total_items: int
    summary_en: str
    summary_fa: str
    items: list[AnalysisItem]

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["items"] = [item.to_dict() for item in self.items]
        return payload


@dataclass(frozen=True, slots=True)
class _ThreatProfile:
    keyword_groups: tuple[tuple[str, ...], ...]
    severity: Severity
    vulnerability_type: str
    cvss_score: float
    confidence: float
    attack_vector: str
    affected_assets: tuple[str, ...]
    iocs: tuple[str, ...]
    remediation_en: str
    remediation_fa: str


class Analyzer:
    """Analyze collected entries with DeepSeek or a deterministic mock model."""

    def __init__(
        self,
        api_key: str | None = None,
        model: str = "deepseek-chat",
        base_url: str = "https://api.deepseek.com/chat/completions",
        timeout: int = 45,
    ) -> None:
        self.api_key = api_key or os.getenv("DEEPSEEK_API_KEY", "").strip()
        self.model = model
        self.base_url = base_url
        self.timeout = timeout

    def analyze(self, entries: Sequence[FeedEntry], use_mock_ai: bool = False, enricher: Any | None = None) -> AnalysisResult:
        """Analyze entries and return structured results."""

        prepared_entries = self._apply_enrichment_context(entries, enricher)

        if not prepared_entries:
            return AnalysisResult(
                generated_at=datetime.now(timezone.utc).isoformat(),
                provider="mock-ai" if use_mock_ai or not self.api_key else "deepseek",
                used_mock_ai=True,
                total_items=0,
                summary_en="No new threat intelligence entries were available.",
                summary_fa="No new threat intelligence entries were available.",
                items=[],
            )

        if use_mock_ai or not self.api_key:
            return self._mock_analysis(prepared_entries)

        try:
            return self._analyze_with_deepseek(prepared_entries)
        except Exception:
            return self._mock_analysis(prepared_entries)

    def _apply_enrichment_context(self, entries: Sequence[FeedEntry], enricher: Any | None) -> list[FeedEntry]:
        if enricher is None:
            return list(entries)

        prepared: list[FeedEntry] = []
        for entry in entries:
            cve_id = getattr(enricher, "extract_cve_id", lambda value: None)(f"{entry.title} {entry.summary}")
            enrichment_parts: list[str] = []
            if cve_id and hasattr(enricher, "enrich_cve"):
                info = enricher.enrich_cve(cve_id)
                if info:
                    if info.cvss_score:
                        enrichment_parts.append(f"CVSS {info.cvss_score:.1f}")
                    if info.nist_severity:
                        enrichment_parts.append(f"Severity {info.nist_severity}")
                    if info.exploitation_status:
                        enrichment_parts.append(f"Exploit status {info.exploitation_status}")
                    if info.description:
                        enrichment_parts.append(f"Affected software {info.description}")
            summary = entry.summary
            if enrichment_parts:
                summary = f"{summary} Enrichment context: {'; '.join(enrichment_parts)}."
            prepared.append(replace(entry, summary=summary))

        return prepared

    def _analyze_with_deepseek(self, entries: Sequence[FeedEntry]) -> AnalysisResult:
        prompt_entries = [entry.to_dict() for entry in entries]

        system_prompt = (
            "You are a senior threat intelligence analyst. Return only valid JSON with this schema: "
            '{"summary_en": str, "summary_fa": str, "items": [ {'
            '"title": str, "source": str, "url": str, "published_at": str, '
            '"severity": "low|medium|high|critical", "vulnerability_type": str, '
            '"cvss_score": float, "confidence": float, "attack_vector": str, '
            '"affected_assets": [str], "iocs": [str], "summary_en": str, "summary_fa": str, '
            '"remediation_en": str, "remediation_fa": str, "exploitation_likelihood": "low|medium|high" } ] }. '
            "All textual fields must be written in English only and must remain concise, professional, and faithful to the inputs."
        )

        user_prompt = (
            "Analyze each intelligence entry and infer realistic cybersecurity details. "
            "Use a clear severity rating, a normalized vulnerability type, and concise but actionable remediation. "
            "Keep cvss_score between 0 and 10 and confidence between 0 and 1. "
            "Include exploitation_likelihood as low, medium, or high. "
            "Provide English-only summaries and remediation guidance.\n\n"
            f"Entries:\n{json.dumps(prompt_entries, ensure_ascii=False)}"
        )

        response = requests.post(
            self.base_url,
            timeout=self.timeout,
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
            },
        )
        response.raise_for_status()

        payload = response.json()
        content = self._extract_message_content(payload)
        parsed = self._load_json_document(content)
        items = self._normalize_items(parsed.get("items", []), entries)

        return AnalysisResult(
            generated_at=datetime.now(timezone.utc).isoformat(),
            provider="deepseek",
            used_mock_ai=False,
            total_items=len(items),
            summary_en=self._safe_text(parsed.get("summary_en")) or self._summarize_en(items),
            summary_fa=self._safe_text(parsed.get("summary_fa")) or self._summarize_en(items),
            items=items,
        )

    @staticmethod
    def _extract_message_content(payload: dict[str, Any]) -> str:
        choices = payload.get("choices")
        if isinstance(choices, list) and choices:
            first_choice = choices[0] if isinstance(choices[0], dict) else {}
            message = first_choice.get("message", {}) if isinstance(first_choice, dict) else {}
            if isinstance(message, dict) and message.get("content") is not None:
                return str(message.get("content", ""))
            if first_choice.get("text") is not None:
                return str(first_choice.get("text", ""))
        raise ValueError("DeepSeek response did not include a message payload")

    @staticmethod
    def _strip_code_fences(value: str) -> str:
        text = value.strip()
        if text.startswith("```"):
            text = re.sub(r"^```(?:json)?\s*", "", text, flags=re.IGNORECASE)
            text = re.sub(r"\s*```$", "", text)
        return text.strip()

    def _load_json_document(self, content: str) -> dict[str, Any]:
        text = self._strip_code_fences(content)
        start_candidates = [idx for idx in (text.find("{"), text.find("[")) if idx != -1]
        start = min(start_candidates) if start_candidates else -1
        if start == -1:
            raise ValueError("DeepSeek response did not contain JSON content")

        candidate = text[start:].strip()
        try:
            parsed = json.loads(candidate)
        except json.JSONDecodeError:
            parsed = json.loads(self._best_effort_json_slice(candidate))

        if isinstance(parsed, list):
            return {"items": parsed}
        if not isinstance(parsed, dict):
            raise ValueError("DeepSeek response JSON must be an object or array")
        return parsed

    @staticmethod
    def _best_effort_json_slice(text: str) -> str:
        opening = text.find("{")
        closing = text.rfind("}")
        if opening == -1 or closing == -1 or closing <= opening:
            raise ValueError("Could not isolate JSON payload from DeepSeek response")
        return text[opening : closing + 1]

    @staticmethod
    def _safe_text(value: Any) -> str:
        if value is None:
            return ""
        if isinstance(value, str):
            return value.strip()
        return str(value).strip()

    @staticmethod
    def _ensure_list(value: Any) -> list[str]:
        if isinstance(value, list):
            return [str(item).strip() for item in value if str(item).strip()]
        if value is None:
            return []
        text = str(value).strip()
        return [text] if text else []

    def _normalize_items(self, raw_items: Any, entries: Sequence[FeedEntry]) -> list[AnalysisItem]:
        normalized: list[AnalysisItem] = []
        raw_list = raw_items if isinstance(raw_items, list) else []

        for index, entry in enumerate(entries):
            raw_item = raw_list[index] if index < len(raw_list) and isinstance(raw_list[index], dict) else {}
            fallback = self._build_mock_item(entry)

            normalized.append(
                AnalysisItem(
                    title=self._safe_text(raw_item.get("title")) or entry.title,
                    source=self._safe_text(raw_item.get("source")) or entry.source,
                    url=self._safe_text(raw_item.get("url")) or entry.url,
                    published_at=self._safe_text(raw_item.get("published_at")) or entry.published_at,
                    severity=self._normalize_severity(raw_item.get("severity")) or fallback.severity,
                    vulnerability_type=self._safe_text(raw_item.get("vulnerability_type")) or fallback.vulnerability_type,
                    cvss_score=self._coerce_float(raw_item.get("cvss_score"), fallback.cvss_score),
                    confidence=self._coerce_float(raw_item.get("confidence"), fallback.confidence),
                    attack_vector=self._safe_text(raw_item.get("attack_vector")) or fallback.attack_vector,
                    affected_assets=self._ensure_list(raw_item.get("affected_assets")) or fallback.affected_assets,
                    iocs=self._ensure_list(raw_item.get("iocs")) or fallback.iocs,
                    summary_en=self._safe_text(raw_item.get("summary_en")) or fallback.summary_en,
                    summary_fa=self._safe_text(raw_item.get("summary_fa")) or fallback.summary_fa,
                    remediation_en=self._safe_text(raw_item.get("remediation_en")) or fallback.remediation_en,
                    remediation_fa=self._safe_text(raw_item.get("remediation_fa")) or fallback.remediation_fa,
                    exploitation_likelihood=self._safe_text(raw_item.get("exploitation_likelihood")) or fallback.exploitation_likelihood,
                )
            )

        return normalized

    @staticmethod
    def _normalize_severity(value: Any) -> str:
        severity = str(value or "").strip().lower()
        if severity in {"low", "medium", "high", "critical"}:
            return severity
        return ""

    @staticmethod
    def _coerce_float(value: Any, default: float) -> float:
        try:
            return float(value)
        except (TypeError, ValueError):
            return default

    def _mock_analysis(self, entries: Sequence[FeedEntry]) -> AnalysisResult:
        """Return deterministic mock AI output in English only."""

        items = [self._build_mock_item(entry) for entry in entries]
        return AnalysisResult(
            generated_at=datetime.now(timezone.utc).isoformat(),
            provider="mock-ai",
            used_mock_ai=True,
            total_items=len(items),
            summary_en=self._summarize_en(items),
            summary_fa=self._summarize_en(items),
            items=items,
        )

    def _build_mock_item(self, entry: FeedEntry) -> AnalysisItem:
        profile = self._infer_profile(entry)
        summary_en = self._build_summary_en(entry, profile)
        summary_fa = self._build_summary_fa(entry, profile)
        return AnalysisItem(
            title=entry.title,
            source=entry.source,
            url=entry.url,
            published_at=entry.published_at,
            severity=profile.severity,
            vulnerability_type=profile.vulnerability_type,
            cvss_score=profile.cvss_score,
            confidence=profile.confidence,
            attack_vector=profile.attack_vector,
            affected_assets=list(profile.affected_assets),
            iocs=list(profile.iocs),
            summary_en=summary_en,
            summary_fa=summary_en,
            remediation_en=profile.remediation_en,
            remediation_fa=profile.remediation_en,
            exploitation_likelihood=self._derive_exploitation_likelihood(profile.severity, profile.keyword_groups, entry.summary),
        )

    def _infer_profile(self, entry: FeedEntry) -> _ThreatProfile:
        text = f"{entry.title} {entry.summary}".lower()

        profiles = [
            _ThreatProfile(
                keyword_groups=(("zero-day", "0-day", "n-day", "kernel"),),
                severity="critical",
                vulnerability_type="Kernel zero-day exploitation",
                cvss_score=9.8,
                confidence=0.92,
                attack_vector="Remote code execution via crafted kernel input",
                affected_assets=("Windows servers", "Privileged endpoints", "Tier-0 systems"),
                iocs=("Unexpected kernel faults", "RPC anomalies", "Suspicious child processes"),
                remediation_en=(
                    "Patch immediately, restrict exposed management interfaces, increase endpoint telemetry, and validate privileged account integrity."
                ),
                remediation_fa=(
                    "Patch immediately, restrict exposed management interfaces, increase endpoint telemetry, and validate privileged account integrity."
                ),
            ),
            _ThreatProfile(
                keyword_groups=(("ransomware", "encrypt", "locker"),),
                severity="high",
                vulnerability_type="Ransomware intrusion",
                cvss_score=8.9,
                confidence=0.89,
                attack_vector="Phishing foothold followed by lateral movement and mass encryption",
                affected_assets=("Linux servers", "Database volumes", "Backup repositories"),
                iocs=("Bulk file rewrites", "Encrypted extensions", "Suspicious scheduled tasks"),
                remediation_en=(
                    "Rotate exposed credentials, verify offline backups, isolate impacted hosts, and enforce least-privilege access on critical services."
                ),
                remediation_fa=(
                    "Rotate exposed credentials, verify offline backups, isolate impacted hosts, and enforce least-privilege access on critical services."
                ),
            ),
            _ThreatProfile(
                keyword_groups=(("log4j", "jndi", "rce"),),
                severity="high",
                vulnerability_type="Application-layer remote code execution",
                cvss_score=9.0,
                confidence=0.88,
                attack_vector="Obfuscated JNDI injection through user-controlled input",
                affected_assets=("Java applications", "API gateways", "Logging infrastructure"),
                iocs=("LDAP callbacks", "${jndi: patterns", "Unexpected JVM children"),
                remediation_en=(
                    "Upgrade vulnerable components, block outbound lookup protocols where possible, and hunt for obfuscated payloads in logs."
                ),
                remediation_fa=(
                    "Upgrade vulnerable components, block outbound lookup protocols where possible, and hunt for obfuscated payloads in logs."
                ),
            ),
            _ThreatProfile(
                keyword_groups=(("secret", "token", "leak", "github"),),
                severity="high",
                vulnerability_type="Secret exposure",
                cvss_score=8.2,
                confidence=0.87,
                attack_vector="Credential leakage in a public repository or artifact",
                affected_assets=("Cloud IAM accounts", "CI/CD tokens", "Container registries"),
                iocs=("Unexpected cloud API usage", "Token reuse", "Repository cloning bursts"),
                remediation_en=(
                    "Revoke exposed credentials, purge secrets from history, enforce secret scanning, and review cloud audit logs for abuse."
                ),
                remediation_fa=(
                    "Revoke exposed credentials, purge secrets from history, enforce secret scanning, and review cloud audit logs for abuse."
                ),
            ),
            _ThreatProfile(
                keyword_groups=(("pypi", "supply chain", "package", "dependency"),),
                severity="high",
                vulnerability_type="Software supply-chain compromise",
                cvss_score=8.5,
                confidence=0.86,
                attack_vector="Malicious package execution during installation",
                affected_assets=("Build runners", "Developer workstations", "Package mirrors"),
                iocs=("Outbound beaconing", "Encoded shell payloads", "Secrets access attempts"),
                remediation_en=(
                    "Pin dependencies, use trusted package mirrors, isolate build environments from secrets, and require signed artifacts."
                ),
                remediation_fa=(
                    "Pin dependencies, use trusted package mirrors, isolate build environments from secrets, and require signed artifacts."
                ),
            ),
        ]

        for profile in profiles:
            if any(keyword in text for group in profile.keyword_groups for keyword in group):
                return profile

        return _ThreatProfile(
            keyword_groups=(tuple(),),
            severity="medium",
            vulnerability_type="Potentially exploitable security issue",
            cvss_score=6.5,
            confidence=0.78,
            attack_vector="Potential misuse of exposed services or outdated components",
            affected_assets=("Application servers", "User endpoints", "Shared infrastructure"),
            iocs=("Unusual service requests", "Log anomalies", "Credential misuse"),
            remediation_en=(
                "Review the affected asset, patch exposed components, harden access controls, and monitor logs for follow-up activity."
            ),
            remediation_fa=(
                "Review the affected asset, patch exposed components, harden access controls, and monitor logs for follow-up activity."
            ),
        )

    def _build_summary_en(self, entry: FeedEntry, profile: _ThreatProfile) -> str:
        return (
            f"{entry.title} suggests a {profile.severity} {profile.vulnerability_type.lower()} affecting "
            f"{', '.join(profile.affected_assets[:2])}. The likely attack path is {profile.attack_vector.lower()}."
        )

    def _build_summary_fa(self, entry: FeedEntry, profile: _ThreatProfile) -> str:
        severity_label = self._severity_label(profile.severity)
        return (
            f"{entry.title} indicates a {severity_label} event involving {profile.vulnerability_type}. "
            f"Likely attack vector: {profile.attack_vector}. Recommended action: {profile.remediation_en}"
        )

    @staticmethod
    def _severity_label(severity: str) -> str:
        return {
            "critical": "critical",
            "high": "high",
            "medium": "medium",
            "low": "low",
        }.get(severity, "medium")

    def _summarize_en(self, items: Iterable[AnalysisItem]) -> str:
        items_list = list(items)
        if not items_list:
            return "No findings were generated."

        severity_counts: dict[str, int] = {}
        for item in items_list:
            severity_counts[item.severity] = severity_counts.get(item.severity, 0) + 1

        high_or_critical = severity_counts.get("critical", 0) + severity_counts.get("high", 0)
        top_types = sorted({item.vulnerability_type for item in items_list})[:3]
        return (
            f"Analyzed {len(items_list)} items. {high_or_critical} findings require urgent attention, "
            f"with primary focus on {', '.join(top_types)}."
        )

    def _summarize_fa(self, items: Iterable[AnalysisItem]) -> str:
        items_list = list(items)
        if not items_list:
            return "No findings were generated."

        severity_counts: dict[str, int] = {}
        for item in items_list:
            severity_counts[item.severity] = severity_counts.get(item.severity, 0) + 1

        urgent = severity_counts.get("critical", 0) + severity_counts.get("high", 0)
        top_types = sorted({item.vulnerability_type for item in items_list})[:3]
        return (
            f"Analyzed {len(items_list)} items. {urgent} findings require urgent attention, "
            f"with primary focus on {', '.join(top_types)}."
        )

    @staticmethod
    def _derive_exploitation_likelihood(severity: str, keyword_groups: tuple[tuple[str, ...], ...], text: str) -> str:
        lower_text = text.lower()
        if severity == "critical" or any(keyword in lower_text for group in keyword_groups for keyword in group if keyword):
            return "high"
        if severity == "high":
            return "medium"
        return "low"