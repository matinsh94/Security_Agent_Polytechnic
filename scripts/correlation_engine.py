"""Correlation engine for linking related CTI findings."""

from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
from itertools import combinations
from typing import Iterable

from scripts.report_generator import ThreatFinding


@dataclass(slots=True)
class CorrelationCluster:
    """Related threat findings grouped by shared evidence."""

    campaign_id: str
    title: str
    finding_titles: list[str]
    cves: list[str]
    iocs: list[str]
    finding_count: int
    reason: str
    risk_score: int
    explanation: str


@dataclass(slots=True)
class CorrelationResult:
    """Structured correlation output."""

    total_clusters: int
    related_findings: int
    clusters: list[CorrelationCluster]

    def to_dict(self) -> dict[str, object]:
        payload = asdict(self)
        payload['clusters'] = [asdict(cluster) for cluster in self.clusters]
        return payload


class CorrelationEngine:
    """Detect basic relationships across threat findings."""

    def correlate(self, findings: Iterable[ThreatFinding]) -> CorrelationResult:
        findings_list = list(findings)
        clusters: list[CorrelationCluster] = []
        used_titles: set[str] = set()

        normalized_iocs: list[tuple[ThreatFinding, set[str]]] = []
        for finding in findings_list:
            values = {
                str(ioc.get('value', '')).strip().lower()
                for ioc in (finding.iocs or [])
                if isinstance(ioc, dict) and str(ioc.get('value', '')).strip()
            }
            normalized_iocs.append((finding, values))

        for left, right in combinations(normalized_iocs, 2):
            left_finding, left_iocs = left
            right_finding, right_iocs = right
            if left_finding.title in used_titles and right_finding.title in used_titles:
                continue

            shared_iocs = sorted(left_iocs & right_iocs)
            same_cve = left_finding.cve_id and right_finding.cve_id and left_finding.cve_id == right_finding.cve_id
            shared_software = self._shared_software(left_finding, right_finding)
            shared_keywords = self._shared_keywords(left_finding, right_finding)

            if not shared_iocs and not same_cve and not shared_software and not shared_keywords:
                continue

            cluster_titles = sorted({left_finding.title, right_finding.title})
            cluster_cves = sorted({cve for cve in [left_finding.cve_id, right_finding.cve_id] if cve})
            cluster_iocs = shared_iocs
            reason_parts = []
            if same_cve:
                reason_parts.append("Shared CVE identifier")
            if shared_iocs:
                reason_parts.append(f"Shared IOC values: {', '.join(shared_iocs)}")
            if shared_software:
                reason_parts.append(f"Shared software: {', '.join(shared_software)}")
            if shared_keywords:
                reason_parts.append(f"Shared keywords: {', '.join(shared_keywords)}")
            reason = "; ".join(reason_parts)
            risk_score = self._calculate_risk_score([left_finding, right_finding], shared_iocs, same_cve)
            explanation = reason or "Related threat activity detected"
            campaign_id = self._campaign_id(cluster_cves, cluster_titles, shared_iocs)

            clusters.append(
                CorrelationCluster(
                    campaign_id=campaign_id,
                    title=f"Related cluster: {cluster_titles[0]}",
                    finding_titles=cluster_titles,
                    cves=cluster_cves,
                    iocs=cluster_iocs,
                    finding_count=len(cluster_titles),
                    reason=reason,
                    risk_score=risk_score,
                    explanation=explanation,
                )
            )
            used_titles.update(cluster_titles)

        if not clusters and findings_list:
            cluster_cves = [findings_list[0].cve_id] if findings_list[0].cve_id else []
            campaign_id = self._campaign_id(cluster_cves, [findings_list[0].title], [])
            clusters.append(
                CorrelationCluster(
                    campaign_id=campaign_id,
                    title=f"Independent finding: {findings_list[0].title}",
                    finding_titles=[findings_list[0].title],
                    cves=cluster_cves,
                    iocs=sorted({
                        str(ioc.get('value', '')).strip().lower()
                        for ioc in (findings_list[0].iocs or [])
                        if isinstance(ioc, dict) and str(ioc.get('value', '')).strip()
                    }),
                    finding_count=1,
                    reason="No direct cross-finding correlations detected",
                    risk_score=self._severity_score([findings_list[0].severity]),
                    explanation="No direct cross-finding correlations detected",
                )
            )

        return CorrelationResult(
            total_clusters=len(clusters),
            related_findings=sum(cluster.finding_count for cluster in clusters),
            clusters=clusters,
        )

    @staticmethod
    def _campaign_id(cves: list[str], titles: list[str], iocs: list[str]) -> str:
        basis = "|".join(sorted(cves + titles + iocs))
        digest = hashlib.sha1(basis.encode("utf-8")).hexdigest()[:12]
        return f"campaign-{digest}"

    @staticmethod
    def _shared_software(left: ThreatFinding, right: ThreatFinding) -> list[str]:
        left_systems = {item.lower() for item in (left.affected_systems or [])}
        right_systems = {item.lower() for item in (right.affected_systems or [])}
        return sorted(left_systems & right_systems)

    @staticmethod
    def _shared_keywords(left: ThreatFinding, right: ThreatFinding) -> list[str]:
        keywords = {"ransomware", "exploit", "privilege", "injection", "credential", "exposure", "supply chain"}
        left_text = f"{left.title} {left.description}".lower()
        right_text = f"{right.title} {right.description}".lower()
        return sorted({keyword for keyword in keywords if keyword in left_text and keyword in right_text})

    @staticmethod
    def _calculate_risk_score(findings: list[ThreatFinding], shared_iocs: list[str], same_cve: bool) -> int:
        score = max(finding.threat_score for finding in findings)
        score += min(10, len(shared_iocs) * 5)
        if same_cve:
            score += 10
        return min(100, score)

    @staticmethod
    def _severity_score(severities: list[str]) -> int:
        mapping = {"critical": 90, "high": 75, "medium": 55, "low": 30}
        return max(mapping.get(severity.lower(), 40) for severity in severities if severity) if severities else 40