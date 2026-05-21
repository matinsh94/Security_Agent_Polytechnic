"""Correlation engine for linking related CTI findings."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from itertools import combinations
from typing import Iterable

from scripts.report_generator import ThreatFinding


@dataclass(slots=True)
class CorrelationCluster:
    """Related threat findings grouped by shared evidence."""

    title: str
    finding_titles: list[str]
    cves: list[str]
    iocs: list[str]
    finding_count: int
    reason: str


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

            if not shared_iocs and not same_cve:
                continue

            cluster_titles = sorted({left_finding.title, right_finding.title})
            cluster_cves = sorted({cve for cve in [left_finding.cve_id, right_finding.cve_id] if cve})
            cluster_iocs = shared_iocs
            reason = "Shared CVE identifier" if same_cve else f"Shared IOC values: {', '.join(shared_iocs)}"

            clusters.append(
                CorrelationCluster(
                    title=f"Related cluster: {cluster_titles[0]}",
                    finding_titles=cluster_titles,
                    cves=cluster_cves,
                    iocs=cluster_iocs,
                    finding_count=len(cluster_titles),
                    reason=reason,
                )
            )
            used_titles.update(cluster_titles)

        if not clusters and findings_list:
            clusters.append(
                CorrelationCluster(
                    title=f"Independent finding: {findings_list[0].title}",
                    finding_titles=[findings_list[0].title],
                    cves=[findings_list[0].cve_id] if findings_list[0].cve_id else [],
                    iocs=sorted({
                        str(ioc.get('value', '')).strip().lower()
                        for ioc in (findings_list[0].iocs or [])
                        if isinstance(ioc, dict) and str(ioc.get('value', '')).strip()
                    }),
                    finding_count=1,
                    reason="No direct cross-finding correlations detected",
                )
            )

        return CorrelationResult(
            total_clusters=len(clusters),
            related_findings=sum(cluster.finding_count for cluster in clusters),
            clusters=clusters,
        )