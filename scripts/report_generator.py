"""Report generator for multi-format CTI output."""

from __future__ import annotations

import csv
import json
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from io import StringIO
from typing import Any


@dataclass
class ThreatFinding:
    """Structured threat finding for reporting."""
    
    title: str
    source: str
    severity: str
    threat_score: int
    cvss_score: float = 0.0
    cve_id: str | None = None
    description: str = ""
    affected_systems: list[str] | None = None
    iocs: list[dict] | None = None
    mitre_tactics: list[str] | None = None
    remediation_en: str = ""
    remediation_secondary: str = ""


class ReportGenerator:
    """Generate threat intelligence reports in multiple formats."""

    def __init__(self) -> None:
        """Initialize report generator."""
        self.generated_at = datetime.now(timezone.utc).isoformat()

    def generate_json(
        self,
        findings: list[ThreatFinding],
        metadata: dict | None = None,
        correlation_data: dict | None = None,
    ) -> str:
        """Generate JSON report."""
        cve_list = self._collect_cves(findings)
        ioc_inventory = self._collect_iocs(findings)
        report = {
            'generated_at': self.generated_at,
            'format': 'json',
            'metadata': metadata or {},
            'summary': self._generate_summary(findings),
            'statistics': self._generate_statistics(findings),
            'cves': cve_list,
            'ioc_inventory': ioc_inventory,
            'insights': self._generate_insights(findings),
            'correlations': correlation_data or {},
            'findings': [asdict(finding) for finding in findings],
        }
        return json.dumps(report, indent=2, ensure_ascii=False)

    def generate_markdown(
        self,
        findings: list[ThreatFinding],
        title: str = "Threat Intelligence Report",
        correlation_data: dict | None = None,
    ) -> str:
        """Generate Markdown report."""
        lines: list[str] = []

        # Header
        lines.append(f"# {title}")
        lines.append(f"_Generated: {self.generated_at}_\n")

        # Summary
        lines.append("## Executive Summary\n")
        summary = self._generate_summary(findings)
        lines.append(f"{summary.get('overview', '')}\n")

        # Statistics
        stats = self._generate_statistics(findings)
        lines.append("## Statistics\n")
        lines.append(f"- **Total Threats**: {stats.get('total_findings', 0)}")
        lines.append(f"- **Critical**: {stats.get('critical_count', 0)}")
        lines.append(f"- **High**: {stats.get('high_count', 0)}")
        lines.append(f"- **Medium**: {stats.get('medium_count', 0)}")
        lines.append(f"- **Low**: {stats.get('low_count', 0)}")
        lines.append(f"- **Average Threat Score**: {stats.get('average_threat_score', 0):.1f}")
        lines.append(f"- **CVE Count**: {stats.get('findings_with_cve', 0)}")
        lines.append(f"- **IOC Findings**: {stats.get('findings_with_iocs', 0)}")
        lines.append("")

        cves = self._collect_cves(findings)
        if cves:
            lines.append("## CVEs\n")
            for cve in cves:
                lines.append(f"- {cve}")
            lines.append("")

        ioc_inventory = self._collect_iocs(findings)
        if ioc_inventory:
            lines.append("## IOC Inventory\n")
            for ioc_type, values in ioc_inventory.items():
                lines.append(f"### {ioc_type.upper()}")
                for value in values[:10]:
                    lines.append(f"- {value}")
                lines.append("")

        insights = self._generate_insights(findings)
        if insights:
            lines.append("## Threat Insights\n")
            for insight in insights:
                lines.append(f"- {insight}")
            lines.append("")

        if correlation_data:
            lines.append("## Correlations\n")
            clusters = correlation_data.get("clusters", []) if isinstance(correlation_data, dict) else []
            if isinstance(clusters, list):
                for cluster in clusters[:10]:
                    if not isinstance(cluster, dict):
                        continue
                    lines.append(f"- {cluster.get('title', 'Related cluster')} ({cluster.get('finding_count', 0)} findings)")
            lines.append("")

        # Findings
        lines.append("## Threat Findings\n")
        for i, finding in enumerate(findings, 1):
            lines.append(f"### {i}. {finding.title}")
            lines.append(f"**Severity**: {finding.severity.upper()}")
            lines.append(f"**Threat Score**: {finding.threat_score}/100")
            if finding.cve_id:
                lines.append(f"**CVE ID**: {finding.cve_id}")
            lines.append(f"**CVSS Score**: {finding.cvss_score:.1f}")
            lines.append(f"**Source**: {finding.source}")
            lines.append("")
            lines.append(f"{finding.description}\n")

            if finding.affected_systems:
                lines.append("**Affected Systems**:")
                for system in finding.affected_systems:
                    lines.append(f"- {system}")
                lines.append("")

            if finding.mitre_tactics:
                lines.append("**MITRE ATT&CK Tactics**:")
                for tactic in finding.mitre_tactics:
                    lines.append(f"- {tactic}")
                lines.append("")

            if finding.remediation_en:
                lines.append("**Remediation (English)**:")
                lines.append(f"{finding.remediation_en}\n")

            if finding.remediation_secondary:
                lines.append("**Alternative Remediation**:")
                lines.append(f"{finding.remediation_secondary}\n")

            lines.append("---\n")

        return "\n".join(lines)

    def generate_csv(self, findings: list[ThreatFinding]) -> str:
        """Generate CSV report."""
        output = StringIO()
        fieldnames = [
            'title', 'severity', 'threat_score', 'cvss_score', 'cve_id',
            'source', 'affected_systems', 'mitre_tactics'
        ]

        writer = csv.DictWriter(output, fieldnames=fieldnames)
        writer.writeheader()

        for finding in findings:
            row = {
                'title': finding.title,
                'severity': finding.severity,
                'threat_score': finding.threat_score,
                'cvss_score': finding.cvss_score,
                'cve_id': finding.cve_id or '',
                'source': finding.source,
                'affected_systems': '; '.join(finding.affected_systems or []),
                'mitre_tactics': '; '.join(finding.mitre_tactics or []),
            }
            writer.writerow(row)

        return output.getvalue()

    def generate_stix_like(self, findings: list[ThreatFinding]) -> str:
        """Generate STIX-like structured format."""
        report = {
            'type': 'threat-report',
            'generated': self.generated_at,
            'findings': []
        }

        for finding in findings:
            stix_obj = {
                'id': f"threat--{finding.title.replace(' ', '-').lower()}",
                'type': 'threat',
                'created': self.generated_at,
                'modified': self.generated_at,
                'name': finding.title,
                'description': finding.description,
                'severity': finding.severity,
                'score': finding.threat_score,
                'object_refs': {
                    'cve': finding.cve_id,
                    'affected_systems': finding.affected_systems or [],
                    'mitre_tactics': finding.mitre_tactics or [],
                }
            }
            report['findings'].append(stix_obj)

        return json.dumps(report, indent=2, ensure_ascii=False)

    @staticmethod
    def _generate_summary(findings: list[ThreatFinding]) -> dict[str, Any]:
        """Generate summary statistics."""
        total = len(findings)
        if total == 0:
            return {'overview': 'No threats detected.', 'threat_count': 0}

        critical = sum(1 for f in findings if f.severity == 'critical')
        high = sum(1 for f in findings if f.severity == 'high')
        avg_score = sum(f.threat_score for f in findings) / total if total > 0 else 0

        threat_types = set()
        for finding in findings:
            if 'remote code' in finding.title.lower():
                threat_types.add('Remote Code Execution')
            if 'ransomware' in finding.title.lower():
                threat_types.add('Ransomware')
            if 'privilege' in finding.title.lower():
                threat_types.add('Privilege Escalation')

        overview = f"Analyzed {total} threats. Found {critical} critical and {high} high-severity findings. Average threat score: {avg_score:.0f}/100."

        return {
            'overview': overview,
            'threat_count': total,
            'critical_count': critical,
            'high_count': high,
            'cve_count': sum(1 for f in findings if f.cve_id),
            'ioc_count': sum(len(f.iocs or []) for f in findings),
            'threat_types': list(threat_types),
        }

    @staticmethod
    def _generate_statistics(findings: list[ThreatFinding]) -> dict[str, Any]:
        """Generate detailed statistics."""
        if not findings:
            return {
                'total_findings': 0,
                'critical_count': 0,
                'high_count': 0,
                'medium_count': 0,
                'low_count': 0,
                'average_threat_score': 0,
            }

        return {
            'total_findings': len(findings),
            'critical_count': sum(1 for f in findings if f.severity == 'critical'),
            'high_count': sum(1 for f in findings if f.severity == 'high'),
            'medium_count': sum(1 for f in findings if f.severity == 'medium'),
            'low_count': sum(1 for f in findings if f.severity == 'low'),
            'average_threat_score': sum(f.threat_score for f in findings) / len(findings),
            'average_cvss_score': sum(f.cvss_score for f in findings) / len(findings),
            'findings_with_cve': sum(1 for f in findings if f.cve_id),
            'findings_with_iocs': sum(1 for f in findings if f.iocs),
        }

    @staticmethod
    def _collect_cves(findings: list[ThreatFinding]) -> list[str]:
        return sorted({finding.cve_id for finding in findings if finding.cve_id})

    @staticmethod
    def _collect_iocs(findings: list[ThreatFinding]) -> dict[str, list[str]]:
        inventory: dict[str, set[str]] = {}
        for finding in findings:
            for ioc in finding.iocs or []:
                if not isinstance(ioc, dict):
                    continue
                ioc_type = str(ioc.get('ioc_type', 'unknown')).strip().lower() or 'unknown'
                value = str(ioc.get('value', '')).strip()
                if not value:
                    continue
                inventory.setdefault(ioc_type, set()).add(value)
        return {ioc_type: sorted(values) for ioc_type, values in sorted(inventory.items())}

    @staticmethod
    def _generate_insights(findings: list[ThreatFinding]) -> list[str]:
        insights: list[str] = []
        if not findings:
            return insights

        critical_or_high = [finding for finding in findings if finding.severity in {'critical', 'high'}]
        if critical_or_high:
            insights.append(f"{len(critical_or_high)} findings require immediate attention.")

        cve_count = sum(1 for finding in findings if finding.cve_id)
        if cve_count:
            insights.append(f"{cve_count} findings are linked to explicit CVE identifiers.")

        ioc_count = sum(len(finding.iocs or []) for finding in findings)
        if ioc_count:
            insights.append(f"{ioc_count} IOC records were extracted across the report.")

        return insights
