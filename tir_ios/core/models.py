from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import List, Dict, Any
import json


class Severity(str, Enum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Info"


@dataclass
class Finding:
    finding_id: str
    title: str
    severity: Severity
    cvss_score: float
    masvs_category: str
    mastg_test_id: str
    phase: str  # "SAST" or "DAST"
    location: str
    evidence: str
    remediation: str
    confidence: str = "Unassessed"
    evidence_source: str = "Unspecified"
    verification_status: str = "Not Verified"

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["severity"] = self.severity.value
        return data


@dataclass
class ScanReport:
    app_name: str
    bundle_id: str
    bundle_version: str
    min_os_version: str
    architectures: List[str] = field(default_factory=list)
    findings: List[Finding] = field(default_factory=list)

    def add_finding(self, finding: Finding) -> None:
        self.findings.append(finding)

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(
            {
                "metadata": {
                    "app_name": self.app_name,
                    "bundle_id": self.bundle_id,
                    "bundle_version": self.bundle_version,
                    "min_os_version": self.min_os_version,
                    "architectures": self.architectures,
                    "total_findings": len(self.findings),
                },
                "findings": [f.to_dict() for f in self.findings],
            },
            indent=indent,
        )