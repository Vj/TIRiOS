from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from typing import List, Dict, Any
import json


class Severity(str, Enum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Info"


class EvidenceConfidence(str, Enum):
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    VERIFIED = "Verified"


class TrafficAttribution(str, Enum):
    UNATTRIBUTED = "Unattributed"
    DEVICE_LEVEL = "Device-level"
    APP_CORRELATED = "App-correlated"
    APP_CONFIRMED = "App-confirmed"


@dataclass
class RuntimeNetworkEvent:
    """A network syscall observed inside the instrumented target process."""

    process_id: int
    bundle_id: str
    timestamp: float
    destination_ip: str
    destination_port: int
    socket_fd: int | None = None
    local_ip: str | None = None
    local_port: int | None = None
    syscall: str = "connect"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class TLSAssessment(str, Enum):
    TLS_HANDSHAKE_OBSERVED = "TLS_HANDSHAKE_OBSERVED"
    PINNING_TEST_INCONCLUSIVE = "PINNING_TEST_INCONCLUSIVE"
    PINNING_ENFORCED = "PINNING_ENFORCED"
    PINNING_BYPASS_VERIFIED = "PINNING_BYPASS_VERIFIED"


@dataclass
class TLSObservation:
    """A proxy-side TLS observation; a handshake alone is not a pinning verdict."""

    host: str
    observed_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    assessment: TLSAssessment = TLSAssessment.TLS_HANDSHAKE_OBSERVED
    confidence: EvidenceConfidence = EvidenceConfidence.LOW
    attribution: TrafficAttribution = TrafficAttribution.UNATTRIBUTED
    bundle_id: str | None = None
    process_id: int | None = None
    connection_id: str | None = None
    tls_version: str | None = None
    cipher: str | None = None
    expected_spki_sha256: str | None = None
    observed_spki_sha256: str | None = None
    baseline_request_succeeded: bool | None = None
    proxy_certificate_trusted: bool | None = None
    mismatch_request_succeeded: bool | None = None
    notes: str = ""

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["assessment"] = self.assessment.value
        data["confidence"] = self.confidence.value
        data["attribution"] = self.attribution.value
        return data


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
