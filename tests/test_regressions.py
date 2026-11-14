import json
import zipfile
from pathlib import Path

import pytest

from tir_ios.core.ipa_extractor import IPAExtractionError, IPAWorkspace
from tir_ios.core.models import Finding, Severity
from tir_ios.core.rule_registry import RuleRegistry
from tir_ios.modules.sast.secrets_scan import SECRET_PATTERNS
from tir_ios.reporting.merger import merge_scan_reports


def test_secret_patterns_have_three_fields():
    for name, pattern_data in SECRET_PATTERNS.items():
        assert len(pattern_data) == 3, name
        pattern, severity, remediation = pattern_data
        assert hasattr(pattern, "finditer")
        assert severity is None or isinstance(severity, Severity)
        assert isinstance(remediation, str)


def test_rule_registry_applies_cvss_override(tmp_path: Path):
    registry_path = tmp_path / "rules.json"
    registry_path.write_text(
        json.dumps(
            {
                "standards": {},
                "rules": {
                    "TEST-1": {
                        "rule_id": "TEST-1",
                        "title": "Test finding",
                        "severity": "Low",
                        "cvss_score": 2.0,
                        "masvs_category": "MASVS-STORAGE-1",
                        "mastg_test_id": "MASTG-TEST-0001",
                        "phase": "SAST",
                        "remediation": "Fix it",
                    }
                },
            }
        ),
        encoding="utf-8",
    )
    finding = RuleRegistry(registry_path).build_finding(
        rule_id="TEST-1",
        location="Info.plist",
        evidence="test evidence",
        cvss_override=8.1,
    )
    assert finding.cvss_score == 8.1


def test_ipa_extractor_rejects_parent_traversal(tmp_path: Path):
    ipa = tmp_path / "malicious.ipa"
    with zipfile.ZipFile(ipa, "w") as archive:
        archive.writestr("../outside.txt", "not safe")
    workspace = IPAWorkspace(ipa)
    try:
        with pytest.raises(IPAExtractionError):
            workspace.extract()
    finally:
        workspace.cleanup()


def test_merger_accepts_proxy_findings_without_metadata(tmp_path: Path):
    finding = Finding(
        finding_id="TEST-DAST-1",
        title="Proxy finding",
        severity=Severity.MEDIUM,
        cvss_score=5.0,
        masvs_category="MASVS-NETWORK-1",
        mastg_test_id="MASTG-TEST-0001",
        phase="DAST",
        location="https://example.test",
        evidence="Sensitive query parameter detected",
        remediation="Remove sensitive values from URLs",
    )
    report_path = tmp_path / "proxy.json"
    report_path.write_text(
        json.dumps({"findings": [finding.to_dict()]}),
        encoding="utf-8",
    )
    merged = merge_scan_reports([report_path])
    assert merged.app_name == "Unknown"
    assert len(merged.findings) == 1
    assert merged.findings[0].finding_id == "TEST-DAST-1"
