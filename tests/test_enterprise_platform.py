import json

import pytest

from tir_ios.modules.enterprise.platform import (
    AssessmentProfile, EvidenceRepository, compare_reports, meets_failure_threshold,
)


def test_profile_validation(tmp_path):
    path = tmp_path / "profile.json"
    path.write_text(json.dumps({"name": "enterprise", "fail_on": "High"}), encoding="utf-8")
    assert AssessmentProfile.load(path).name == "enterprise"
    path.write_text(json.dumps({"name": "enterprise", "extra": True}), encoding="utf-8")
    with pytest.raises(ValueError, match="Unknown profile"):
        AssessmentProfile.load(path)
    path.write_text(json.dumps({"name": "enterprise", "sast_enabled": "yes"}), encoding="utf-8")
    with pytest.raises(ValueError, match="sast_enabled"):
        AssessmentProfile.load(path)


def test_evidence_store_uses_jsonl_and_verifies_integrity(tmp_path):
    artifact = tmp_path / "report.json"
    artifact.write_text('{"findings":[]}', encoding="utf-8")
    store = EvidenceRepository(tmp_path / "store")
    first = store.add(artifact, assessment_id="ENG-1")
    second = store.add(artifact, assessment_id="ENG-1")
    assert first["sha256"] == second["sha256"]
    lines = store.manifest.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 2
    assert all(json.loads(line)["assessment_id"] == "ENG-1" for line in lines)
    assert store.verify() == {"valid": True, "checked": 2, "errors": []}
    (store.root / first["object"]).write_text("tampered", encoding="utf-8")
    assert store.verify()["valid"] is False


def test_report_comparison_classifies_changed_findings(tmp_path):
    baseline = {"findings": [
        {"finding_id": "A", "location": "a", "evidence": "old", "severity": "Low"},
        {"finding_id": "B", "location": "b", "evidence": "same", "severity": "High"},
    ]}
    current = {"findings": [
        {"finding_id": "A", "location": "a", "evidence": "updated", "severity": "High"},
        {"finding_id": "C", "location": "c", "evidence": "new", "severity": "Medium"},
    ]}
    old_path, new_path = tmp_path / "old.json", tmp_path / "new.json"
    old_path.write_text(json.dumps(baseline), encoding="utf-8")
    new_path.write_text(json.dumps(current), encoding="utf-8")
    result = compare_reports(old_path, new_path)
    assert result["summary"] == {
        "baseline": 2, "current": 2, "new": 1, "resolved": 1, "persistent": 0, "changed": 1,
    }
    assert result["changed_findings"][0]["baseline"]["severity"] == "Low"
    assert result["changed_findings"][0]["current"]["severity"] == "High"


def test_ci_gate_threshold_is_inclusive(tmp_path):
    report = tmp_path / "report.json"
    report.write_text(json.dumps({"findings": [{"severity": "High"}, {"severity": "Info"}]}), encoding="utf-8")
    passed, blockers = meets_failure_threshold(report, "High")
    assert not passed
    assert len(blockers) == 1
