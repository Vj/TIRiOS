import json
import pytest
from tir_ios.modules.enterprise.platform import AssessmentProfile, EvidenceRepository, compare_reports, meets_failure_threshold

def test_profile_validation(tmp_path):
    p=tmp_path/"p.json"; p.write_text(json.dumps({"name":"x","fail_on":"High"}),encoding="utf-8")
    assert AssessmentProfile.load(p).name=="x"
    p.write_text(json.dumps({"name":"x","extra":1}),encoding="utf-8")
    with pytest.raises(ValueError,match="Unknown profile"): AssessmentProfile.load(p)

def test_evidence_store_integrity_and_deduplication(tmp_path):
    artifact=tmp_path/"r.json"; artifact.write_text('{"findings":[]}',encoding="utf-8")
    store=EvidenceRepository(tmp_path/"store"); first=store.add(artifact,assessment_id="ENG-1"); second=store.add(artifact,assessment_id="ENG-1")
    assert first["sha256"]==second["sha256"] and store.verify()["valid"]
    (store.root/first["object"]).write_text("tampered",encoding="utf-8")
    assert store.verify()["valid"] is False

def test_report_comparison(tmp_path):
    a={"findings":[{"finding_id":"A","location":"a","evidence":"1"},{"finding_id":"B","location":"b","evidence":"2"}]}
    b={"findings":[{"finding_id":"A","location":"a","evidence":"1"},{"finding_id":"C","location":"c","evidence":"3"}]}
    old,new=tmp_path/"old.json",tmp_path/"new.json"; old.write_text(json.dumps(a)); new.write_text(json.dumps(b))
    assert compare_reports(old,new)["summary"]=={"baseline":2,"current":2,"new":1,"resolved":1,"persistent":1}

def test_ci_gate_threshold_is_inclusive(tmp_path):
    p=tmp_path/"r.json"; p.write_text(json.dumps({"findings":[{"severity":"High"},{"severity":"Info"}]}))
    passed,blocking=meets_failure_threshold(p,"High")
    assert not passed and len(blocking)==1
