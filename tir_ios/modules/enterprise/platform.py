"""Enterprise assessment profiles, evidence storage and report comparison."""
from __future__ import annotations
from dataclasses import dataclass, field
from datetime import datetime, timezone
import hashlib, json, shutil
from pathlib import Path
from typing import Any
from tir_ios.core.models import Severity

SEVERITY_RANK = {s.value: i for i, s in enumerate((Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO))}

@dataclass
class AssessmentProfile:
    name: str
    description: str = ""
    sast_enabled: bool = True
    dast_enabled: bool = False
    html_report: bool = True
    pdf_report: bool = True
    evidence_enabled: bool = True
    fail_on: str = "High"
    source_scan_enabled: bool = True
    dast_duration: int = 180
    settings: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def load(cls, path: Path) -> "AssessmentProfile":
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        if not isinstance(data, dict): raise ValueError("Assessment profile must be a JSON object")
        allowed = set(cls.__dataclass_fields__)
        unknown = set(data) - allowed
        if unknown: raise ValueError(f"Unknown profile keys: {', '.join(sorted(unknown))}")
        profile = cls(**data)
        if profile.fail_on not in SEVERITY_RANK: raise ValueError(f"fail_on must be one of: {', '.join(SEVERITY_RANK)}")
        if profile.dast_duration <= 0: raise ValueError("dast_duration must be greater than zero")
        return profile

class EvidenceRepository:
    """Local SHA-256 addressed evidence store with a verifiable JSON manifest."""
    def __init__(self, root: Path):
        self.root = Path(root); self.objects = self.root / "objects"; self.manifest = self.root / "manifest.jsonl"
        self.objects.mkdir(parents=True, exist_ok=True)

    def add(self, artifact: Path, *, assessment_id: str, kind: str | None = None) -> dict[str, Any]:
        source = Path(artifact)
        if not source.is_file(): raise FileNotFoundError(source)
        raw = source.read_bytes(); digest = hashlib.sha256(raw).hexdigest()
        target = self.objects / digest[:2] / digest; target.parent.mkdir(parents=True, exist_ok=True)
        if not target.exists(): shutil.copyfile(source, target)
        record = {"schema_version":"1.0","assessment_id":assessment_id,"kind":kind or source.suffix.lstrip(".") or "file",
                  "name":source.name,"sha256":digest,"size_bytes":len(raw),"stored_at":datetime.now(timezone.utc).isoformat(),
                  "object":str(target.relative_to(self.root))}
        with self.manifest.open("a",encoding="utf-8") as stream: stream.write(json.dumps(record,sort_keys=True)+"\\n")
        return record

    def verify(self) -> dict[str, Any]:
        checked, errors = 0, []
        if not self.manifest.exists(): return {"valid":True,"checked":0,"errors":[]}
        for number,line in enumerate(self.manifest.read_text(encoding="utf-8").splitlines(),1):
            if not line.strip(): continue
            try:
                record=json.loads(line); rel=Path(record["object"])
                if rel.is_absolute() or ".." in rel.parts: raise ValueError("unsafe object path")
                digest=hashlib.sha256((self.root/rel).read_bytes()).hexdigest()
                if digest != record["sha256"]: raise ValueError("SHA-256 mismatch")
                checked += 1
            except Exception as exc: errors.append({"line":number,"error":str(exc)})
        return {"valid":not errors,"checked":checked,"errors":errors}

def _fingerprint(item): return (str(item.get("finding_id","")),str(item.get("location","")),str(item.get("evidence","")))

def compare_reports(baseline_path: Path, current_path: Path) -> dict[str, Any]:
    old_data=json.loads(Path(baseline_path).read_text(encoding="utf-8")); new_data=json.loads(Path(current_path).read_text(encoding="utf-8"))
    old={_fingerprint(x):x for x in old_data.get("findings",[])}; new={_fingerprint(x):x for x in new_data.get("findings",[])}
    added=[new[k] for k in sorted(new.keys()-old.keys())]; resolved=[old[k] for k in sorted(old.keys()-new.keys())]
    persistent=[new[k] for k in sorted(new.keys()&old.keys())]
    return {"schema_version":"1.0","baseline":str(baseline_path),"current":str(current_path),
            "summary":{"baseline":len(old),"current":len(new),"new":len(added),"resolved":len(resolved),"persistent":len(persistent)},
            "new_findings":added,"resolved_findings":resolved,"persistent_findings":persistent}

def meets_failure_threshold(report_path: Path, fail_on: str="High"):
    if fail_on not in SEVERITY_RANK: raise ValueError(f"Unknown severity threshold: {fail_on}")
    data=json.loads(Path(report_path).read_text(encoding="utf-8"))
    blockers=[f for f in data.get("findings",[]) if SEVERITY_RANK.get(f.get("severity"),99)<=SEVERITY_RANK[fail_on]]
    return not blockers, blockers
