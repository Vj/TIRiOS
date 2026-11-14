import json
from pathlib import Path
from typing import Dict, Any, Optional

from tir_ios.core.models import Finding, Severity


class RuleRegistry:
    _instance: Optional["RuleRegistry"] = None

    def __init__(self, registry_path: Optional[Path] = None):
        path = registry_path or (Path(__file__).resolve().parent.parent / "rules" / "masvs_registry.json")
        data = json.loads(path.read_text(encoding="utf-8"))
        self.metadata: Dict[str, Any] = data.get("standards", {})
        self.rules: Dict[str, Dict[str, Any]] = data.get("rules", {})

    @classmethod
    def default(cls) -> "RuleRegistry":
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    def build_finding(
        self,
        rule_id: str,
        location: str,
        evidence: str,
        title_suffix: str = "",
        severity_override: Optional[Severity] = None,
        cvss_override: Optional[float] = None,
    ) -> Finding:
        if rule_id not in self.rules:
            raise KeyError(f"Unknown TIRiOS rule ID: {rule_id}")

        rule = self.rules[rule_id]
        title = f"{rule['title']} {title_suffix}".strip()
        severity = severity_override or Severity(rule["severity"])
        cvss = float(cvss_override) if cvss_override is not None else float(rule["cvss_score"])

        return Finding(
            finding_id=rule["rule_id"],
            title=title,
            severity=severity,
            cvss_score=float(rule["cvss_score"]),
            masvs_category=rule["masvs_category"],
            mastg_test_id=rule["mastg_test_id"],
            phase=rule["phase"],
            location=location,
            evidence=evidence,
            remediation=rule["remediation"],
        )
