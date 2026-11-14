import json
from pathlib import Path
from typing import List, Set, Tuple

from tir_ios.core.models import Finding, ScanReport, Severity


def merge_scan_reports(report_paths: List[Path]) -> ScanReport:
    """Merges multiple TIRiOS JSON reports (e.g., SAST + DAST) and deduplicates identical findings."""
    if not report_paths:
        raise ValueError("At least one report JSON path is required.")

    base_data = json.loads(report_paths[0].read_text(encoding="utf-8"))
    meta = base_data.get("metadata", {})

    merged = ScanReport(
        app_name=meta.get("app_name", "Unknown"),
        bundle_id=meta.get("bundle_id", "Unknown"),
        bundle_version=meta.get("bundle_version", "Unknown"),
        min_os_version=meta.get("min_os_version", "Unknown"),
        architectures=meta.get("architectures", []),
    )

    seen: Set[Tuple[str, str, str]] = set()
    for path in report_paths:
        data = json.loads(path.read_text(encoding="utf-8"))
        metadata = data.get("metadata", {})
        if not merged.architectures and metadata.get("architectures"):
            merged.architectures = metadata["architectures"]

        for item in data.get("findings", []):
            fp = (item["finding_id"], item["location"], item["evidence"])
            if fp in seen:
                continue
            seen.add(fp)
            merged.add_finding(
                Finding(
                    finding_id=item["finding_id"],
                    title=item["title"],
                    severity=Severity(item["severity"]),
                    cvss_score=float(item["cvss_score"]),
                    masvs_category=item["masvs_category"],
                    mastg_test_id=item["mastg_test_id"],
                    phase=item["phase"],
                    location=item["location"],
                    evidence=item["evidence"],
                    remediation=item["remediation"],
                    confidence=item.get("confidence", "Unassessed"),
                    evidence_source=item.get("evidence_source", "Unspecified"),
                    verification_status=item.get("verification_status", "Not Verified"),
                )
            )

    return merged