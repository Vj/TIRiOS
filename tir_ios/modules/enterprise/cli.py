"""Click commands for enterprise assessment workflows."""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
import click

from tir_ios.modules.enterprise.platform import (
    AssessmentProfile, EvidenceRepository, compare_reports, meets_failure_threshold,
)


def _run_sast(ipa_path: Path, source_dir: Path | None):
    from tir_ios.core.ipa_extractor import IPAWorkspace
    from tir_ios.core.models import ScanReport
    from tir_ios.modules.sast.macho_inspector import MachOInspector
    from tir_ios.modules.sast.plist_auditor import PlistAuditor
    from tir_ios.modules.sast.secrets_scan import SecretsScanner
    from tir_ios.modules.sast.sast_expansion import SASTExpansion

    with IPAWorkspace(ipa_path) as workspace:
        assert workspace.app_dir and workspace.main_binary_path
        info = workspace.info_plist
        macho = MachOInspector(workspace.main_binary_path)
        report = ScanReport(
            app_name=info.get("CFBundleDisplayName") or info.get("CFBundleName", "Unknown"),
            bundle_id=info.get("CFBundleIdentifier", "Unknown"),
            bundle_version=info.get("CFBundleShortVersionString", "Unknown"),
            min_os_version=info.get("MinimumOSVersion", "Unknown"),
            architectures=macho.get_architectures(),
        )
        scanners = (
            macho,
            PlistAuditor(workspace.app_dir, info, workspace.main_binary_path),
            SecretsScanner(workspace.app_dir, workspace.main_binary_path),
        )
        for scanner in scanners:
            for finding in scanner.run_all():
                report.add_finding(finding)
        # Always run bundle-level checks (privacy manifests and SDK inventory).
        # Source-specific checks naturally produce no source findings without --source-dir.
        for finding in SASTExpansion(workspace.app_dir, info, source_dir=source_dir).run_all():
            report.add_finding(finding)
        return report


def register_enterprise_commands(cli_group):
    @cli_group.command("assessment")
    @click.argument("ipa_path", type=click.Path(exists=True, dir_okay=False, path_type=Path))
    @click.option("--profile", "profile_path", type=click.Path(exists=True, dir_okay=False, path_type=Path), required=True)
    @click.option("--source-dir", type=click.Path(exists=True, file_okay=False, path_type=Path), default=None)
    @click.option("--bundle-id", default=None, help="Required by profiles that enable DAST.")
    @click.option("--executable", default=None, help="Target CFBundleExecutable name required for DAST.")
    @click.option("--udid", default=None, help="Target iOS device UDID.")
    @click.option("--proxy-port", type=click.IntRange(1, 65535), default=8080, show_default=True)
    @click.option("--mitmdump", "mitmdump_path", default=None)
    @click.option("--output-dir", type=click.Path(file_okay=False, path_type=Path), default=Path("tirios-assessment"), show_default=True)
    @click.option("--assessment-id", default=None)
    def assessment(ipa_path, profile_path, source_dir, bundle_id, executable, udid,
                   proxy_port, mitmdump_path, output_dir, assessment_id):
        """Run a profile-driven SAST/DAST assessment and publish reports/evidence."""
        try:
            profile = AssessmentProfile.load(profile_path)
        except (ValueError, OSError, json.JSONDecodeError) as exc:
            raise click.ClickException(f"Invalid assessment profile: {exc}") from exc
        if source_dir and not profile.source_scan_enabled:
            raise click.ClickException("The selected profile disables source-tree scanning.")
        if profile.dast_enabled and (not bundle_id or not executable):
            raise click.ClickException("This profile enables DAST; provide --bundle-id and --executable.")
        if not profile.sast_enabled and not profile.dast_enabled:
            raise click.ClickException("The profile must enable at least one assessment phase.")

        output_dir.mkdir(parents=True, exist_ok=True)
        reports = []
        if profile.sast_enabled:
            sast_report = _run_sast(ipa_path, source_dir)
            sast_path = output_dir / "sast.json"
            sast_path.write_text(sast_report.to_json(), encoding="utf-8")
            reports.append(sast_report)
        if profile.dast_enabled:
            from tir_ios.modules.dast.session_orchestrator import DASTSessionOrchestrator
            dast_path = output_dir / "dast-session.json"
            try:
                DASTSessionOrchestrator(
                    bundle_id=bundle_id, executable=executable, udid=udid,
                    output=dast_path, duration=profile.dast_duration,
                    proxy_port=proxy_port, mitmdump_path=mitmdump_path,
                ).run()
            except Exception as exc:
                raise click.ClickException(
                    f"DAST failed; any partial session evidence is at {dast_path}: {exc}"
                ) from exc
            from tir_ios.core.models import Finding, ScanReport, Severity
            payload = json.loads(dast_path.read_text(encoding="utf-8"))
            metadata = payload.get("metadata", {})
            dast_report = ScanReport(
                app_name=metadata.get("app_name", executable),
                bundle_id=metadata.get("bundle_id", bundle_id),
                bundle_version=metadata.get("bundle_version", "Dynamic"),
                min_os_version=metadata.get("min_os_version", "Unknown"),
            )
            for item in payload.get("findings", []):
                dast_report.add_finding(Finding(
                    finding_id=item["finding_id"], title=item["title"], severity=Severity(item["severity"]),
                    cvss_score=float(item["cvss_score"]), masvs_category=item["masvs_category"],
                    mastg_test_id=item["mastg_test_id"], phase=item["phase"], location=item["location"],
                    evidence=item["evidence"], remediation=item["remediation"],
                ))
            reports.append(dast_report)

        from tir_ios.core.models import ScanReport
        combined = reports[0]
        if len(reports) > 1:
            combined = ScanReport(
                app_name=reports[0].app_name, bundle_id=reports[0].bundle_id,
                bundle_version=reports[0].bundle_version, min_os_version=reports[0].min_os_version,
                architectures=reports[0].architectures,
            )
            seen = set()
            for report in reports:
                for finding in report.findings:
                    fingerprint = (finding.finding_id, finding.location, finding.evidence)
                    if fingerprint not in seen:
                        seen.add(fingerprint)
                        combined.add_finding(finding)

        assessment_path = output_dir / "assessment.json"
        assessment_path.write_text(combined.to_json(), encoding="utf-8")
        if profile.html_report or profile.pdf_report:
            from tir_ios.reporting.pdf_generator import PDFReportGenerator
            generator = PDFReportGenerator()
        if profile.html_report:
            generator.generate_html(combined, output_dir / "assessment.html")
        if profile.pdf_report:
            generator.generate_pdf(combined, output_dir / "assessment.pdf")

        aid = assessment_id or f"{combined.bundle_id}-{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}"
        if profile.evidence_enabled:
            repository = EvidenceRepository(output_dir / "evidence")
            for artifact in sorted(output_dir.glob("*")):
                if artifact.is_file() and artifact.suffix.lower() in {".json", ".html", ".pdf"}:
                    repository.add(artifact, assessment_id=aid)
            click.echo(f"[+] Evidence repository: {output_dir / 'evidence'}")
        click.echo(
            f"[+] Assessment {aid}: {len(combined.findings)} findings; "
            f"SAST={'on' if profile.sast_enabled else 'off'}, DAST={'on' if profile.dast_enabled else 'off'}."
        )
        click.echo(f"[+] Reports and evidence: {output_dir}")

    @cli_group.command("compare")
    @click.argument("baseline", type=click.Path(exists=True, dir_okay=False, path_type=Path))
    @click.argument("current", type=click.Path(exists=True, dir_okay=False, path_type=Path))
    @click.option("-o", "--output", type=click.Path(path_type=Path), default=None)
    def compare(baseline, current, output):
        """Compare runs: new, resolved, changed and persistent findings."""
        rendered = json.dumps(compare_reports(baseline, current), indent=2)
        if output:
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_text(rendered, encoding="utf-8")
            click.echo(f"[+] Comparison written to {output}")
        else:
            click.echo(rendered)

    @cli_group.group("evidence")
    def evidence():
        """Manage and verify local content-addressed evidence."""
    @evidence.command("add")
    @click.argument("artifact", type=click.Path(exists=True, dir_okay=False, path_type=Path))
    @click.option("--store", type=click.Path(file_okay=False, path_type=Path), required=True)
    @click.option("--assessment-id", required=True)
    def evidence_add(artifact, store, assessment_id):
        click.echo(json.dumps(EvidenceRepository(store).add(artifact, assessment_id=assessment_id), indent=2))
    @evidence.command("verify")
    @click.option("--store", type=click.Path(file_okay=False, path_type=Path), required=True)
    def evidence_verify(store):
        result = EvidenceRepository(store).verify()
        click.echo(json.dumps(result, indent=2))
        if not result["valid"]:
            raise click.ClickException("Evidence integrity verification failed")

    @cli_group.command("ci")
    @click.argument("report", type=click.Path(exists=True, dir_okay=False, path_type=Path))
    @click.option("--profile", "profile_path", type=click.Path(exists=True, dir_okay=False, path_type=Path), default=None,
                  help="Use the fail_on threshold from an assessment profile.")
    @click.option("--fail-on", type=click.Choice(list(SEVERITY_RANK_NAMES)), default=None,
                  help="Override the profile threshold (defaults to High without --profile).")
    def ci(report, profile_path, fail_on):
        """Return non-zero when findings meet or exceed the selected severity threshold."""
        if profile_path:
            try:
                threshold = AssessmentProfile.load(profile_path).fail_on
            except (ValueError, OSError, json.JSONDecodeError) as exc:
                raise click.ClickException(f"Invalid assessment profile: {exc}") from exc
        else:
            threshold = "High"
        threshold = fail_on or threshold
        passed, blockers = meets_failure_threshold(report, threshold)
        click.echo(f"{'PASS' if passed else 'FAIL'}: {len(blockers)} findings at or above {threshold}")
        if not passed:
            raise click.exceptions.Exit(1)


    @cli_group.group("profiles")
    def profiles():
        """Discover bundled enterprise assessment profiles."""
    @profiles.command("list")
    def profiles_list():
        root = Path(__file__).resolve().parents[2] / "profiles"
        if not root.exists():
            root = Path(__file__).resolve().parents[2] / "tir_ios" / "profiles"
        for path in sorted(root.glob("*.json")):
            try:
                profile = AssessmentProfile.load(path)
                click.echo(f"{path.stem}: {profile.description or profile.name}")
            except (ValueError, OSError, json.JSONDecodeError) as exc:
                click.echo(f"{path.name}: invalid ({exc})", err=True)


SEVERITY_RANK_NAMES = ("Critical", "High", "Medium", "Low", "Info")
