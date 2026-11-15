"""Click commands for enterprise assessment workflows."""
from __future__ import annotations
import json
from pathlib import Path
import click
from tir_ios.modules.enterprise.platform import AssessmentProfile, EvidenceRepository, compare_reports, meets_failure_threshold

def _run_sast(ipa_path: Path, source_dir: Path | None):
    from tir_ios.core.ipa_extractor import IPAWorkspace
    from tir_ios.core.models import ScanReport
    from tir_ios.modules.sast.macho_inspector import MachOInspector
    from tir_ios.modules.sast.plist_auditor import PlistAuditor
    from tir_ios.modules.sast.secrets_scan import SecretsScanner
    from tir_ios.modules.sast.sast_expansion import SASTExpansion
    with IPAWorkspace(ipa_path) as ws:
        assert ws.app_dir and ws.main_binary_path
        info=ws.info_plist; macho=MachOInspector(ws.main_binary_path)
        report=ScanReport(app_name=info.get("CFBundleDisplayName") or info.get("CFBundleName","Unknown"),
            bundle_id=info.get("CFBundleIdentifier","Unknown"),bundle_version=info.get("CFBundleShortVersionString","Unknown"),
            min_os_version=info.get("MinimumOSVersion","Unknown"),architectures=macho.get_architectures())
        for scanner in (macho,PlistAuditor(ws.app_dir,info,ws.main_binary_path),SecretsScanner(ws.app_dir,ws.main_binary_path)):
            for finding in scanner.run_all(): report.add_finding(finding)
        if source_dir:
            for finding in SASTExpansion(ws.app_dir,info,source_dir=source_dir).run_all(): report.add_finding(finding)
        return report

def register_enterprise_commands(cli):
    @cli.command("assessment")
    @click.argument("ipa_path",type=click.Path(exists=True,dir_okay=False,path_type=Path))
    @click.option("--profile","profile_path",type=click.Path(exists=True,dir_okay=False,path_type=Path),required=True)
    @click.option("--source-dir",type=click.Path(exists=True,file_okay=False,path_type=Path),default=None)
    @click.option("--output-dir",type=click.Path(file_okay=False,path_type=Path),default=Path("tirios-assessment"),show_default=True)
    @click.option("--assessment-id",default=None)
    def assessment(ipa_path,profile_path,source_dir,output_dir,assessment_id):
        """Run a profile-driven assessment and publish JSON/HTML/PDF evidence."""
        from tir_ios.reporting.pdf_generator import PDFReportGenerator
        profile=AssessmentProfile.load(profile_path)
        if not profile.sast_enabled: raise click.ClickException("SAST must be enabled; DAST-only runs use dast-session.")
        if source_dir and not profile.source_scan_enabled: raise click.ClickException("Profile disables source-tree scanning.")
        if profile.dast_enabled:
            raise click.ClickException("Profile requires DAST. Run tir-ios dast-session on the authorized device, then merge its JSON with the SAST report. DAST is never silently skipped.")
        output_dir.mkdir(parents=True,exist_ok=True); report=_run_sast(ipa_path,source_dir)
        report_path=output_dir/"assessment.json"; report_path.write_text(report.to_json(),encoding="utf-8")
        generator=PDFReportGenerator()
        if profile.html_report: generator.generate_html(report,output_dir/"assessment.html")
        if profile.pdf_report: generator.generate_pdf(report,output_dir/"assessment.pdf")
        if profile.evidence_enabled:
            store=EvidenceRepository(output_dir/"evidence"); aid=assessment_id or report.bundle_id
            for path in sorted(output_dir.glob("assessment.*")): store.add(path,assessment_id=aid)
            click.echo(f"[+] Evidence stored: {output_dir/'evidence'}")
        click.echo(f"[+] Assessment complete: {len(report.findings)} findings; output: {output_dir}")

    @cli.command("compare")
    @click.argument("baseline",type=click.Path(exists=True,dir_okay=False,path_type=Path))
    @click.argument("current",type=click.Path(exists=True,dir_okay=False,path_type=Path))
    @click.option("-o","--output",type=click.Path(path_type=Path),default=None)
    def compare(baseline,current,output):
        """Compare assessments and classify new, resolved and persistent findings."""
        rendered=json.dumps(compare_reports(baseline,current),indent=2)
        if output: output.parent.mkdir(parents=True,exist_ok=True); output.write_text(rendered,encoding="utf-8"); click.echo(f"[+] Comparison written to {output}")
        else: click.echo(rendered)

    @cli.group("evidence")
    def evidence(): """Manage and verify local content-addressed evidence."""
    @evidence.command("add")
    @click.argument("artifact",type=click.Path(exists=True,dir_okay=False,path_type=Path))
    @click.option("--store",type=click.Path(file_okay=False,path_type=Path),required=True)
    @click.option("--assessment-id",required=True)
    def evidence_add(artifact,store,assessment_id): click.echo(json.dumps(EvidenceRepository(store).add(artifact,assessment_id=assessment_id),indent=2))
    @evidence.command("verify")
    @click.option("--store",type=click.Path(file_okay=False,path_type=Path),required=True)
    def evidence_verify(store):
        result=EvidenceRepository(store).verify(); click.echo(json.dumps(result,indent=2))
        if not result["valid"]: raise click.ClickException("Evidence integrity verification failed")

    @cli.command("ci")
    @click.argument("report",type=click.Path(exists=True,dir_okay=False,path_type=Path))
    @click.option("--fail-on",type=click.Choice(["Critical","High","Medium","Low","Info"]),default="High",show_default=True)
    def ci(report,fail_on):
        """Apply a severity gate to an assessment JSON report."""
        passed,blocking=meets_failure_threshold(report,fail_on); click.echo(f"{'PASS' if passed else 'FAIL'}: {len(blocking)} findings at or above {fail_on}")
        if not passed: raise click.exceptions.Exit(1)

    @cli.group("profiles")
    def profiles(): """List bundled assessment profiles."""
    @profiles.command("list")
    def profiles_list():
        root=Path(__file__).resolve().parents[2]/"profiles"
        for path in sorted(root.glob("*.json")):
            try:
                profile=AssessmentProfile.load(path); click.echo(f"{path.stem}: {profile.description or profile.name}")
            except (ValueError,OSError) as exc: click.echo(f"{path.name}: invalid ({exc})",err=True)
