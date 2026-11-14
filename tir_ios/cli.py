from pathlib import Path
import sys
import time
import click

from tir_ios.core.ipa_extractor import IPAExtractionError, IPAWorkspace
from tir_ios.core.models import ScanReport
from tir_ios.modules.sast.macho_inspector import MachOInspector
from tir_ios.modules.sast.plist_auditor import PlistAuditor
from tir_ios.modules.sast.secrets_scan import SecretsScanner
from tir_ios.reporting.merger import merge_scan_reports


@click.group()
def cli() -> None:
    """TIRiOS - Threat Inspection & Response for iOS VAPT."""


@cli.command("scan")
@click.argument("ipa_path", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option("-o", "--output", type=click.Path(path_type=Path), default=None, help="Output JSON report path.")
@click.option("--html", "html_output", type=click.Path(path_type=Path), default=None, help="Output HTML report path.")
@click.option("--pdf", "pdf_output", type=click.Path(path_type=Path), default=None, help="Output PDF report path.")
def scan_ipa(ipa_path: Path, output: Path | None, html_output: Path | None, pdf_output: Path | None) -> None:
    """Run static security checks (SAST) against an iOS .ipa package."""
    try:
        with IPAWorkspace(ipa_path) as ws:
            assert ws.app_dir and ws.main_binary_path
            info = ws.info_plist

            macho = MachOInspector(ws.main_binary_path)
            plist_auditor = PlistAuditor(ws.app_dir, info, ws.main_binary_path)
            secrets_scanner = SecretsScanner(ws.app_dir, ws.main_binary_path)

            report = ScanReport(
                app_name=info.get("CFBundleDisplayName") or info.get("CFBundleName", "Unknown"),
                bundle_id=info.get("CFBundleIdentifier", "Unknown"),
                bundle_version=info.get("CFBundleShortVersionString", "Unknown"),
                min_os_version=info.get("MinimumOSVersion", "Unknown"),
                architectures=macho.get_architectures(),
            )

            for finding in macho.run_all():
                report.add_finding(finding)
            for finding in plist_auditor.run_all():
                report.add_finding(finding)
            for finding in secrets_scanner.run_all():
                report.add_finding(finding)

            if output:
                output.write_text(report.to_json(), encoding="utf-8")
                click.echo(f"[+] JSON report written to {output} ({len(report.findings)} findings)")
            if html_output:
                from tir_ios.reporting.pdf_generator import PDFReportGenerator
                PDFReportGenerator().generate_html(report, html_output)
                click.echo(f"[+] HTML report written to {html_output} ({len(report.findings)} findings)")
            if pdf_output:
                from tir_ios.reporting.pdf_generator import PDFReportGenerator
                PDFReportGenerator().generate_pdf(report, pdf_output)
                click.echo(f"[+] PDF report written to {pdf_output} ({len(report.findings)} findings)")
            if not output and not html_output and not pdf_output:
                click.echo(report.to_json())

    except (IPAExtractionError, ValueError, FileNotFoundError) as exc:
        click.echo(f"[!] Scan failed: {exc}", err=True)
        sys.exit(1)


@cli.command("dast")
@click.argument("bundle_id", type=str)
@click.option("--executable", required=True, help="CFBundleExecutable name for syslog filtering.")
@click.option("--duration", default=60, show_default=True, help="Monitoring window in seconds.")
@click.option("--udid", default=None, help="Target iOS device UDID (defaults to first USB device).")
@click.option("-o", "--output", type=click.Path(path_type=Path), default=None, help="Output DAST JSON report path.")
def run_dast(
    bundle_id: str,
    executable: str,
    duration: int,
    udid: str | None,
    output: Path | None,
) -> None:
    """Run live DAST instrumentation (sandbox diff + syslog leak monitor + Frida runtime checks)."""
    try:
        from tir_ios.core.device_bridge import DeviceConnectionError, IOSDeviceBridge
        from tir_ios.modules.dast.frida_runner import FridaRuntimeAuditor
        from tir_ios.modules.dast.resilience_auditor import ResilienceRuntimeAuditor
        from tir_ios.modules.dast.storage_monitor import SandboxStorageMonitor
        from tir_ios.modules.dast.syslog_monitor import SyslogLeakMonitor

        bridge = IOSDeviceBridge(udid=udid)
        summary = bridge.device_summary()
        click.echo(f"[+] Connected to {summary}")

        with SandboxStorageMonitor(bridge, bundle_id=bundle_id) as storage_mon:
            click.echo("[*] Capturing pre-session sandbox baseline...")
            baseline = storage_mon.capture_baseline()
            click.echo(f"[+] Baseline indexed {len(baseline)} sandbox files.")

            syslog_mon = SyslogLeakMonitor(bridge, executable_name=executable)
            frida_auditor = FridaRuntimeAuditor(bundle_id=bundle_id, udid=bridge.udid)
            resilience_auditor = ResilienceRuntimeAuditor(bundle_id=bundle_id, udid=bridge.udid)

            started_components = []
            findings_by_component = {}
            cleanup_errors = []
            try:
                started_components.append(("syslog", syslog_mon))
                syslog_mon.start()
                started_components.append(("frida", frida_auditor))
                frida_auditor.start(spawn=True)
                started_components.append(("resilience", resilience_auditor))
                resilience_auditor.start(spawn=False)
                click.echo(f"[*] Monitoring {bundle_id} for {duration}s. Exercise app flows on device...")
                time.sleep(duration)
            finally:
                # Stop every successfully started component, even if a later
                # component fails during startup or the monitoring window errors.
                for component_name, component in reversed(started_components):
                    try:
                        findings_by_component[component_name] = component.stop()
                    except Exception as cleanup_exc:
                        cleanup_errors.append(f"{component_name}: {cleanup_exc}")
                        click.echo(f"[!] DAST cleanup failed for {component_name}: {cleanup_exc}", err=True)

                if cleanup_errors and sys.exc_info()[0] is None:
                    raise RuntimeError("One or more DAST components failed to stop: " + "; ".join(cleanup_errors))

            live_findings = (
                findings_by_component.get("syslog", [])
                + findings_by_component.get("frida", [])
                + findings_by_component.get("resilience", [])
            )
            click.echo("[*] Analyzing post-session sandbox storage and backup attributes...")
            storage_findings = storage_mon.analyze_post_session()

        report = ScanReport(
            app_name=executable,
            bundle_id=bundle_id,
            bundle_version="Dynamic",
            min_os_version=str(summary.get("ios_version", "Unknown")),
        )
        for f in live_findings + storage_findings:
            report.add_finding(f)

        if output:
            output.write_text(report.to_json(), encoding="utf-8")
            click.echo(f"[+] DAST JSON report written to {output} ({len(report.findings)} findings)")
        else:
            click.echo(report.to_json())

    except Exception as exc:
        click.echo(f"[!] DAST session failed: {exc}", err=True)
        sys.exit(1)


@cli.command("merge")
@click.argument("report_files", nargs=-1, required=True, type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option("-o", "--output", type=click.Path(path_type=Path), default=None, help="Merged JSON output path.")
@click.option("--pdf", "pdf_output", type=click.Path(path_type=Path), default=None, help="Merged PDF report path.")
def merge_reports_cmd(report_files: tuple[Path, ...], output: Path | None, pdf_output: Path | None) -> None:
    """Merge SAST and DAST JSON reports into a single deduplicated VAPT report."""
    merged = merge_scan_reports(list(report_files))
    if output:
        output.write_text(merged.to_json(), encoding="utf-8")
        click.echo(f"[+] Merged JSON written to {output} ({len(merged.findings)} unique findings)")
    if pdf_output:
        from tir_ios.reporting.pdf_generator import PDFReportGenerator
        PDFReportGenerator().generate_pdf(merged, pdf_output)
        click.echo(f"[+] Combined PDF report written to {pdf_output}")
    if not output and not pdf_output:
        click.echo(merged.to_json())


if __name__ == "__main__":
    cli()