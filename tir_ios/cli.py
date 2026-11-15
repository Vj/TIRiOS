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

            syslog_mon.start()
            frida_auditor.start(spawn=True)
            resilience_auditor.start(spawn=False)
            click.echo(f"[*] Monitoring {bundle_id} for {duration}s. Exercise app flows on device...")

            time.sleep(duration)

            live_findings = syslog_mon.stop() + frida_auditor.stop() + resilience_auditor.stop()
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



@cli.command("dast-session")
@click.argument("bundle_id", type=str)
@click.option("--executable", required=True, help="CFBundleExecutable name for syslog filtering.")
@click.option("--duration", default=60, show_default=True, help="Monitoring window in seconds.")
@click.option("--udid", default=None, help="Target iOS device UDID (defaults to first USB device).")
@click.option("--proxy-listen-host", default="0.0.0.0", show_default=True, help="Host/interface for mitmproxy to listen on.")
@click.option("--proxy-port", default=8080, show_default=True, type=click.IntRange(1, 65535), help="mitmproxy listen port.")
@click.option("--mitmdump", "mitmdump_path", default=None, help="Explicit path to the mitmdump executable.")
@click.option("-o", "--output", type=click.Path(path_type=Path), default=Path("tirios_dast_session.json"), show_default=True, help="Consolidated session JSON report.")
def run_dast_session(
    bundle_id: str,
    executable: str,
    duration: int,
    udid: str | None,
    proxy_listen_host: str,
    proxy_port: int,
    mitmdump_path: str | None,
    output: Path,
) -> None:
    """Run coordinated Frida, syslog, sandbox, resilience and proxy DAST collection."""
    try:
        from tir_ios.modules.dast.session_orchestrator import DASTSessionOrchestrator
        click.echo("[*] Starting unified DAST session. Ensure the iPhone HTTP proxy points to this host.")
        orchestrator = DASTSessionOrchestrator(
            bundle_id=bundle_id,
            executable=executable,
            udid=udid,
            output=output,
            duration=duration,
            proxy_host=proxy_listen_host,
            proxy_port=proxy_port,
            mitmdump_path=mitmdump_path,
        )
        payload = orchestrator.run()
        click.echo(
            f"[+] Session complete: {len(payload['findings'])} findings, "
            f"{len(payload['proxy_observations'])} TLS observations. Report: {output}"
        )
    except Exception as exc:
        click.echo(f"[!] Unified DAST session failed: {exc}", err=True)
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