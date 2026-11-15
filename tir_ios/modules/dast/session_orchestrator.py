"""Coordinate a complete, evidence-preserving iOS DAST session."""
from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import tempfile
import threading
import time
from typing import Any

from tir_ios.core.device_bridge import IOSDeviceBridge
from tir_ios.core.models import ScanReport


class DASTSessionError(RuntimeError):
    """Raised when a unified DAST session cannot be initialized."""


class DASTSessionOrchestrator:
    """Run existing DAST collectors and mitmproxy as one managed session.

    The iPhone's Wi-Fi HTTP proxy must point to the host running TIRiOS. This
    class deliberately does not alter device network settings.
    """

    def __init__(
        self,
        bundle_id: str,
        executable: str,
        *,
        udid: str | None = None,
        output: Path | None = None,
        duration: int = 60,
        proxy_host: str = "0.0.0.0",
        proxy_port: int = 8080,
        mitmdump_path: str | None = None,
        bridge: Any | None = None,
        frida_auditor_factory: Any | None = None,
        resilience_auditor_factory: Any | None = None,
        syslog_monitor_factory: Any | None = None,
        storage_monitor_factory: Any | None = None,
    ):
        if duration <= 0:
            raise ValueError("duration must be greater than zero")
        if not 1 <= proxy_port <= 65535:
            raise ValueError("proxy_port must be between 1 and 65535")
        self.bundle_id = bundle_id
        self.executable = executable
        self.udid = udid
        self.output = Path(output or "tirios_dast_session.json")
        self.duration = int(duration)
        self.proxy_host = proxy_host
        self.proxy_port = int(proxy_port)
        self.mitmdump_path = mitmdump_path
        self._bridge = bridge
        self._factories = (
            frida_auditor_factory,
            resilience_auditor_factory,
            syslog_monitor_factory,
            storage_monitor_factory,
        )

    def run(self) -> dict:
        from tir_ios.modules.dast.frida_runner import FridaRuntimeAuditor
        from tir_ios.modules.dast.resilience_auditor import ResilienceRuntimeAuditor
        from tir_ios.modules.dast.storage_monitor import SandboxStorageMonitor
        from tir_ios.modules.dast.syslog_monitor import SyslogLeakMonitor

        frida_factory, resilience_factory, syslog_factory, storage_factory = self._factories
        bridge = self._bridge or IOSDeviceBridge(udid=self.udid)
        summary = bridge.device_summary()
        frida_factory = frida_factory or FridaRuntimeAuditor
        resilience_factory = resilience_factory or ResilienceRuntimeAuditor
        syslog_factory = syslog_factory or SyslogLeakMonitor
        storage_factory = storage_factory or SandboxStorageMonitor

        self.output.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="tirios_dast_session_") as temp:
            work = Path(temp)
            events_path = work / "runtime_events.json"
            proxy_path = work / "proxy_evidence.json"
            addon_path = Path(__file__).with_name("mitm_addon.py")
            mitmdump = self.mitmdump_path or shutil.which("mitmdump")
            if not mitmdump:
                raise DASTSessionError(
                    "mitmdump was not found. Install the optional DAST dependencies "
                    "and ensure the mitmproxy executable is on PATH."
                )

            storage = storage_factory(bridge, bundle_id=self.bundle_id)
            syslog = syslog_factory(bridge, executable_name=self.executable)
            frida = frida_factory(bundle_id=self.bundle_id, udid=bridge.udid)
            resilience = resilience_factory(bundle_id=self.bundle_id, udid=bridge.udid)
            proxy = None
            writer_stop = threading.Event()
            writer_thread = None
            started = {"storage": False, "syslog": False, "frida": False, "resilience": False}
            findings = []
            session_error = None

            try:
                storage.__enter__()
                started["storage"] = True
                baseline = storage.capture_baseline()

                env = os.environ.copy()
                env["TIRIOS_RUNTIME_EVENTS"] = str(events_path)
                env["TIRIOS_PROXY_OUTPUT"] = str(proxy_path)
                command = [
                    mitmdump, "--quiet", "--listen-host", self.proxy_host,
                    "--listen-port", str(self.proxy_port), "-s", str(addon_path),
                ]
                proxy = subprocess.Popen(
                    command, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
                )
                self._wait_for_proxy(proxy)

                def publish_events():
                    while not writer_stop.is_set():
                        snapshot = [event.to_dict() for event in frida.network_events]
                        temporary = events_path.with_suffix(".tmp")
                        temporary.write_text(json.dumps(snapshot), encoding="utf-8")
                        temporary.replace(events_path)
                        writer_stop.wait(0.25)

                writer_thread = threading.Thread(target=publish_events, daemon=True)
                writer_thread.start()

                syslog.start()
                started["syslog"] = True
                frida.start(spawn=True)
                started["frida"] = True
                resilience.start(spawn=False)
                started["resilience"] = True

                deadline = time.monotonic() + self.duration
                while time.monotonic() < deadline:
                    if proxy.poll() is not None:
                        raise DASTSessionError(
                            f"mitmdump exited during capture with code {proxy.returncode}"
                        )
                    time.sleep(min(0.25, max(0.0, deadline - time.monotonic())))
            except Exception as exc:
                session_error = str(exc)
            finally:
                # Stop data producers before the proxy, so its final snapshot is complete.
                for name, collector in (
                    ("syslog", syslog), ("frida", frida), ("resilience", resilience)
                ):
                    if started[name]:
                        try:
                            findings.extend(collector.stop())
                        except Exception as exc:
                            session_error = session_error or f"{name} shutdown failed: {exc}"

                writer_stop.set()
                if writer_thread:
                    writer_thread.join(timeout=2)
                if started["frida"]:
                    snapshot = [event.to_dict() for event in frida.network_events]
                    events_path.write_text(json.dumps(snapshot), encoding="utf-8")

                if proxy and proxy.poll() is None:
                    proxy.terminate()
                    try:
                        proxy.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        proxy.kill()
                        proxy.wait(timeout=5)

                if started["storage"]:
                    try:
                        findings.extend(storage.analyze_post_session())
                    except Exception as exc:
                        session_error = session_error or f"sandbox analysis failed: {exc}"
                    finally:
                        storage.__exit__(None, None, None)

            proxy_data = {"findings": [], "observations": [], "schema_version": "1.1.0"}
            if proxy_path.exists():
                try:
                    proxy_data = json.loads(proxy_path.read_text(encoding="utf-8"))
                    from tir_ios.core.models import Finding, Severity
                    for item in proxy_data.get("findings", []):
                        findings.append(Finding(
                            finding_id=item["finding_id"], title=item["title"],
                            severity=Severity(item["severity"]), cvss_score=float(item["cvss_score"]),
                            masvs_category=item["masvs_category"], mastg_test_id=item["mastg_test_id"],
                            phase=item["phase"], location=item["location"], evidence=item["evidence"],
                            remediation=item["remediation"],
                        ))
                except (OSError, ValueError, KeyError, TypeError) as exc:
                    session_error = session_error or f"proxy evidence could not be read: {exc}"

            report = ScanReport(
                app_name=self.executable,
                bundle_id=self.bundle_id,
                bundle_version="Dynamic",
                min_os_version=str(summary.get("ios_version", "Unknown")),
            )
            for finding in findings:
                report.add_finding(finding)

            payload = {
                "schema_version": "1.0.0",
                "metadata": {
                    "app_name": report.app_name,
                    "bundle_id": report.bundle_id,
                    "bundle_version": report.bundle_version,
                    "min_os_version": report.min_os_version,
                    "device": summary,
                    "duration_seconds": self.duration,
                    "proxy": {"listen_host": self.proxy_host, "listen_port": self.proxy_port},
                    "sandbox_baseline_files": len(baseline) if "baseline" in locals() else 0,
                    "runtime_network_events": len(frida.network_events),
                    "session_error": session_error,
                },
                "findings": [finding.to_dict() for finding in report.findings],
                "proxy_observations": proxy_data.get("observations", []),
                "proxy_schema_version": proxy_data.get("schema_version"),
            }
            self.output.write_text(json.dumps(payload, indent=2), encoding="utf-8")
            if session_error:
                raise DASTSessionError(
                    f"DAST session ended with an error; partial evidence was saved to {self.output}: {session_error}"
                )
            return payload

    def _wait_for_proxy(self, process: subprocess.Popen, timeout: float = 15.0) -> None:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if process.poll() is not None:
                raise DASTSessionError(
                    f"mitmdump exited during startup with code {process.returncode}"
                )
            try:
                with socket.create_connection(("127.0.0.1", self.proxy_port), timeout=0.25):
                    return
            except OSError:
                time.sleep(0.1)
        raise DASTSessionError(
            f"mitmproxy did not listen on port {self.proxy_port} within {timeout:.0f}s"
        )
