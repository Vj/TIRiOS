from pathlib import Path
from typing import Any, Dict, List, Optional
import frida

from tir_ios.core.models import Finding
from tir_ios.core.rule_registry import RuleRegistry
from tir_ios.modules.dast.keychain_auditor import KeychainAndSnapshotAuditor


class ResilienceRuntimeAuditor:
    """
    Runs resilience_agent.js to audit Keychain accessibility flags, background
    snapshot masking, jailbreak detection probes, and anti-debugging defenses.
    """

    def __init__(
        self,
        bundle_id: str,
        udid: Optional[str] = None,
        agent_path: Optional[Path] = None,
        registry: RuleRegistry | None = None,
    ):
        self.bundle_id = bundle_id
        self.udid = udid
        self.registry = registry or RuleRegistry.default()
        self.agent_path = agent_path or (Path(__file__).parent / "agents" / "resilience_agent.js")
        self.keychain_auditor = KeychainAndSnapshotAuditor(registry=self.registry)
        self._session: Optional[frida.core.Session] = None
        self._script: Optional[frida.core.Script] = None
        self._device = None
        self._spawned_pid: Optional[int] = None
        self._process_resumed = False

    def start(self, spawn: bool = False) -> None:
        if self._session is not None or self._script is not None or self._spawned_pid is not None:
            raise RuntimeError("Resilience auditor is already started.")

        self._device = frida.get_device(self.udid) if self.udid else frida.get_usb_device(timeout=5)
        source = self.agent_path.read_text(encoding="utf-8")

        try:
            if spawn:
                self._spawned_pid = self._device.spawn([self.bundle_id])
                self._process_resumed = False
                self._session = self._device.attach(self._spawned_pid)
            else:
                self._session = self._device.attach(self.bundle_id)

            self._script = self._session.create_script(source)
            self._script.on("message", self._on_message)
            self._script.load()

            if self._spawned_pid is not None:
                self._device.resume(self._spawned_pid)
                self._process_resumed = True
        except Exception:
            self._cleanup_after_start_failure()
            raise

    def _cleanup_after_start_failure(self) -> None:
        if self._script is not None:
            try:
                self._script.unload()
            except Exception:
                pass
        if self._session is not None:
            try:
                self._session.detach()
            except Exception:
                pass
        if self._spawned_pid is not None and not self._process_resumed and self._device is not None:
            try:
                self._device.resume(self._spawned_pid)
                self._process_resumed = True
            except Exception:
                pass
        self._script = None
        self._session = None
        self._spawned_pid = None
        self._device = None

    def stop(self) -> List[Finding]:
        telemetry: Dict[str, Any] = {}
        cleanup_error: Optional[Exception] = None
        if self._script is not None:
            try:
                telemetry = self._script.exports_sync.get_telemetry_summary()
            except Exception as exc:
                cleanup_error = exc
            try:
                self._script.unload()
            except frida.InvalidOperationError:
                pass
            except Exception as exc:
                cleanup_error = cleanup_error or exc
        if self._session is not None:
            try:
                self._session.detach()
            except frida.InvalidOperationError:
                pass
            except Exception as exc:
                cleanup_error = cleanup_error or exc
        if self._spawned_pid is not None and not self._process_resumed and self._device is not None:
            try:
                self._device.resume(self._spawned_pid)
                self._process_resumed = True
            except Exception as exc:
                cleanup_error = cleanup_error or exc

        self._script = None
        self._session = None
        self._spawned_pid = None
        self._device = None
        if cleanup_error is not None:
            raise RuntimeError(f"Frida resilience cleanup failed: {cleanup_error}") from cleanup_error

        findings = self.keychain_auditor.get_findings()

        if telemetry and not telemetry.get("sawJailbreakCheck", False):
            findings.append(
                self.registry.build_finding(
                    rule_id="TIR-IOS-DAST-030",
                    location=f"Runtime Process ({self.bundle_id})",
                    evidence=(
                        "No standard jailbreak filesystem/dyld integrity checks were observed "
                        "during app startup and interaction."
                    ),
                )
            )

        if telemetry and not telemetry.get("sawAntiDebugCheck", False):
            findings.append(
                self.registry.build_finding(
                    rule_id="TIR-IOS-DAST-031",
                    location=f"Runtime Process ({self.bundle_id})",
                    evidence=(
                        "Process permitted dynamic instrumentation attachment without invoking "
                        "sysctl (P_TRACED) or ptrace (PT_DENY_ATTACH) checks."
                    ),
                )
            )

        return findings

    def _on_message(self, message: dict, _data: object) -> None:
        if message.get("type") == "send":
            self.keychain_auditor.process_frida_payload(message.get("payload", {}))