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

    def start(self, spawn: bool = False) -> None:
        device = frida.get_device(self.udid) if self.udid else frida.get_usb_device(timeout=5)
        source = self.agent_path.read_text(encoding="utf-8")

        if spawn:
            pid = device.spawn([self.bundle_id])
            self._session = device.attach(pid)
            self._script = self._session.create_script(source)
            self._script.on("message", self._on_message)
            self._script.load()
            device.resume(pid)
        else:
            self._session = device.attach(self.bundle_id)
            self._script = self._session.create_script(source)
            self._script.on("message", self._on_message)
            self._script.load()

    def stop(self) -> List[Finding]:
        telemetry: Dict[str, Any] = {}
        if self._script:
            try:
                telemetry = self._script.exports_sync.get_telemetry_summary()
                self._script.unload()
            except Exception:
                pass
        if self._session:
            try:
                self._session.detach()
            except Exception:
                pass

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