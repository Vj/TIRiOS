from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple
import frida

from tir_ios.core.models import Finding, Severity


EVENT_METADATA: Dict[str, Tuple[str, str, Severity, float, str, str, str]] = {
    "WEBVIEW_JS_BRIDGE": (
        "TIR-IOS-DAST-010",
        "WKWebView JavaScript Bridge Exposed to Web Content",
        Severity.MEDIUM,
        5.4,
        "MASVS-PLATFORM-2",
        "MASTG-TEST-0077",
        "Validate message origin (message.frameInfo.securityOrigin) inside userContentController(_:didReceive:) and restrict loaded URLs to trusted HTTPS origins.",
    ),
    "WEBVIEW_FILE_ACCESS": (
        "TIR-IOS-DAST-011",
        "WKWebView Local File Access Enabled (allowFileAccessFromFileURLs)",
        Severity.HIGH,
        7.1,
        "MASVS-PLATFORM-2",
        "MASTG-TEST-0077",
        "Disable allowFileAccessFromFileURLs on WKPreferences unless strictly required for sandboxed local HTML bundles.",
    ),
    "BIOMETRIC_BOOLEAN_ONLY": (
        "TIR-IOS-DAST-012",
        "Event-Bound Biometric Authentication (LAContext Without Keychain ACL)",
        Severity.MEDIUM,
        5.9,
        "MASVS-AUTH-2",
        "MASTG-TEST-0064",
        "Bind biometric authentication to a Keychain secret protected with SecAccessControlCreateWithFlags(..., .biometryCurrentSet, ...) rather than relying on LAContext boolean callbacks.",
    ),
    "PASTEBOARD_GLOBAL_WRITE": (
        "TIR-IOS-DAST-013",
        "Unrestricted Write to Global General Pasteboard",
        Severity.LOW,
        3.5,
        "MASVS-STORAGE-2",
        "MASTG-TEST-0055",
        "Use UIPasteboard.setItems(_:options:) with .localOnly and .expirationDate for sensitive values, or disable copy actions on sensitive fields.",
    ),
}


class FridaRuntimeAuditor:
    def __init__(self, bundle_id: str, udid: Optional[str] = None, agent_path: Optional[Path] = None):
        self.bundle_id = bundle_id
        self.udid = udid
        self.agent_path = agent_path or (Path(__file__).parent / "agents" / "audit_agent.js")
        self._findings: List[Finding] = []
        self._network_events = []
        self._seen: Set[Tuple[str, str]] = set()
        self._session: Optional[frida.core.Session] = None
        self._script: Optional[frida.core.Script] = None
        self._network_script: Optional[frida.core.Script] = None

    def start(self, spawn: bool = True) -> None:
        device = frida.get_device(self.udid) if self.udid else frida.get_usb_device(timeout=5)
        agent_source = self.agent_path.read_text(encoding="utf-8")
        network_agent_path = self.agent_path.parent / "network_attribution_agent.js"
        network_source = network_agent_path.read_text(encoding="utf-8")

        if spawn:
            pid = device.spawn([self.bundle_id])
            self._session = device.attach(pid)
        else:
            self._session = device.attach(self.bundle_id)

        self._script = self._session.create_script(agent_source)
        self._script.on("message", self._on_message)
        self._script.load()

        self._network_script = self._session.create_script(network_source)
        self._network_script.on("message", self._on_message)
        self._network_script.load()

        if spawn:
            device.resume(pid)

    @property
    def network_events(self):
        """Return a snapshot of network syscall events captured by Frida."""
        return list(self._network_events)

    def stop(self) -> List[Finding]:
        if self._script:
            try:
                self._script.unload()
            except frida.InvalidOperationError:
                pass
        if self._network_script:
            try:
                self._network_script.unload()
            except frida.InvalidOperationError:
                pass
        if self._session:
            try:
                self._session.detach()
            except frida.InvalidOperationError:
                pass
        return list(self._findings)

    def _on_message(self, message: dict, _data: object) -> None:
        if message.get("type") != "send":
            return
        payload = message.get("payload", {})
        if payload.get("category") == "TIR_NETWORK_EVENT":
            try:
                from tir_ios.core.models import RuntimeNetworkEvent

                event = RuntimeNetworkEvent(
                    process_id=int(payload["process_id"]),
                    bundle_id=str(payload["bundle_id"]),
                    timestamp=float(payload["timestamp"]),
                    destination_ip=str(payload["destination_ip"]),
                    destination_port=int(payload["destination_port"]),
                    socket_fd=int(payload["socket_fd"]) if payload.get("socket_fd") is not None else None,
                    syscall=str(payload.get("syscall", "connect")),
                )
                if event.bundle_id == self.bundle_id:
                    self._network_events.append(event)
            except (KeyError, TypeError, ValueError):
                return
            return

        if payload.get("category") != "TIR_DAST_EVENT":
            return

        check_type = payload.get("check_type", "")
        evidence = payload.get("evidence", "")
        location = payload.get("location", "Runtime")

        if check_type not in EVENT_METADATA:
            return
        fingerprint = (check_type, evidence)
        if fingerprint in self._seen:
            return
        self._seen.add(fingerprint)

        fid, title, severity, cvss, masvs, mastg, remediation = EVENT_METADATA[check_type]
        self._findings.append(
            Finding(
                finding_id=fid,
                title=title,
                severity=severity,
                cvss_score=cvss,
                masvs_category=masvs,
                mastg_test_id=mastg,
                phase="DAST",
                location=location,
                evidence=evidence,
                remediation=remediation,
            )
        )