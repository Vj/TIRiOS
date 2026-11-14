from pathlib import Path
import plistlib
import re
from typing import Dict, Any, List
import lief

from tir_ios.core.models import Finding
from tir_ios.core.rule_registry import RuleRegistry


SENSITIVE_PERMISSIONS = {
    "NSCameraUsageDescription": "Camera",
    "NSMicrophoneUsageDescription": "Microphone",
    "NSLocationAlwaysAndWhenInUseUsageDescription": "Background Location (Always)",
    "NSLocationWhenInUseUsageDescription": "Location (When In Use)",
    "NSContactsUsageDescription": "Contacts",
    "NSPhotoLibraryUsageDescription": "Photo Library",
    "NSFaceIDUsageDescription": "Face ID Biometrics",
    "NSBluetoothAlwaysUsageDescription": "Bluetooth",
}


class PlistAuditor:
    def __init__(
        self,
        app_dir: Path,
        info_plist: Dict[str, Any],
        main_binary_path: Path,
        registry: RuleRegistry | None = None,
    ):
        self.app_dir = Path(app_dir)
        self.info_plist = info_plist
        self.main_binary_path = Path(main_binary_path)
        self.registry = registry or RuleRegistry.default()
        self.location = f"Payload/{self.app_dir.name}/Info.plist"

    def run_all(self) -> List[Finding]:
        findings: List[Finding] = []
        findings.extend(self._audit_ats())
        findings.extend(self._audit_url_schemes())
        findings.extend(self._audit_permissions())
        findings.extend(self._audit_entitlements())
        return findings

    def _audit_ats(self) -> List[Finding]:
        results: List[Finding] = []
        ats = self.info_plist.get("NSAppTransportSecurity")
        if not isinstance(ats, dict):
            return results

        if ats.get("NSAllowsArbitraryLoads") is True:
            results.append(
                self.registry.build_finding(
                    rule_id="TIR-IOS-SAST-010",
                    location=f"{self.location} -> NSAppTransportSecurity",
                    evidence="NSAllowsArbitraryLoads = true (permits cleartext HTTP connections to any domain).",
                )
            )

        if ats.get("NSAllowsArbitraryLoadsInWebContent") is True:
            results.append(
                self.registry.build_finding(
                    rule_id="TIR-IOS-SAST-011",
                    location=f"{self.location} -> NSAppTransportSecurity",
                    evidence="NSAllowsArbitraryLoadsInWebContent = true.",
                )
            )

        exception_domains = ats.get("NSExceptionDomains", {})
        if isinstance(exception_domains, dict):
            for domain, cfg in exception_domains.items():
                if not isinstance(cfg, dict):
                    continue
                insecure_flags = []
                if cfg.get("NSExceptionAllowsInsecureHTTPLoads") is True:
                    insecure_flags.append("NSExceptionAllowsInsecureHTTPLoads=true")
                if cfg.get("NSExceptionRequiresForwardSecrecy") is False:
                    insecure_flags.append("NSExceptionRequiresForwardSecrecy=false")
                min_tls = cfg.get("NSExceptionMinimumTLSVersion", "")
                if min_tls in {"TLSv1.0", "TLSv1.1"}:
                    insecure_flags.append(f"NSExceptionMinimumTLSVersion={min_tls}")

                if insecure_flags:
                    results.append(
                        self.registry.build_finding(
                            rule_id="TIR-IOS-SAST-012",
                            location=f"{self.location} -> NSExceptionDomains -> {domain}",
                            evidence=", ".join(insecure_flags),
                            title_suffix=f"for '{domain}'",
                        )
                    )

        return results

    def _audit_url_schemes(self) -> List[Finding]:
        results: List[Finding] = []
        url_types = self.info_plist.get("CFBundleURLTypes", [])
        schemes: List[str] = []

        for entry in url_types:
            if isinstance(entry, dict):
                schemes.extend(entry.get("CFBundleURLSchemes", []))

        if schemes:
            results.append(
                self.registry.build_finding(
                    rule_id="TIR-IOS-SAST-013",
                    location=f"{self.location} -> CFBundleURLTypes",
                    evidence=f"Registered schemes: {', '.join(schemes)}",
                )
            )
        return results

    def _audit_permissions(self) -> List[Finding]:
        results: List[Finding] = []
        declared = [
            f"{label} ({key})"
            for key, label in SENSITIVE_PERMISSIONS.items()
            if key in self.info_plist
        ]
        if declared:
            results.append(
                self.registry.build_finding(
                    rule_id="TIR-IOS-SAST-014",
                    location=self.location,
                    evidence="Declared permissions: " + ", ".join(declared),
                )
            )
        return results

    def _audit_entitlements(self) -> List[Finding]:
        results: List[Finding] = []
        entitlements = self._extract_entitlements_dict()
        if not entitlements:
            return results

        if entitlements.get("get-task-allow") is True:
            results.append(
                self.registry.build_finding(
                    rule_id="TIR-IOS-SAST-015",
                    location=f"Payload/{self.app_dir.name}/embedded.mobileprovision (Entitlements)",
                    evidence="get-task-allow = true (allows debugger attachment and container inspection on non-jailbroken devices).",
                )
            )
        return results

    def _extract_entitlements_dict(self) -> Dict[str, Any]:
        """Extracts embedded XML entitlements from Mach-O LC_CODE_SIGNATURE or embedded.mobileprovision."""
        fat = lief.MachO.parse(str(self.main_binary_path))
        if fat:
            for binary in fat:
                if binary.has_code_signature:
                    sig_bytes = bytes(binary.code_signature.content)
                    match = re.search(rb"<\?xml.*?</plist>", sig_bytes, flags=re.DOTALL)
                    if match:
                        try:
                            return plistlib.loads(match.group(0))
                        except Exception:
                            pass

        prov_path = self.app_dir / "embedded.mobileprovision"
        if prov_path.is_file():
            raw = prov_path.read_bytes()
            match = re.search(rb"<\?xml.*?</plist>", raw, flags=re.DOTALL)
            if match:
                try:
                    prov_plist = plistlib.loads(match.group(0))
                    return prov_plist.get("Entitlements", {})
                except Exception:
                    pass

        return {}