from typing import Any, Dict, List, Set, Tuple

from tir_ios.core.models import Finding
from tir_ios.core.rule_registry import RuleRegistry


WEAK_ACCESSIBILITY_FLAGS = {
    "kSecAttrAccessibleAlways",
    "kSecAttrAccessibleAlwaysThisDeviceOnly",
    "kSecAttrAccessibleWhenUnlocked",
    "kSecAttrAccessibleAfterFirstUnlock",
    "dk",
    "dku",
    "ak",
    "ck",
    "unset",
}


class KeychainAndSnapshotAuditor:
    """
    Evaluates runtime Keychain accessibility flags (TIR-IOS-DAST-004) and
    background UI snapshot masking (TIR-IOS-DAST-005) from Frida events or
    offline Keychain dump JSON exports.
    """

    def __init__(self, registry: RuleRegistry | None = None):
        self.registry = registry or RuleRegistry.default()
        self._findings: List[Finding] = []
        self._seen: Set[Tuple[str, str]] = set()

    def process_frida_payload(self, payload: Dict[str, Any]) -> None:
        if payload.get("category") != "TIR_RESILIENCE_EVENT":
            return

        check_type = payload.get("check_type", "")
        location = payload.get("location", "Runtime")
        evidence = payload.get("evidence", "")

        if check_type == "KEYCHAIN_WEAK_ACCESSIBILITY":
            self._add_unique("TIR-IOS-DAST-004", location, evidence)
        elif check_type == "SNAPSHOT_NOT_OBSCURED":
            self._add_unique("TIR-IOS-DAST-005", location, evidence)

    def audit_keychain_dump(self, keychain_entries: List[Dict[str, Any]]) -> List[Finding]:
        """Audits an exported list of Keychain item dictionaries (e.g., from keychain-dumper)."""
        for entry in keychain_entries:
            accessible = str(entry.get("pdmn") or entry.get("kSecAttrAccessible") or "unset")
            service = str(entry.get("svce") or entry.get("kSecAttrService") or "unknown")
            account = str(entry.get("acct") or entry.get("kSecAttrAccount") or "unknown")

            if accessible in WEAK_ACCESSIBILITY_FLAGS:
                self._add_unique(
                    rule_id="TIR-IOS-DAST-004",
                    location=f"iOS Keychain (Service: {service})",
                    evidence=(
                        f"Account '{account}' stored with '{accessible}'. "
                        "Prefer kSecAttrAccessibleWhenUnlockedThisDeviceOnly."
                    ),
                )
        return self.get_findings()

    def get_findings(self) -> List[Finding]:
        return list(self._findings)

    def _add_unique(self, rule_id: str, location: str, evidence: str) -> None:
        fp = (rule_id, evidence)
        if fp in self._seen:
            return
        self._seen.add(fp)
        self._findings.append(
            self.registry.build_finding(
                rule_id=rule_id,
                location=location,
                evidence=evidence,
            )
        )