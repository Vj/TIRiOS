"""Additional source- and bundle-level SAST checks.

Static heuristics intentionally report indicators, not proof of exploitability.
Source code is not normally shipped inside an IPA; pass --source-dir to scan a
checked-out Xcode source tree.
"""
from __future__ import annotations

from pathlib import Path
import plistlib
import re
from typing import Any

from tir_ios.core.models import Finding, Severity
from tir_ios.core.rule_registry import RuleRegistry

SOURCE_SUFFIXES = {".swift", ".m", ".mm", ".h", ".hpp", ".c", ".cc", ".cpp"}
MAX_SOURCE_BYTES = 2 * 1024 * 1024
SDK_MARKERS = {
    "Firebase": ("FirebaseCore.framework", "FirebaseAnalytics.framework", "FirebaseCrashlytics.framework", "FirebaseMessaging.framework"),
    "Google Mobile Ads": ("GoogleMobileAds.framework", "GoogleMobileAds"),
    "Facebook SDK": ("FBSDKCoreKit.framework", "FBSDKLoginKit.framework", "FacebookSDK"),
    "Adjust": ("AdjustSdk.framework", "Adjust.framework"),
    "AppsFlyer": ("AppsFlyerLib.framework", "AppsFlyer"),
    "Amplitude": ("Amplitude.framework", "AmplitudeSwift.framework"),
    "Sentry": ("Sentry.framework", "Sentry"),
    "OneSignal": ("OneSignal.framework", "OneSignal"),
    "Alamofire": ("Alamofire.framework", "Alamofire"),
    "Realm": ("Realm.framework", "RealmSwift.framework"),
}

CRYPTO_PATTERNS = {
    "MD5": re.compile(r"\b(?:CC_MD5|Insecure\.MD5|CommonCrypto\.MD5)\b"),
    "SHA-1": re.compile(r"\b(?:CC_SHA1|Insecure\.SHA1|CommonCrypto\.SHA1)\b"),
    "DES / 3DES / RC4": re.compile(r"\b(?:kCCAlgorithmDES|kCCAlgorithm3DES|kCCAlgorithmRC4)\b"),
    "ECB mode": re.compile(r"\b(?:kCCOptionECBMode|\.ecb)\b", re.I),
    "Non-cryptographic random": re.compile(r"\b(?:arc4random(?:_uniform)?|rand|random)\s*\("),
}
OAUTH_MARKERS = re.compile(r"(?i)\b(?:ASAuthorization|ASWebAuthenticationSession|oauth2?|openid|code_verifier|code_challenge|redirect_uri)\b")
STATE_VALIDATION = re.compile(r"(?i)(?:state\s*==|state\s*!=|validate\w*state|guard\s+.*state)")
PKCE_S256 = re.compile(r"(?i)(?:code_challenge_method\s*[:=]\s*[\"']S256|codeChallengeMethod\s*[:=]\s*\.S256|code_challenge\s*[:=])")
UNIVERSAL_LINKS = "com.apple.developer.associated-domains"


class SASTExpansion:
    def __init__(self, app_dir: Path, info_plist: dict[str, Any], source_dir: Path | None = None,
                 registry: RuleRegistry | None = None):
        self.app_dir = Path(app_dir)
        self.info_plist = info_plist
        self.source_dir = Path(source_dir) if source_dir else None
        self.registry = registry or RuleRegistry.default()

    def run_all(self) -> list[Finding]:
        findings: list[Finding] = []
        findings.extend(self._privacy_manifests())
        findings.extend(self._sdk_inventory())
        source_files = self._source_files()
        findings.extend(self._oauth_review(source_files))
        findings.extend(self._deep_link_review(source_files))
        findings.extend(self._crypto_review(source_files))
        return findings

    def _privacy_manifests(self) -> list[Finding]:
        manifests = list(self.app_dir.rglob("PrivacyInfo.xcprivacy"))
        if not manifests:
            return [self.registry.build_finding(
                "TIR-IOS-SAST-030", f"Payload/{self.app_dir.name}/PrivacyInfo.xcprivacy",
                "No PrivacyInfo.xcprivacy found in the app bundle. Absence is a review signal, not by itself proof of non-compliance; requirements depend on app APIs and included SDKs.",
                severity_override=Severity.INFO, cvss_override=0.0)]
        results = []
        for path in manifests:
            rel = f"Payload/{self.app_dir.name}/{path.relative_to(self.app_dir).as_posix()}"
            try:
                data = plistlib.loads(path.read_bytes())
                if not isinstance(data, dict):
                    raise ValueError("root value is not a dictionary")
                required = ("NSPrivacyTracking", "NSPrivacyCollectedDataTypes", "NSPrivacyAccessedAPITypes")
                missing = [key for key in required if key not in data]
                malformed = [key for key in required if key in data and not isinstance(data[key], (bool, list))]
                if missing or malformed:
                    results.append(self.registry.build_finding(
                        "TIR-IOS-SAST-030", rel,
                        f"Manifest parsed, but declaration keys absent={missing}; values with unexpected types={malformed}. Review whether each declaration is applicable and required.",
                        severity_override=Severity.LOW))
            except (OSError, plistlib.InvalidFileException, ValueError) as exc:
                results.append(self.registry.build_finding(
                    "TIR-IOS-SAST-030", rel, f"Privacy manifest could not be parsed: {exc}",
                    severity_override=Severity.MEDIUM))
        return results

    def _sdk_inventory(self) -> list[Finding]:
        names = []
        roots = [self.app_dir / "Frameworks", self.app_dir / "PlugIns"]
        candidates = []
        for root in roots:
            if root.exists():
                candidates.extend(p for p in root.rglob("*") if p.is_dir() and (p.suffix in {".framework", ".appex", ".bundle"}))
        candidates.extend(p for p in self.app_dir.iterdir() if p.is_dir() and p.suffix == ".framework")
        for vendor, markers in SDK_MARKERS.items():
            if any(any(marker.lower() in p.name.lower() for marker in markers) for p in candidates):
                names.append(vendor)
        if not names:
            return []
        return [self.registry.build_finding(
            "TIR-IOS-SAST-031", f"Payload/{self.app_dir.name}/Frameworks",
            "Recognized SDK indicators: " + ", ".join(sorted(set(names))) +
            ". This is an inventory signal only; no vulnerable version or malicious behavior is inferred.",
            severity_override=Severity.INFO, cvss_override=0.0)]

    def _source_files(self) -> list[Path]:
        roots = [self.source_dir] if self.source_dir else [self.app_dir]
        files = []
        for root in roots:
            if root and root.exists():
                files.extend(p for p in root.rglob("*") if p.is_file() and p.suffix.lower() in SOURCE_SUFFIXES
                             and p.stat().st_size <= MAX_SOURCE_BYTES)
        return sorted(set(files))

    @staticmethod
    def _read(path: Path) -> str:
        try:
            return path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            return ""

    def _oauth_review(self, files: list[Path]) -> list[Finding]:
        matched = []
        has_state = False
        has_pkce = False
        for path in files:
            content = self._read(path)
            if OAUTH_MARKERS.search(content):
                matched.append(path)
                has_state |= bool(STATE_VALIDATION.search(content))
                has_pkce |= bool(PKCE_S256.search(content))
        if not matched:
            return []
        notes = []
        if not has_state:
            notes.append("No obvious state validation pattern found in scanned source")
        if not has_pkce:
            notes.append("No obvious PKCE S256 pattern found in scanned source")
        if not notes:
            return []
        locations = ", ".join(str(p) for p in matched[:8])
        return [self.registry.build_finding(
            "TIR-IOS-SAST-032", locations,
            "OAuth-related source indicators found. " + "; ".join(notes) +
            ". Heuristic limitation: validation may be delegated to a library or represented indirectly; manually trace the complete authorization flow.",
            severity_override=Severity.MEDIUM)]

    def _deep_link_review(self, files: list[Path]) -> list[Finding]:
        schemes = []
        for entry in self.info_plist.get("CFBundleURLTypes", []) or []:
            if isinstance(entry, dict):
                for scheme in entry.get("CFBundleURLSchemes", []) or []:
                    if isinstance(scheme, str) and scheme and scheme not in schemes:
                        schemes.append(scheme)
        if not schemes:
            return []
        associated = self.info_plist.get("com.apple.developer.associated-domains", [])
        locations = [str(p) for p in files if re.search(r"(?i)(onOpenURL|openURLContexts|application\(.*open|scene\(.*openURLContexts|continueUserActivity)", self._read(p))]
        evidence = f"Registered custom schemes: {', '.join(schemes)}. Associated Domains present in Info.plist: {bool(associated)}. URL handler source files: {locations[:8] or 'not found in scanned source'}."
        return [self.registry.build_finding(
            "TIR-IOS-SAST-033", f"Payload/{self.app_dir.name}/Info.plist -> CFBundleURLTypes",
            evidence + " Custom schemes can be claimed by another installed app; this finding requests handler review and does not assert an exploitable issue.",
            severity_override=Severity.INFO, cvss_override=0.0)]

    def _crypto_review(self, files: list[Path]) -> list[Finding]:
        matches = []
        for path in files:
            content = self._read(path)
            for label, pattern in CRYPTO_PATTERNS.items():
                for match in pattern.finditer(content):
                    line = content.count("\n", 0, match.start()) + 1
                    matches.append(f"{path}:{line}: {label} ({match.group(0)})")
        if not matches:
            return []
        return [self.registry.build_finding(
            "TIR-IOS-SAST-034", ", ".join(matches[:20]),
            "Potential weak cryptographic API references: " + "; ".join(matches[:20]) +
            ". Static token matches do not prove the API is used on sensitive data; inspect call sites, algorithm mode, key size and protocol context.",
            severity_override=Severity.MEDIUM)]
