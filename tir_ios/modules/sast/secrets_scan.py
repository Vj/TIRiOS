from collections import Counter
import math
from pathlib import Path
import plistlib
import re
from typing import Dict, Iterable, List, Set, Tuple
import lief

from tir_ios.core.models import Finding, Severity
from tir_ios.core.rule_registry import RuleRegistry


# Tuple: (compiled_regex, severity_override_or_None, specific_remediation)
SECRET_PATTERNS: Dict[str, Tuple[re.Pattern[str], Severity | None, str]] = {
    "AWS Access Key ID": (
        re.compile(r"\b(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}\b"),
        Severity.CRITICAL,
        "Rotate the compromised IAM key immediately and migrate mobile authentication to AWS Cognito or temporary STS credentials.",
    ),
    "PEM Private Key": (
        re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"),
        Severity.CRITICAL,
        "Remove embedded private keys from the app bundle; generate device-specific keys inside the iOS Secure Enclave / Keychain.",
    ),
    "Google / Firebase API Key": (
        re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b"),
        Severity.MEDIUM,
        "Restrict the API key by iOS Bundle ID in Google Cloud Console and enforce Firebase App Check.",
    ),
    "Stripe Secret / Restricted Key": (
        re.compile(r"\b(?:sk|rk)_(?:live|test)_[0-9a-zA-Z]{24,99}\b"),
        Severity.CRITICAL,
        "Never embed Stripe secret keys in client apps; route payment intent creation through a backend server and use publishable keys (pk_*) only.",
    ),
    "GitHub Personal Access Token": (
        re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,255}\b"),
        Severity.HIGH,
        "Revoke the token in GitHub developer settings and remove build-time tokens from bundled configuration files.",
    ),
    "Slack Token / Webhook": (
        re.compile(r"\bxox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24,32}\b"),
        Severity.HIGH,
        "Revoke the Slack token and move webhook integrations to a server-side notification service.",
    ),
    "Hardcoded Bearer / JWT Token": (
        re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
        Severity.HIGH,
        "Remove static JWT tokens from bundle assets; fetch short-lived tokens dynamically at runtime and store them in the iOS Keychain.",
    ),
    "Generic Hardcoded Secret Assignment": (
        re.compile(
            r"(?i)(?:api[_-]?key|client[_-]?secret|auth[_-]?token|password|passwd|secret[_-]?key|private[_-]?key)"
            r"\s*[:=]\s*[\"']([A-Za-z0-9+/=_\-]{16,128})[\"']"
        ),
        Severity.HIGH,
        "Externalize static credentials to a secure backend token-exchange flow rather than hardcoding secrets in client code or plists.",
    ),
    "Internal / Staging Backend URL": (
        re.compile(
            r"https?://(?:[a-zA-Z0-9\-]+\.)*(?:internal|staging|dev|uat|qa|sandbox|local|corp)\.[a-zA-Z0-9.\-]+"
            r"|https?://(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})(?::\d+)?"
        ),
        Severity.LOW,
        "Strip non-production staging URLs and internal RFC1918 IP addresses from release builds via build configurations.",
    ),
}

SCANNABLE_EXTENSIONS = {".plist", ".json", ".js", ".xml", ".strings", ".yaml", ".yml", ".config", ".env"}
UUID_PATTERN = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
HEX_HASH_PATTERN = re.compile(r"^[0-9a-fA-F]{32,128}$")
SWIFT_MANGLING_PATTERN = re.compile(r"^(?:s\d+[A-Za-z0-9_]+|TtC\d+[A-Za-z0-9_]+)$")
CANDIDATE_TOKEN_PATTERN = re.compile(r"\b[A-Za-z0-9+/=_\-]{24,128}\b")


class SecretsScanner:
    def __init__(
        self,
        app_dir: Path,
        main_binary_path: Path,
        entropy_threshold: float = 4.6,
        max_file_size_bytes: int = 5 * 1024 * 1024,
        registry: RuleRegistry | None = None,
    ):
        self.app_dir = Path(app_dir)
        self.main_binary_path = Path(main_binary_path)
        self.entropy_threshold = entropy_threshold
        self.max_file_size_bytes = max_file_size_bytes
        self.registry = registry or RuleRegistry.default()
        self._seen_fingerprints: Set[Tuple[str, str, str]] = set()

    def run_all(self) -> List[Finding]:
        findings: List[Finding] = []

        macho_rel = f"Payload/{self.app_dir.name}/{self.main_binary_path.name}"
        for text_chunk in self._extract_macho_strings():
            findings.extend(self._scan_text(text_chunk, location=macho_rel, allow_entropy=True))

        for file_path in self.app_dir.rglob("*"):
            if not file_path.is_file() or file_path == self.main_binary_path:
                continue
            if file_path.suffix.lower() not in SCANNABLE_EXTENSIONS:
                continue
            if file_path.stat().st_size > self.max_file_size_bytes:
                continue

            rel_path = f"Payload/{self.app_dir.name}/{file_path.relative_to(self.app_dir).as_posix()}"
            content = self._read_asset_as_text(file_path)
            if content:
                findings.extend(self._scan_text(content, location=rel_path, allow_entropy=True))

        return findings

    def _extract_macho_strings(self) -> Iterable[str]:
        fat_binary = lief.MachO.parse(str(self.main_binary_path))
        if not fat_binary:
            return []

        extracted: List[str] = []
        for binary in fat_binary:
            for section in binary.sections:
                if section.name in {"__cstring", "__ustring", "__cfstring"}:
                    raw = bytes(section.content)
                    for chunk in raw.split(b"\x00"):
                        if len(chunk) >= 8:
                            try:
                                extracted.append(chunk.decode("utf-8"))
                            except UnicodeDecodeError:
                                continue
        return ["\n".join(extracted)]

    @staticmethod
    def _read_asset_as_text(file_path: Path) -> str:
        try:
            raw = file_path.read_bytes()
            if file_path.suffix.lower() in {".plist", ".strings"} and raw.startswith(b"bplist"):
                parsed = plistlib.loads(raw)
                return SecretsScanner._flatten_plist(parsed)
            return raw.decode("utf-8", errors="ignore")
        except Exception:
            return ""

    @staticmethod
    def _flatten_plist(obj: object, prefix: str = "") -> str:
        lines: List[str] = []
        if isinstance(obj, dict):
            for k, v in obj.items():
                key_path = f"{prefix}.{k}" if prefix else str(k)
                lines.append(SecretsScanner._flatten_plist(v, key_path))
        elif isinstance(obj, list):
            for idx, item in enumerate(obj):
                lines.append(SecretsScanner._flatten_plist(item, f"{prefix}[{idx}]"))
        else:
            lines.append(f'{prefix} = "{obj}"')
        return "\n".join(lines)

    def _scan_text(self, text: str, location: str, allow_entropy: bool) -> List[Finding]:
        results: List[Finding] = []

        # Pass 1: Deterministic Regex Signatures
        for rule_name, (pattern, severity_override, remediation) in SECRET_PATTERNS.items():
            for match in pattern.finditer(text):
                matched_val = match.group(1) if match.lastindex else match.group(0)
                masked = self._mask_secret(matched_val)
                fingerprint = (rule_name, location, masked)
                if fingerprint in self._seen_fingerprints:
                    continue
                self._seen_fingerprints.add(fingerprint)

                finding = self.registry.build_finding(
                    rule_id="TIR-IOS-SAST-020",
                    location=location,
                    evidence=f"Matched {rule_name}: {masked}",
                    title_suffix=f"({rule_name})",
                    severity_override=severity_override,
                )
                finding.remediation = remediation
                results.append(finding)

        # Pass 2: Shannon Entropy Scanner on Standalone Tokens
        if allow_entropy:
            for candidate in CANDIDATE_TOKEN_PATTERN.findall(text):
                if self._is_noise_token(candidate):
                    continue
                entropy = self.shannon_entropy(candidate)
                if entropy >= self.entropy_threshold:
                    masked = self._mask_secret(candidate)
                    fingerprint = ("HIGH_ENTROPY", location, masked)
                    if fingerprint in self._seen_fingerprints:
                        continue
                    self._seen_fingerprints.add(fingerprint)

                    results.append(
                        self.registry.build_finding(
                            rule_id="TIR-IOS-SAST-021",
                            location=location,
                            evidence=f"Token '{masked}' (length={len(candidate)}, Shannon entropy={entropy:.2f} bits/char).",
                        )
                    )

        return results

    @staticmethod
    def shannon_entropy(data: str) -> float:
        if not data:
            return 0.0
        counts = Counter(data)
        length = len(data)
        return -sum((count / length) * math.log2(count / length) for count in counts.values())

    @staticmethod
    def _is_noise_token(token: str) -> bool:
        if UUID_PATTERN.match(token) or HEX_HASH_PATTERN.match(token):
            return True
        # The token regex starts at a word boundary, so it can strip the leading
        # "$" from Swift's "$s..." mangled symbols. Filter that remainder too.
        if SWIFT_MANGLING_PATTERN.match(token):
            return True
        if token.startswith(("_OBJC_", "$s", "_$s", "com.apple.", "NS", "UI", "WK", "CF")):
            return True
        has_upper = any(c.isupper() for c in token)
        has_lower = any(c.islower() for c in token)
        has_digit = any(c.isdigit() for c in token)
        return not (has_digit and (has_upper or has_lower))

    @staticmethod
    def _mask_secret(secret: str) -> str:
        if len(secret) <= 10:
            return secret[:2] + "*" * (len(secret) - 2)
        return f"{secret[:4]}...{secret[-4:]}"
