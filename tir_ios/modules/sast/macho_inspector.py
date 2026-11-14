from pathlib import Path
from typing import List, Set
import lief

from tir_ios.core.models import Finding
from tir_ios.core.rule_registry import RuleRegistry


UNSAFE_C_FUNCTIONS = {
    "_strcpy": ("Buffer overflow risk (no bounds checking)", "strlcpy / strncpy"),
    "_strcat": ("Buffer overflow risk (no bounds checking)", "strlcat / strncat"),
    "_sprintf": ("Buffer overflow / format string risk", "snprintf"),
    "_vsprintf": ("Buffer overflow / format string risk", "vsnprintf"),
    "_gets": ("Unbounded input read vulnerability", "fgets"),
    "_memcpy": ("Potential heap/stack buffer overflow if length is unchecked", "memcpy_s / bounds-checked copy"),
    "_rand": ("Predictable PRNG unsuitable for security", "SecRandomCopyBytes"),
    "_random": ("Predictable PRNG unsuitable for security", "SecRandomCopyBytes"),
}

WEAK_CRYPTO_INDICATORS = {
    "CC_MD5": ("MD5 is cryptographically broken (collision attacks)", "SHA-256 / SHA-3 via CryptoKit"),
    "CC_SHA1": ("SHA-1 is deprecated and vulnerable to collisions", "SHA-256 / SHA-3 via CryptoKit"),
    "kCCAlgorithmDES": ("DES uses a 56-bit key vulnerable to brute force", "AES-GCM (AES-256)"),
    "kCCAlgorithm3DES": ("3DES is deprecated and vulnerable to Sweet32", "AES-GCM (AES-256)"),
    "kCCAlgorithmRC4": ("RC4 stream cipher has severe statistical biases", "AES-GCM or ChaCha20-Poly1305"),
    "kCCOptionECBMode": ("ECB mode preserves plaintext patterns", "AES-GCM or CBC with random IV + HMAC"),
}


class MachOInspector:
    def __init__(self, binary_path: Path, registry: RuleRegistry | None = None):
        self.binary_path = Path(binary_path)
        self.registry = registry or RuleRegistry.default()
        self.fat_binary = lief.MachO.parse(str(self.binary_path))
        if self.fat_binary is None:
            raise ValueError(f"Failed to parse Mach-O binary: {self.binary_path}")

    def get_architectures(self) -> List[str]:
        return [str(b.header.cpu_type).split(".")[-1] for b in self.fat_binary]

    def run_all(self) -> List[Finding]:
        findings: List[Finding] = []
        rel_loc = f"Payload/{self.binary_path.parent.name}/{self.binary_path.name}"

        for binary in self.fat_binary:
            arch = str(binary.header.cpu_type).split(".")[-1]
            imported_symbols: Set[str] = {sym.name for sym in binary.imported_symbols}

            findings.extend(self._check_binary_protections(binary, imported_symbols, arch, rel_loc))
            findings.extend(self._check_encryption_info(binary, arch, rel_loc))
            findings.extend(self._check_unsafe_apis(imported_symbols, arch, rel_loc))
            findings.extend(self._check_weak_crypto(binary, imported_symbols, arch, rel_loc))

        return findings

    def _check_binary_protections(
        self, binary: lief.MachO.Binary, imports: Set[str], arch: str, location: str
    ) -> List[Finding]:
        results: List[Finding] = []

        # 1. Position Independent Executable (PIE / ASLR)
        if not binary.header.has(lief.MachO.Header.FLAGS.PIE):
            results.append(
                self.registry.build_finding(
                    rule_id="TIR-IOS-SAST-001",
                    location=location,
                    evidence=f"Mach-O header missing MH_PIE flag for architecture {arch}.",
                    title_suffix=f"[{arch}]",
                )
            )

        # 2. Stack Canaries
        has_canary = "___stack_chk_fail" in imports or "___stack_chk_guard" in imports
        if not has_canary:
            results.append(
                self.registry.build_finding(
                    rule_id="TIR-IOS-SAST-002",
                    location=location,
                    evidence="Neither ___stack_chk_fail nor ___stack_chk_guard found in imported symbols.",
                    title_suffix=f"[{arch}]",
                )
            )

        # 3. Automatic Reference Counting (ARC)
        has_arc = "_objc_release" in imports or "_swift_release" in imports
        if not has_arc:
            results.append(
                self.registry.build_finding(
                    rule_id="TIR-IOS-SAST-003",
                    location=location,
                    evidence="Missing _objc_release / _swift_release runtime memory management symbols.",
                    title_suffix=f"[{arch}]",
                )
            )

        return results

    def _check_encryption_info(
        self, binary: lief.MachO.Binary, arch: str, location: str
    ) -> List[Finding]:
        results: List[Finding] = []
        if binary.has_encryption_info:
            enc_info = binary.encryption_info
            if enc_info.crypt_id == 0:
                results.append(
                    self.registry.build_finding(
                        rule_id="TIR-IOS-SAST-004",
                        location=location,
                        evidence=f"LC_ENCRYPTION_INFO cryptid={enc_info.crypt_id} (expected for ad-hoc/enterprise builds; App Store builds must be 1).",
                        title_suffix=f"[{arch}]",
                    )
                )
        return results

    def _check_unsafe_apis(
        self, imports: Set[str], arch: str, location: str
    ) -> List[Finding]:
        results: List[Finding] = []
        matched = sorted(imports.intersection(UNSAFE_C_FUNCTIONS.keys()))
        if matched:
            details = "; ".join(
                f"{fn} ({UNSAFE_C_FUNCTIONS[fn][0]} -> use {UNSAFE_C_FUNCTIONS[fn][1]})"
                for fn in matched
            )
            results.append(
                self.registry.build_finding(
                    rule_id="TIR-IOS-SAST-005",
                    location=location,
                    evidence=details,
                    title_suffix=f"[{arch}]",
                )
            )
        return results

    def _check_weak_crypto(
        self, binary: lief.MachO.Binary, imports: Set[str], arch: str, location: str
    ) -> List[Finding]:
        results: List[Finding] = []
        cstrings = self._extract_cstrings(binary)
        combined_tokens = imports | {f"_{s}" for s in cstrings} | cstrings

        found_weak = []
        for indicator, (reason, fix) in WEAK_CRYPTO_INDICATORS.items():
            if indicator in combined_tokens or f"_{indicator}" in combined_tokens:
                found_weak.append(f"{indicator}: {reason} (Use {fix})")

        if found_weak:
            results.append(
                self.registry.build_finding(
                    rule_id="TIR-IOS-SAST-006",
                    location=location,
                    evidence="; ".join(found_weak),
                    title_suffix=f"[{arch}]",
                )
            )
        return results

    @staticmethod
    def _extract_cstrings(binary: lief.MachO.Binary) -> Set[str]:
        strings: Set[str] = set()
        for section in binary.sections:
            if section.name == "__cstring":
                raw = bytes(section.content)
                for chunk in raw.split(b"\x00"):
                    if len(chunk) >= 4:
                        try:
                            strings.add(chunk.decode("utf-8"))
                        except UnicodeDecodeError:
                            continue
        return strings