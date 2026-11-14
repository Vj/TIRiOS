import hashlib
from pathlib import Path
import plistlib
import re
import shutil
import sqlite3
import tempfile
from typing import Dict, List, Set, Tuple

from pymobiledevice3.services.house_arrest import HouseArrestService

from tir_ios.core.device_bridge import IOSDeviceBridge
from tir_ios.core.models import Finding, Severity
from tir_ios.core.rule_registry import RuleRegistry


PLAINTEXT_STORAGE_PATTERNS: Dict[str, Tuple[re.Pattern[str], Severity | None]] = {
    "JWT / Bearer Session Token": (
        re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
        Severity.HIGH,
    ),
    "Plaintext Password / Secret Key-Value": (
        re.compile(
            r"(?i)(?:password|passwd|pwd|secret|access_token|refresh_token|auth_token|api_key|pin_code)"
            r"\s*[:=]\s*['\"]?([A-Za-z0-9+/=_\-!@#$%^&*]{6,128})['\"]?"
        ),
        Severity.HIGH,
    ),
    "Credit Card Number (PAN)": (
        re.compile(r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b"),
        Severity.CRITICAL,
    ),
    "Email / User PII Stored in Plaintext": (
        re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
        Severity.LOW,
    ),
}

# Sandbox subdirectories subject to iCloud / Finder backups unless excluded
BACKUP_ELIGIBLE_ROOTS = ("Documents", "Library/Application Support", "Library/Preferences")
INSPECTABLE_EXTENSIONS = {".plist", ".sqlite", ".sqlite3", ".db", ".realm", ".json", ".xml", ".txt", ".dat"}


class SandboxStorageMonitor:
    """
    Pulls an app's sandbox container via pymobiledevice3 HouseArrestService,
    diffs pre/post-session artifacts, scans SQLite/Realm/plist files for
    plaintext sensitive data, and verifies backup exclusion attributes.
    """

    def __init__(
        self,
        bridge: IOSDeviceBridge,
        bundle_id: str,
        registry: RuleRegistry | None = None,
    ):
        self.bridge = bridge
        self.bundle_id = bundle_id
        self.registry = registry or RuleRegistry.default()
        self._work_dir = Path(tempfile.mkdtemp(prefix="tir_ios_sandbox_"))
        self._baseline_hashes: Dict[str, str] = {}
        self._seen_findings: Set[Tuple[str, str, str]] = set()

    def capture_baseline(self) -> Dict[str, str]:
        """Pulls the initial sandbox container and records SHA-256 digests of existing files."""
        baseline_dir = self._work_dir / "baseline"
        self._pull_container(baseline_dir)
        self._baseline_hashes = self._hash_directory(baseline_dir)
        return dict(self._baseline_hashes)

    def analyze_post_session(self) -> List[Finding]:
        """
        Pulls the post-exercise sandbox container, identifies newly created or
        modified files, scans them for plaintext secrets, and checks backup flags.
        """
        post_dir = self._work_dir / "post_session"
        self._pull_container(post_dir)
        post_hashes = self._hash_directory(post_dir)

        findings: List[Finding] = []
        for rel_path, current_hash in post_hashes.items():
            # If a baseline was captured, focus on files created or modified during the test session
            if self._baseline_hashes and self._baseline_hashes.get(rel_path) == current_hash:
                continue

            local_file = post_dir / rel_path
            if not local_file.is_file():
                continue

            has_sensitive_data = False
            if self._is_inspectable(local_file):
                storage_findings = self._scan_sandbox_file(local_file, rel_path)
                if storage_findings:
                    has_sensitive_data = True
                    findings.extend(storage_findings)

            # Check NSURLIsExcludedFromBackupKey for sensitive files inside backup-eligible folders
            if has_sensitive_data and self._is_backup_eligible(rel_path):
                if not self._is_excluded_from_backup(local_file, rel_path):
                    findings.append(self._build_backup_finding(rel_path))

        return findings

    def cleanup(self) -> None:
        if self._work_dir.exists():
            shutil.rmtree(self._work_dir, ignore_errors=True)

    def __enter__(self) -> "SandboxStorageMonitor":
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.cleanup()

    def _pull_container(self, destination: Path) -> None:
        """
        Connects via HouseArrestService ('VendContainer' for debuggable apps or
        'VendDocuments' fallback) and mirrors the sandbox container locally.
        """
        if destination.exists():
            shutil.rmtree(destination)
        destination.mkdir(parents=True, exist_ok=True)

        try:
            with HouseArrestService(lockdown=self.bridge.lockdown, bundle_id=self.bundle_id, cmd="VendContainer") as afc:
                afc.pull("/", str(destination))
        except Exception:
            # Fallback to VendDocuments if VendContainer is restricted on non-debuggable builds
            with HouseArrestService(lockdown=self.bridge.lockdown, bundle_id=self.bundle_id, cmd="VendDocuments") as afc:
                docs_dest = destination / "Documents"
                docs_dest.mkdir(parents=True, exist_ok=True)
                afc.pull("/Documents", str(docs_dest))

    def _scan_sandbox_file(self, file_path: Path, rel_path: str) -> List[Finding]:
        text_corpus = self._extract_file_text(file_path)
        if not text_corpus:
            return []

        results: List[Finding] = []
        for rule_name, (pattern, severity_override) in PLAINTEXT_STORAGE_PATTERNS.items():
            for match in pattern.finditer(text_corpus):
                raw_val = match.group(1) if match.lastindex else match.group(0)
                redacted = self._redact(raw_val)
                fp = ("TIR-IOS-DAST-002", rel_path, f"{rule_name}:{redacted}")
                if fp in self._seen_findings:
                    continue
                self._seen_findings.add(fp)

                results.append(
                    self.registry.build_finding(
                        rule_id="TIR-IOS-DAST-002",
                        location=f"AppSandbox/{rel_path}",
                        evidence=f"Plaintext {rule_name} found at rest: {redacted}",
                        title_suffix=f"({rule_name})",
                        severity_override=severity_override,
                    )
                )
        return results

    def _extract_file_text(self, file_path: Path) -> str:
        suffix = file_path.suffix.lower()
        try:
            raw = file_path.read_bytes()

            # 1. Binary or XML Property Lists (NSUserDefaults, caches)
            if suffix == ".plist" or raw.startswith(b"bplist"):
                parsed = plistlib.loads(raw)
                return self._flatten_obj(parsed)

            # 2. SQLite / CoreData Databases
            if suffix in {".sqlite", ".sqlite3", ".db"} or raw.startswith(b"SQLite format 3\x00"):
                return self._dump_sqlite_text(file_path)

            # 3. Realm / Binary Stores (extract printable UTF-8 strings >= 6 chars)
            if suffix == ".realm":
                chunks = re.findall(rb"[\x20-\x7e]{6,}", raw)
                return "\n".join(c.decode("ascii", errors="ignore") for c in chunks)

            # 4. Plaintext JSON / XML / TXT
            return raw.decode("utf-8", errors="ignore")
        except Exception:
            return ""

    @staticmethod
    def _dump_sqlite_text(db_path: Path) -> str:
        """Reads all user tables from a SQLite/CoreData database in read-only mode."""
        lines: List[str] = []
        uri = f"file:{db_path.as_posix()}?mode=ro"
        with sqlite3.connect(uri, uri=True) as conn:
            cursor = conn.cursor()
            tables = [
                row[0]
                for row in cursor.execute(
                    "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%';"
                ).fetchall()
            ]
            for table in tables:
                safe_table = table.replace('"', '""')
                col_info = cursor.execute(f'PRAGMA table_info("{safe_table}");').fetchall()
                col_names = [c[1] for c in col_info]
                rows = cursor.execute(f'SELECT * FROM "{safe_table}" LIMIT 500;').fetchall()
                for r in rows:
                    row_pairs = [f"{col}={val}" for col, val in zip(col_names, r) if val is not None]
                    if row_pairs:
                        lines.append(f"[{table}] " + ", ".join(row_pairs))
        return "\n".join(lines)

    @classmethod
    def _flatten_obj(cls, obj: object, prefix: str = "") -> str:
        lines: List[str] = []
        if isinstance(obj, dict):
            for k, v in obj.items():
                key_path = f"{prefix}.{k}" if prefix else str(k)
                lines.append(cls._flatten_obj(v, key_path))
        elif isinstance(obj, list):
            for idx, item in enumerate(obj):
                lines.append(cls._flatten_obj(item, f"{prefix}[{idx}]"))
        else:
            lines.append(f'{prefix} = "{obj}"')
        return "\n".join(lines)

    def _is_excluded_from_backup(self, local_file: Path, rel_path: str) -> bool:
        """
        Checks NSURLIsExcludedFromBackupKey via extended attributes
        ('com.apple.MobileBackup') or Apple's backup exclusion plist metadata.
        """
        try:
            import os
            if hasattr(os, "listxattr") and hasattr(os, "getxattr"):
                attrs = os.listxattr(local_file)
                if "com.apple.MobileBackup" in attrs:
                    val = os.getxattr(local_file, "com.apple.MobileBackup")
                    if val in {b"1", b"\x01", b"true"}:
                        return True
        except OSError:
            pass

        # Fallback: check if parent directory itself carries the backup exclusion xattr
        parent = local_file.parent
        try:
            import os
            if hasattr(os, "getxattr"):
                val = os.getxattr(parent, "com.apple.MobileBackup")
                if val in {b"1", b"\x01", b"true"}:
                    return True
        except OSError:
            pass

        return False

    def _build_backup_finding(self, rel_path: str) -> Finding:
        return self.registry.build_finding(
            rule_id="TIR-IOS-DAST-003",
            location=f"AppSandbox/{rel_path}",
            evidence=(
                f"Sensitive file '{rel_path}' resides in a backup-eligible directory "
                "without NSURLIsExcludedFromBackupKey (com.apple.MobileBackup) set."
            ),
        )

    @staticmethod
    def _is_inspectable(file_path: Path) -> bool:
        if file_path.suffix.lower() in INSPECTABLE_EXTENSIONS:
            return True
        # Also inspect extensionless files under Library/Preferences or Documents
        return file_path.stat().st_size <= 2 * 1024 * 1024

    @staticmethod
    def _is_backup_eligible(rel_path: str) -> bool:
        normalized = rel_path.lstrip("/")
        if normalized.startswith("Library/Caches") or normalized.startswith("tmp"):
            return False
        return any(normalized.startswith(root) for root in BACKUP_ELIGIBLE_ROOTS)

    @staticmethod
    def _hash_directory(root_dir: Path) -> Dict[str, str]:
        hashes: Dict[str, str] = {}
        if not root_dir.exists():
            return hashes
        for path in root_dir.rglob("*"):
            if path.is_file():
                rel = path.relative_to(root_dir).as_posix()
                digest = hashlib.sha256(path.read_bytes()).hexdigest()
                hashes[rel] = digest
        return hashes

    @staticmethod
    def _redact(value: str) -> str:
        if len(value) <= 10:
            return value[:2] + "*" * (len(value) - 2)
        return f"{value[:4]}...{value[-4:]}"