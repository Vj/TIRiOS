from pathlib import Path
import plistlib
import shutil
import tempfile
import zipfile
from typing import Dict, Any, Tuple


class IPAExtractionError(Exception):
    """Raised when an IPA archive is malformed or missing core bundle artifacts."""


class IPAWorkspace:
    def __init__(self, ipa_path: Path):
        self.ipa_path = Path(ipa_path).resolve()
        if not self.ipa_path.is_file():
            raise FileNotFoundError(f"IPA file not found: {self.ipa_path}")

        self._temp_dir = Path(tempfile.mkdtemp(prefix="tir_ios_"))
        self.app_dir: Path | None = None
        self.info_plist_path: Path | None = None
        self.info_plist: Dict[str, Any] = {}
        self.main_binary_path: Path | None = None

    def extract(self) -> Tuple[Path, Dict[str, Any], Path]:
        """Unzips the IPA and resolves (.app dir, parsed Info.plist, main Mach-O path)."""
        with zipfile.ZipFile(self.ipa_path, "r") as zf:
            # Guard against Zip Slip path traversal
            for member in zf.namelist():
                target = (self._temp_dir / member).resolve()
                if not str(target).startswith(str(self._temp_dir.resolve())):
                    raise IPAExtractionError(f"Unsafe archive entry detected: {member}")
            zf.extractall(self._temp_dir)

        payload_dir = self._temp_dir / "Payload"
        if not payload_dir.is_dir():
            raise IPAExtractionError("Invalid IPA: Missing 'Payload' directory.")

        app_bundles = list(payload_dir.glob("*.app"))
        if not app_bundles:
            raise IPAExtractionError("Invalid IPA: No .app bundle found inside Payload.")

        self.app_dir = app_bundles[0]
        self.info_plist_path = self.app_dir / "Info.plist"
        if not self.info_plist_path.is_file():
            raise IPAExtractionError("Invalid .app bundle: Missing Info.plist.")

        with open(self.info_plist_path, "rb") as f:
            self.info_plist = plistlib.load(f)

        executable_name = self.info_plist.get("CFBundleExecutable")
        if not executable_name:
            raise IPAExtractionError("Info.plist missing 'CFBundleExecutable' key.")

        self.main_binary_path = self.app_dir / executable_name
        if not self.main_binary_path.is_file():
            raise IPAExtractionError(f"Main Mach-O executable missing: {self.main_binary_path}")

        return self.app_dir, self.info_plist, self.main_binary_path

    def cleanup(self) -> None:
        if self._temp_dir.exists():
            shutil.rmtree(self._temp_dir, ignore_errors=True)

    def __enter__(self) -> "IPAWorkspace":
        self.extract()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.cleanup()