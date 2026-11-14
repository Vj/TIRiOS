from pathlib import Path
import plistlib
from unittest.mock import MagicMock
import zipfile
import lief
import pytest


@pytest.fixture
def mock_macho_factory():
    """Creates a synthetic lief.MachO.Binary stub with configurable flags, symbols, and __cstring data."""

    def _create(
        has_pie: bool = True,
        imported_symbols: list[str] | None = None,
        has_encryption_info: bool = True,
        crypt_id: int = 1,
        cstrings: list[str] | None = None,
        has_code_signature: bool = False,
        code_sig_bytes: bytes = b"",
    ) -> MagicMock:
        binary = MagicMock()
        binary.header.cpu_type = lief.MachO.Header.CPU_TYPE.ARM64
        binary.header.has.side_effect = lambda flag: (
            has_pie if flag == lief.MachO.Header.FLAGS.PIE else False
        )

        sym_objs = []
        for sym_name in imported_symbols or []:
            s = MagicMock()
            s.name = sym_name
            sym_objs.append(s)
        binary.imported_symbols = sym_objs

        binary.has_encryption_info = has_encryption_info
        binary.encryption_info.crypt_id = crypt_id

        section = MagicMock()
        section.name = "__cstring"
        raw_cstrings = b"\x00".join(s.encode("utf-8") for s in (cstrings or [])) + b"\x00"
        section.content = list(raw_cstrings)
        binary.sections = [section]

        binary.has_code_signature = has_code_signature
        binary.code_signature.content = list(code_sig_bytes)

        return binary

    return _create


@pytest.fixture
def build_sample_ipa(tmp_path: Path):
    """Builds a valid .ipa archive on disk with binary Info.plist, dummy Mach-O, and optional extra assets."""

    def _build(
        info_plist_dict: dict | None = None,
        extra_files: dict[str, bytes] | None = None,
        executable_name: str = "DemoApp",
    ) -> Path:
        base_plist = {
            "CFBundleName": "DemoApp",
            "CFBundleDisplayName": "Demo App",
            "CFBundleIdentifier": "com.example.demoapp",
            "CFBundleShortVersionString": "1.2.0",
            "CFBundleExecutable": executable_name,
            "MinimumOSVersion": "15.0",
        }
        if info_plist_dict:
            base_plist.update(info_plist_dict)

        ipa_path = tmp_path / "DemoApp.ipa"
        app_prefix = "Payload/DemoApp.app"

        with zipfile.ZipFile(ipa_path, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr(f"{app_prefix}/Info.plist", plistlib.dumps(base_plist, fmt=plistlib.FMT_BINARY))
            zf.writestr(f"{app_prefix}/{executable_name}", b"\xcf\xfa\xed\xfe" + b"\x00" * 64)
            for rel_path, content in (extra_files or {}).items():
                zf.writestr(f"{app_prefix}/{rel_path}", content)

        return ipa_path

    return _build