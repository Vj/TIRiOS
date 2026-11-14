from pathlib import Path
from unittest.mock import patch
import pytest

from tir_ios.core.models import Severity
from tir_ios.modules.sast.macho_inspector import MachOInspector


def test_macho_hardened_binary_produces_no_findings(tmp_path: Path, mock_macho_factory):
    dummy_bin = tmp_path / "HardenedApp"
    dummy_bin.write_bytes(b"stub")

    hardened = mock_macho_factory(
        has_pie=True,
        imported_symbols=["___stack_chk_fail", "___stack_chk_guard", "_objc_release", "_swift_release"],
        has_encryption_info=True,
        crypt_id=1,
        cstrings=["https://api.example.com/v2/health"],
    )

    with patch("tir_ios.modules.sast.macho_inspector.lief.MachO.parse", return_value=[hardened]):
        inspector = MachOInspector(dummy_bin)
        findings = inspector.run_all()

    assert findings == []
    assert inspector.get_architectures() == ["ARM64"]


def test_macho_detects_missing_protections_and_weak_crypto(tmp_path: Path, mock_macho_factory):
    dummy_bin = tmp_path / "WeakApp"
    dummy_bin.write_bytes(b"stub")

    vulnerable = mock_macho_factory(
        has_pie=False,
        imported_symbols=["_strcpy", "_rand", "_CC_MD5"],
        has_encryption_info=True,
        crypt_id=0,
        cstrings=["kCCOptionECBMode"],
    )

    with patch("tir_ios.modules.sast.macho_inspector.lief.MachO.parse", return_value=[vulnerable]):
        inspector = MachOInspector(dummy_bin)
        findings = inspector.run_all()

    by_id = {f.finding_id: f for f in findings}

    assert "TIR-IOS-SAST-001" in by_id  # PIE disabled
    assert by_id["TIR-IOS-SAST-001"].severity == Severity.HIGH

    assert "TIR-IOS-SAST-002" in by_id  # Stack canaries absent
    assert "TIR-IOS-SAST-003" in by_id  # ARC disabled
    assert "TIR-IOS-SAST-004" in by_id  # cryptid = 0 (Info)
    assert by_id["TIR-IOS-SAST-004"].severity == Severity.INFO

    assert "TIR-IOS-SAST-005" in by_id  # _strcpy, _rand
    assert "_strcpy" in by_id["TIR-IOS-SAST-005"].evidence
    assert "_rand" in by_id["TIR-IOS-SAST-005"].evidence

    assert "TIR-IOS-SAST-006" in by_id  # CC_MD5 & kCCOptionECBMode
    assert "CC_MD5" in by_id["TIR-IOS-SAST-006"].evidence
    assert "kCCOptionECBMode" in by_id["TIR-IOS-SAST-006"].evidence