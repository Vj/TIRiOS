from pathlib import Path
import zipfile
import pytest

from tir_ios.core.ipa_extractor import IPAExtractionError, IPAWorkspace


def test_ipa_workspace_extracts_and_cleans_up(build_sample_ipa):
    ipa_path = build_sample_ipa()
    extracted_dir = None

    with IPAWorkspace(ipa_path) as ws:
        extracted_dir = ws._temp_dir
        assert ws.app_dir is not None and ws.app_dir.is_dir()
        assert ws.main_binary_path is not None and ws.main_binary_path.is_file()
        assert ws.info_plist["CFBundleIdentifier"] == "com.example.demoapp"

    assert extracted_dir is not None and not extracted_dir.exists()


def test_ipa_workspace_blocks_zip_slip(tmp_path: Path):
    malicious_ipa = tmp_path / "malicious.ipa"
    with zipfile.ZipFile(malicious_ipa, "w") as zf:
        zf.writestr("../../evil.txt", b"traversal")

    ws = IPAWorkspace(malicious_ipa)
    try:
        with pytest.raises(IPAExtractionError, match="Unsafe archive entry"):
            ws.extract()
    finally:
        ws.cleanup()


def test_ipa_workspace_missing_payload_raises(tmp_path: Path):
    bad_ipa = tmp_path / "no_payload.ipa"
    with zipfile.ZipFile(bad_ipa, "w") as zf:
        zf.writestr("README.txt", b"not an ipa")

    with pytest.raises(IPAExtractionError, match="Missing 'Payload'"):
        with IPAWorkspace(bad_ipa):
            pass