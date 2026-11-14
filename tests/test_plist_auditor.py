import plistlib
from unittest.mock import patch

from tir_ios.core.ipa_extractor import IPAWorkspace
from tir_ios.core.models import Severity
from tir_ios.modules.sast.plist_auditor import PlistAuditor


def test_plist_auditor_flags_ats_schemes_permissions_and_debug_entitlement(
    build_sample_ipa, mock_macho_factory
):
    entitlements_xml = plistlib.dumps({"get-task-allow": True}, fmt=plistlib.FMT_XML)
    ipa_path = build_sample_ipa(
        info_plist_dict={
            "NSAppTransportSecurity": {
                "NSAllowsArbitraryLoads": True,
                "NSAllowsArbitraryLoadsInWebContent": True,
                "NSExceptionDomains": {
                    "legacy.example.com": {
                        "NSExceptionAllowsInsecureHTTPLoads": True,
                        "NSExceptionMinimumTLSVersion": "TLSv1.0",
                    }
                },
            },
            "CFBundleURLTypes": [{"CFBundleURLSchemes": ["demoapp", "demoapp-oauth"]}],
            "NSCameraUsageDescription": "Scan QR codes",
        }
    )

    signed_binary = mock_macho_factory(
        has_code_signature=True,
        code_sig_bytes=b"\xfa\xde\x0c\x01" + entitlements_xml,
    )

    with patch("tir_ios.modules.sast.plist_auditor.lief.MachO.parse", return_value=[signed_binary]):
        with IPAWorkspace(ipa_path) as ws:
            assert ws.app_dir and ws.main_binary_path
            auditor = PlistAuditor(ws.app_dir, ws.info_plist, ws.main_binary_path)
            findings = auditor.run_all()

    by_id = {f.finding_id: f for f in findings}

    assert "TIR-IOS-SAST-010" in by_id  # NSAllowsArbitraryLoads
    assert by_id["TIR-IOS-SAST-010"].severity == Severity.HIGH

    assert "TIR-IOS-SAST-011" in by_id  # NSAllowsArbitraryLoadsInWebContent
    assert "TIR-IOS-SAST-012" in by_id  # legacy.example.com ATS exception
    assert "legacy.example.com" in by_id["TIR-IOS-SAST-012"].title

    assert "TIR-IOS-SAST-013" in by_id  # URL schemes
    assert "demoapp-oauth" in by_id["TIR-IOS-SAST-013"].evidence

    assert "TIR-IOS-SAST-014" in by_id  # NSCameraUsageDescription
    assert "TIR-IOS-SAST-015" in by_id  # get-task-allow = true
    assert by_id["TIR-IOS-SAST-015"].severity == Severity.HIGH


def test_plist_auditor_clean_config_has_no_findings(build_sample_ipa, mock_macho_factory):
    entitlements_xml = plistlib.dumps({"get-task-allow": False}, fmt=plistlib.FMT_XML)
    ipa_path = build_sample_ipa(
        info_plist_dict={"NSAppTransportSecurity": {"NSAllowsArbitraryLoads": False}}
    )
    prod_binary = mock_macho_factory(
        has_code_signature=True,
        code_sig_bytes=b"\xfa\xde\x0c\x01" + entitlements_xml,
    )

    with patch("tir_ios.modules.sast.plist_auditor.lief.MachO.parse", return_value=[prod_binary]):
        with IPAWorkspace(ipa_path) as ws:
            assert ws.app_dir and ws.main_binary_path
            auditor = PlistAuditor(ws.app_dir, ws.info_plist, ws.main_binary_path)
            assert auditor.run_all() == []