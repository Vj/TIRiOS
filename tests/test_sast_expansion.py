import plistlib

from tir_ios.core.models import Severity
from tir_ios.modules.sast.sast_expansion import SASTExpansion


def test_privacy_manifest_absence_is_info_not_compliance_verdict(tmp_path):
    app = tmp_path / "Demo.app"
    app.mkdir()
    findings = SASTExpansion(app, {}).run_all()
    privacy = next(f for f in findings if f.finding_id == "TIR-IOS-SAST-030")
    assert privacy.severity == Severity.INFO
    assert "not by itself proof" in privacy.evidence


def test_privacy_manifest_detects_malformed_declarations(tmp_path):
    app = tmp_path / "Demo.app"
    app.mkdir()
    (app / "PrivacyInfo.xcprivacy").write_bytes(plistlib.dumps({"NSPrivacyTracking": "yes"}))
    findings = SASTExpansion(app, {}).run_all()
    privacy = next(f for f in findings if f.finding_id == "TIR-IOS-SAST-030")
    assert "unexpected types" in privacy.evidence


def test_sdk_inventory_does_not_claim_vulnerability(tmp_path):
    app = tmp_path / "Demo.app"
    framework = app / "Frameworks" / "FirebaseCore.framework"
    framework.mkdir(parents=True)
    findings = SASTExpansion(app, {}).run_all()
    sdk = next(f for f in findings if f.finding_id == "TIR-IOS-SAST-031")
    assert sdk.severity == Severity.INFO
    assert "no vulnerable version" in sdk.evidence


def test_oauth_missing_state_and_pkce_is_review_finding(tmp_path):
    app = tmp_path / "Demo.app"
    app.mkdir()
    source = tmp_path / "Sources"
    source.mkdir()
    (source / "Login.swift").write_text("let url = URL(string: \"https://idp.test/oauth2/authorize\")!")
    findings = SASTExpansion(app, {}, source).run_all()
    oauth = next(f for f in findings if f.finding_id == "TIR-IOS-SAST-032")
    assert "state validation" in oauth.evidence
    assert "PKCE S256" in oauth.evidence


def test_custom_scheme_and_weak_crypto_source_are_detected(tmp_path):
    app = tmp_path / "Demo.app"
    app.mkdir()
    source = tmp_path / "Sources"
    source.mkdir()
    (source / "App.m").write_text("CC_MD5(data, len, digest);\n")
    info = {"CFBundleURLTypes": [{"CFBundleURLSchemes": ["demo-auth"]}]}
    findings = SASTExpansion(app, info, source).run_all()
    assert any(f.finding_id == "TIR-IOS-SAST-033" for f in findings)
    crypto = next(f for f in findings if f.finding_id == "TIR-IOS-SAST-034")
    assert "MD5" in crypto.evidence
