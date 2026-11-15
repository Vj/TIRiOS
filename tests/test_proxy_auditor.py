from pathlib import Path
from types import SimpleNamespace

from tir_ios.core.models import TLSAssessment, TrafficAttribution
from tir_ios.modules.dast.proxy_auditor import ProxyTrafficAuditor


def test_tls_handshake_is_observation_not_pinning_finding():
    auditor = ProxyTrafficAuditor()
    data = SimpleNamespace(
        context=SimpleNamespace(
            client=SimpleNamespace(sni="api.example.test", id="conn-1")
        )
    )

    auditor.tls_established_client(data)

    assert auditor.get_findings() == []
    observations = auditor.get_observations()
    assert len(observations) == 1
    assert observations[0].assessment is TLSAssessment.TLS_HANDSHAKE_OBSERVED
    assert observations[0].attribution is TrafficAttribution.UNATTRIBUTED


def test_verified_pin_mismatch_bypass_creates_finding():
    auditor = ProxyTrafficAuditor()
    observation = auditor.record_pinning_test(
        host="api.example.test",
        expected_spki_sha256="aa" * 32,
        observed_spki_sha256="bb" * 32,
        baseline_request_succeeded=True,
        proxy_certificate_trusted=True,
        mismatch_request_succeeded=True,
        attribution=TrafficAttribution.APP_CONFIRMED,
        attribution_method="socket_tuple",
        bundle_id="com.example.app",
        process_id=1234,
        evidence="Controlled test request returned HTTP 200.",
    )

    assert observation.assessment is TLSAssessment.PINNING_BYPASS_VERIFIED
    assert len(auditor.get_findings()) == 1
    assert auditor.get_findings()[0].finding_id == "TIR-IOS-DAST-020"
    assert "differed from the configured expected pin" in auditor.get_findings()[0].evidence


def test_rejected_mismatched_pin_is_recorded_as_enforced_not_vulnerable():
    auditor = ProxyTrafficAuditor()
    observation = auditor.record_pinning_test(
        host="api.example.test",
        expected_spki_sha256="aa" * 32,
        observed_spki_sha256="bb" * 32,
        baseline_request_succeeded=True,
        proxy_certificate_trusted=True,
        mismatch_request_succeeded=False,
        attribution=TrafficAttribution.APP_CONFIRMED,
        bundle_id="com.example.app",
        process_id=1234,
    )

    assert observation.assessment is TLSAssessment.PINNING_ENFORCED
    assert auditor.get_findings() == []


def test_missing_baseline_or_trust_validation_is_inconclusive():
    auditor = ProxyTrafficAuditor()
    observation = auditor.record_pinning_test(
        host="api.example.test",
        expected_spki_sha256="aa" * 32,
        observed_spki_sha256="bb" * 32,
        baseline_request_succeeded=False,
        proxy_certificate_trusted=True,
        mismatch_request_succeeded=True,
    )

    assert observation.assessment is TLSAssessment.PINNING_TEST_INCONCLUSIVE
    assert auditor.get_findings() == []


def test_tls_observations_are_exported_separately(tmp_path: Path):
    auditor = ProxyTrafficAuditor()
    auditor.tls_established_client(
        SimpleNamespace(context=SimpleNamespace(
            client=SimpleNamespace(sni="api.example.test", id="conn-2")
        ))
    )
    target = tmp_path / "proxy.json"

    auditor.export_findings(target)

    import json
    payload = json.loads(target.read_text(encoding="utf-8"))
    assert payload["findings"] == []
    assert payload["observations"][0]["assessment"] == "TLS_HANDSHAKE_OBSERVED"
    assert payload["schema_version"] == "1.1.0"


def test_sensitive_query_parameter_detection_remains_available():
    auditor = ProxyTrafficAuditor()
    request = SimpleNamespace(
        pretty_host="api.example.test",
        scheme="https",
        path="/v1/login?access_token=secretvalue",
        query={"access_token": "secretvalue"},
    )

    auditor.request(SimpleNamespace(request=request))

    assert len(auditor.get_findings()) == 1
    assert auditor.get_findings()[0].finding_id == "TIR-IOS-DAST-021"


def test_unattributed_pin_mismatch_never_becomes_app_finding():
    auditor = ProxyTrafficAuditor()
    observation = auditor.record_pinning_test(
        host="api.example.test",
        expected_spki_sha256="aa" * 32,
        observed_spki_sha256="bb" * 32,
        baseline_request_succeeded=True,
        proxy_certificate_trusted=True,
        mismatch_request_succeeded=True,
        attribution=TrafficAttribution.DEVICE_LEVEL,
    )

    assert observation.assessment is TLSAssessment.PINNING_TEST_INCONCLUSIVE
    assert auditor.get_findings() == []


def test_malformed_spki_fingerprints_are_inconclusive():
    auditor = ProxyTrafficAuditor()
    observation = auditor.record_pinning_test(
        host="api.example.test",
        expected_spki_sha256="expected-pin",
        observed_spki_sha256="different-pin",
        baseline_request_succeeded=True,
        proxy_certificate_trusted=True,
        mismatch_request_succeeded=True,
        attribution=TrafficAttribution.APP_CONFIRMED,
        attribution_method="socket_tuple",
        bundle_id="com.example.app",
        process_id=1234,
    )

    assert observation.assessment is TLSAssessment.PINNING_TEST_INCONCLUSIVE
    assert auditor.get_findings() == []



def test_app_confirmed_label_without_socket_tuple_provenance_is_inconclusive():
    auditor = ProxyTrafficAuditor()
    observation = auditor.record_pinning_test(
        host="api.example.test",
        expected_spki_sha256="aa" * 32,
        observed_spki_sha256="bb" * 32,
        baseline_request_succeeded=True,
        proxy_certificate_trusted=True,
        mismatch_request_succeeded=True,
        attribution=TrafficAttribution.APP_CONFIRMED,
        bundle_id="com.example.app",
        process_id=1234,
    )

    assert observation.assessment is TLSAssessment.PINNING_TEST_INCONCLUSIVE
    assert auditor.get_findings() == []
