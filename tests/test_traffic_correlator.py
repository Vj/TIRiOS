from tir_ios.core.models import RuntimeNetworkEvent, TLSAssessment, TLSObservation, TrafficAttribution
from tir_ios.modules.dast.traffic_correlator import ProxyEndpoint, TrafficCorrelator


def event(pid=321, bundle="com.example.target", ip="203.0.113.10", port=443, timestamp=1000.0):
    return RuntimeNetworkEvent(
        process_id=pid,
        bundle_id=bundle,
        timestamp=timestamp,
        destination_ip=ip,
        destination_port=port,
        socket_fd=12,
        local_ip="192.0.2.44",
        local_port=50123,
    )


def test_unique_endpoint_and_time_match_is_app_correlated_only():
    result = TrafficCorrelator().correlate(
        ProxyEndpoint("203.0.113.10", 443, 1000.5, "flow-1"),
        [event()],
    )

    assert result.attribution is TrafficAttribution.APP_CORRELATED
    assert result.bundle_id == "com.example.target"
    assert result.process_id == 321
    assert "not definitive" in result.rationale


def test_multiple_matching_connect_events_are_ambiguous():
    result = TrafficCorrelator().correlate(
        ProxyEndpoint("203.0.113.10", 443, 1000.0),
        [event(pid=321), event(pid=321, timestamp=1000.1)],
        device_level_capture=True,
    )

    assert result.attribution is TrafficAttribution.DEVICE_LEVEL
    assert result.matched_event_count == 2
    assert result.bundle_id is None


def test_destination_or_time_mismatch_does_not_attribute_to_app():
    result = TrafficCorrelator(time_window_seconds=1).correlate(
        ProxyEndpoint("203.0.113.11", 443, 1000.0),
        [event(timestamp=1005.0)],
        device_level_capture=True,
    )

    assert result.attribution is TrafficAttribution.DEVICE_LEVEL
    assert result.matched_event_count == 0


def test_invalid_proxy_ip_is_unattributed_without_device_capture():
    result = TrafficCorrelator().correlate(
        ProxyEndpoint("not-an-ip", 443, 1000.0),
        [event()],
    )

    assert result.attribution is TrafficAttribution.UNATTRIBUTED


def test_proxy_observation_accepts_correlation_but_never_app_confirms():
    from tir_ios.modules.dast.proxy_auditor import ProxyTrafficAuditor

    auditor = ProxyTrafficAuditor()
    auditor._observations.append(
        TLSObservation(
            host="api.example.test",
            assessment=TLSAssessment.TLS_HANDSHAKE_OBSERVED,
            connection_id="flow-2",
        )
    )
    correlation = TrafficCorrelator().correlate(
        ProxyEndpoint("203.0.113.10", 443, 1000.0, "flow-2"),
        [event()],
    )

    assert auditor.apply_traffic_correlation("flow-2", correlation)
    observation = auditor.get_observations()[0]
    assert observation.attribution is TrafficAttribution.APP_CORRELATED
    assert observation.bundle_id == "com.example.target"
    assert observation.process_id == 321


def test_no_proxy_observation_matches_unknown_connection():
    from tir_ios.modules.dast.proxy_auditor import ProxyTrafficAuditor

    auditor = ProxyTrafficAuditor()
    assert not auditor.apply_traffic_correlation("missing", object())



def test_exact_client_socket_tuple_confirms_app_process_attribution():
    result = TrafficCorrelator().correlate(
        ProxyEndpoint(
            "203.0.113.10", 443, 1000.0, "flow-socket",
            client_ip="192.0.2.44", client_port=50123,
        ),
        [event()],
    )

    assert result.attribution is TrafficAttribution.APP_CONFIRMED
    assert result.method == "socket_tuple"
    assert result.bundle_id == "com.example.target"
    assert result.process_id == 321


def test_exact_socket_tuple_is_ambiguous_when_multiple_process_events_match():
    result = TrafficCorrelator().correlate(
        ProxyEndpoint(
            "203.0.113.10", 443, 1000.0,
            client_ip="192.0.2.44", client_port=50123,
        ),
        [event(), event(pid=999, bundle="com.example.other")],
    )

    assert result.attribution is TrafficAttribution.UNATTRIBUTED
    assert result.matched_event_count == 2


def test_proxy_accepts_app_confirmed_only_for_exact_socket_tuple():
    from tir_ios.modules.dast.proxy_auditor import ProxyTrafficAuditor

    auditor = ProxyTrafficAuditor()
    auditor._observations.append(TLSObservation(host="api.example.test", connection_id="flow-3"))
    correlation = TrafficCorrelator().correlate(
        ProxyEndpoint("203.0.113.10", 443, 1000.0, "flow-3", "192.0.2.44", 50123),
        [event()],
    )

    assert auditor.apply_traffic_correlation("flow-3", correlation)
    assert auditor.get_observations()[0].attribution is TrafficAttribution.APP_CONFIRMED


def test_proxy_flow_helper_uses_client_peer_tuple_for_process_attribution():
    from types import SimpleNamespace
    from tir_ios.modules.dast.proxy_auditor import ProxyTrafficAuditor

    auditor = ProxyTrafficAuditor()
    auditor._observations.append(TLSObservation(host="api.example.test", connection_id="conn-9"))
    flow = SimpleNamespace(
        client_conn=SimpleNamespace(id="conn-9", peername=("192.0.2.44", 50123)),
        server_conn=SimpleNamespace(peername=("203.0.113.10", 443)),
        request=SimpleNamespace(timestamp_start=1000.0),
    )

    result = auditor.correlate_flow(flow, [event()], TrafficCorrelator())

    assert result.attribution is TrafficAttribution.APP_CONFIRMED
    assert auditor.get_observations()[0].attribution is TrafficAttribution.APP_CONFIRMED