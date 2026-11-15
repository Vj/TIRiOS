from tir_ios.modules.dast.frida_runner import FridaRuntimeAuditor


def test_frida_network_event_is_retained_for_target_bundle():
    runner = FridaRuntimeAuditor.__new__(FridaRuntimeAuditor)
    runner.bundle_id = "com.example.target"
    runner._network_events = []
    payload = {
        "category": "TIR_NETWORK_EVENT",
        "process_id": 4321,
        "bundle_id": "com.example.target",
        "timestamp": 1234.5,
        "destination_ip": "203.0.113.10",
        "destination_port": 443,
        "socket_fd": 18,
        "local_ip": "192.0.2.44",
        "local_port": 50123,
        "syscall": "connect",
    }

    runner._on_message({"type": "send", "payload": payload}, None)

    assert len(runner.network_events) == 1
    event = runner.network_events[0]
    assert event.process_id == 4321
    assert event.bundle_id == "com.example.target"
    assert event.local_ip == "192.0.2.44"
    assert event.local_port == 50123


def test_frida_network_event_from_other_bundle_is_ignored():
    runner = FridaRuntimeAuditor.__new__(FridaRuntimeAuditor)
    runner.bundle_id = "com.example.target"
    runner._network_events = []
    runner._on_message({
        "type": "send",
        "payload": {
            "category": "TIR_NETWORK_EVENT",
            "process_id": 99,
            "bundle_id": "com.example.other",
            "timestamp": 1234.5,
            "destination_ip": "203.0.113.10",
            "destination_port": 443,
        },
    }, None)

    assert runner.network_events == []


def test_malformed_frida_network_event_is_ignored_safely():
    runner = FridaRuntimeAuditor.__new__(FridaRuntimeAuditor)
    runner.bundle_id = "com.example.target"
    runner._network_events = []
    runner._on_message({
        "type": "send",
        "payload": {"category": "TIR_NETWORK_EVENT", "bundle_id": "com.example.target"},
    }, None)

    assert runner.network_events == []
