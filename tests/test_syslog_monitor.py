import time
from unittest.mock import MagicMock

from tir_ios.core.models import Severity
from tir_ios.modules.dast.syslog_monitor import SyslogLeakMonitor


def test_syslog_monitor_captures_and_deduplicates_leaks():
    sample_logs = [
        "Nov 13 22:10:01 iPhone DemoApp[412] <Notice>: Auth header Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjoiYWRtaW4ifQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
        "Nov 13 22:10:02 iPhone DemoApp[412] <Notice>: Auth header Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjoiYWRtaW4ifQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
        "Nov 13 22:10:03 iPhone DemoApp[412] <Notice>: Login request user=alice@example.com password=SuperSecretPassword123",
        "Nov 13 22:10:04 iPhone DemoApp[412] <Notice>: UIViewController viewDidLoad completed",
    ]

    mock_bridge = MagicMock()
    mock_bridge.stream_syslog.return_value = iter(sample_logs)

    monitor = SyslogLeakMonitor(mock_bridge, executable_name="DemoApp")
    monitor.start()
    time.sleep(0.1)
    findings = monitor.stop()

    mock_bridge.stream_syslog.assert_called_once_with(process_filter="DemoApp")

    # Duplicate Bearer/JWT line should be deduplicated
    titles = [f.title for f in findings]
    assert len(findings) == 4
    assert any("Bearer / Authorization Token" in t for t in titles)
    assert any("JWT Token Written to Syslog" in t for t in titles)
    assert any("Password / Secret Parameter Logged" in t for t in titles)
    assert any("Email Address / PII" in t for t in titles)

    # Confirm raw password is redacted in evidence
    evidence_blob = "\n".join(f.evidence for f in findings)
    assert "SuperSecretPassword123" not in evidence_blob
    assert all(f.phase == "DAST" for f in findings)
    assert any(f.severity == Severity.HIGH for f in findings)