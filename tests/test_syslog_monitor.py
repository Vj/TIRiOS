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

    # The repeated JWT log entry should produce one unique finding.
    titles = [finding.title for finding in findings]
    assert len(findings) == 3
    assert sum("JWT Token Written to Syslog" in title for title in titles) == 1
    assert sum("Password / Secret Parameter Logged" in title for title in titles) == 1
    assert sum("Email Address / PII" in title for title in titles) == 1

    # Confirm raw password is redacted in evidence.
    evidence_blob = "\n".join(finding.evidence for finding in findings)
    assert "SuperSecretPassword123" not in evidence_blob
    assert all(finding.phase == "DAST" for finding in findings)
    assert any(finding.severity == Severity.HIGH for finding in findings)
