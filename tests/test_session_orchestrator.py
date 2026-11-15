import subprocess

import pytest

from tir_ios.modules.dast.session_orchestrator import DASTSessionError, DASTSessionOrchestrator


def test_session_rejects_non_positive_duration():
    with pytest.raises(ValueError, match="duration"):
        DASTSessionOrchestrator("com.example.app", "Example", duration=0)


def test_session_rejects_invalid_proxy_port():
    with pytest.raises(ValueError, match="proxy_port"):
        DASTSessionOrchestrator("com.example.app", "Example", proxy_port=70000)


def test_proxy_startup_fails_fast_when_mitmdump_exits():
    orchestrator = DASTSessionOrchestrator("com.example.app", "Example", proxy_port=8080)

    class ExitedProcess:
        returncode = 2

        @staticmethod
        def poll():
            return 2

    with pytest.raises(DASTSessionError, match="exited during startup"):
        orchestrator._wait_for_proxy(ExitedProcess(), timeout=0.01)


def test_session_report_path_is_normalized(tmp_path):
    target = tmp_path / "reports" / "session.json"
    orchestrator = DASTSessionOrchestrator(
        "com.example.app", "Example", output=target, duration=1
    )

    assert orchestrator.output == target
    assert orchestrator.duration == 1
