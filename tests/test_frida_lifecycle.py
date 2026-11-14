from pathlib import Path

import pytest

frida = pytest.importorskip("frida")

from tir_ios.modules.dast.frida_runner import FridaRuntimeAuditor
from tir_ios.modules.dast.resilience_auditor import ResilienceRuntimeAuditor


class FakeScript:
    def __init__(self, *, fail_load=False):
        self.fail_load = fail_load
        self.unloaded = False
        self.exports_sync = self

    def on(self, *_args):
        pass

    def load(self):
        if self.fail_load:
            raise RuntimeError("script load failed")

    def unload(self):
        self.unloaded = True

    def get_telemetry_summary(self):
        return {}


class FakeSession:
    def __init__(self, script):
        self.script = script
        self.detached = False

    def create_script(self, _source):
        return self.script

    def detach(self):
        self.detached = True


class FakeDevice:
    def __init__(self, session):
        self.session = session
        self.resumed = []
        self.attached = []

    def spawn(self, _argv):
        return 4242

    def attach(self, target):
        self.attached.append(target)
        return self.session

    def resume(self, pid):
        self.resumed.append(pid)


@pytest.mark.parametrize("auditor_type", [FridaRuntimeAuditor, ResilienceRuntimeAuditor])
def test_spawned_process_is_resumed_and_session_detached_when_script_load_fails(
    auditor_type, tmp_path: Path, monkeypatch
):
    agent = tmp_path / "agent.js"
    agent.write_text("// test agent", encoding="utf-8")
    script = FakeScript(fail_load=True)
    session = FakeSession(script)
    device = FakeDevice(session)
    monkeypatch.setattr(frida, "get_usb_device", lambda timeout=5: device)

    auditor = auditor_type(bundle_id="com.example.test", agent_path=agent)

    with pytest.raises(RuntimeError, match="script load failed"):
        auditor.start(spawn=True)

    assert device.resumed == [4242]
    assert session.detached
    assert script.unloaded
    assert auditor._session is None
    assert auditor._script is None


@pytest.mark.parametrize("auditor_type", [FridaRuntimeAuditor, ResilienceRuntimeAuditor])
def test_stop_releases_successfully_started_spawned_process(auditor_type, tmp_path: Path, monkeypatch):
    agent = tmp_path / "agent.js"
    agent.write_text("// test agent", encoding="utf-8")
    script = FakeScript()
    session = FakeSession(script)
    device = FakeDevice(session)
    monkeypatch.setattr(frida, "get_usb_device", lambda timeout=5: device)

    auditor = auditor_type(bundle_id="com.example.test", agent_path=agent)
    auditor.start(spawn=True)
    auditor.stop()

    assert device.resumed == [4242]
    assert session.detached
    assert script.unloaded
