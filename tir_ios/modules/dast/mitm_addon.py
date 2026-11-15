"""mitmproxy addon used by the unified DAST session.

Configuration is passed through environment variables by DASTSessionOrchestrator.
"""
import json
import os
from pathlib import Path

from tir_ios.core.models import RuntimeNetworkEvent
from tir_ios.modules.dast.proxy_auditor import ProxyTrafficAuditor
from tir_ios.modules.dast.traffic_correlator import TrafficCorrelator


class TIRiOSProxyAddon:
    def __init__(self):
        self.events_path = Path(os.environ.get("TIRIOS_RUNTIME_EVENTS", "tirios_runtime_events.json"))
        self.output_path = Path(os.environ.get("TIRIOS_PROXY_OUTPUT", "tirios_proxy_evidence.json"))
        self.auditor = ProxyTrafficAuditor()
        self.correlator = TrafficCorrelator()
        self._last_events = []
        self._flush()

    def _runtime_events(self):
        try:
            payload = json.loads(self.events_path.read_text(encoding="utf-8"))
            events = [RuntimeNetworkEvent(**item) for item in payload]
            self._last_events = events
        except (FileNotFoundError, json.JSONDecodeError, TypeError, ValueError):
            # Keep the last complete snapshot if an atomic replacement races a read.
            pass
        return self._last_events

    def tls_established_client(self, data):
        self.auditor.tls_established_client(data)
        self._flush()

    def request(self, flow):
        self.auditor.correlate_flow(flow, self._runtime_events(), self.correlator)
        self.auditor.request(flow)
        self._flush()

    def done(self):
        self._flush()

    def _flush(self):
        self.output_path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self.output_path.with_suffix(self.output_path.suffix + ".tmp")
        payload = {
            "schema_version": "1.1.0",
            "findings": [finding.to_dict() for finding in self.auditor.get_findings()],
            "observations": [item.to_dict() for item in self.auditor.get_observations()],
        }
        temporary.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        temporary.replace(self.output_path)


addons = [TIRiOSProxyAddon()]
