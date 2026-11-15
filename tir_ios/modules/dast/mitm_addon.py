"""mitmproxy addon used by the unified DAST session.

Configuration is passed through environment variables by DASTSessionOrchestrator.
"""
import json
import os
from pathlib import Path

from mitmproxy import ctx

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

    def request(self, flow):
        self.auditor.correlate_flow(flow, self._runtime_events(), self.correlator)
        self.auditor.request(flow)

    def done(self):
        self.auditor.export_findings(self.output_path)


addons = [TIRiOSProxyAddon()]
