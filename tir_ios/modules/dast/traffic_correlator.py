"""Conservative correlation between Frida socket events and proxy flows.

Destination/time matching is useful evidence, but it is not a cryptographic or
unique flow identifier. This module therefore never returns APP_CONFIRMED.
"""
from dataclasses import dataclass
from ipaddress import ip_address
from typing import Iterable

from tir_ios.core.models import RuntimeNetworkEvent, TrafficAttribution


@dataclass(frozen=True)
class ProxyEndpoint:
    destination_ip: str
    destination_port: int
    timestamp: float
    connection_id: str | None = None
    client_ip: str | None = None
    client_port: int | None = None


@dataclass(frozen=True)
class TrafficCorrelation:
    attribution: TrafficAttribution
    bundle_id: str | None = None
    process_id: int | None = None
    matched_event_count: int = 0
    connection_id: str | None = None
    method: str = "none"
    rationale: str = ""


class TrafficCorrelator:
    """Match proxy endpoints to Frida-observed connect() events conservatively."""

    def __init__(self, time_window_seconds: float = 2.0):
        if time_window_seconds <= 0:
            raise ValueError("time_window_seconds must be positive")
        self.time_window_seconds = float(time_window_seconds)

    @staticmethod
    def _normalize_ip(value: str) -> str:
        return str(ip_address(value))

    def correlate(
        self,
        proxy: ProxyEndpoint,
        runtime_events: Iterable[RuntimeNetworkEvent],
        *,
        device_level_capture: bool = False,
    ) -> TrafficCorrelation:
        try:
            proxy_ip = self._normalize_ip(proxy.destination_ip)
        except ValueError:
            return TrafficCorrelation(
                TrafficAttribution.DEVICE_LEVEL if device_level_capture else TrafficAttribution.UNATTRIBUTED,
                connection_id=proxy.connection_id,
                rationale="Proxy destination is not a valid IP address.",
            )

        events = list(runtime_events)
        # An exact local socket tuple maps a process-owned TCP socket to the
        # peer endpoint accepted by mitmproxy. This is stronger than timing.
        if proxy.client_ip and proxy.client_port is not None:
            try:
                client_ip = self._normalize_ip(proxy.client_ip)
            except ValueError:
                client_ip = ""
            exact = [
                event for event in events
                if event.local_ip and event.local_port is not None
                and self._normalize_ip(event.local_ip) == client_ip
                and event.local_port == proxy.client_port
            ]
            if len(exact) == 1:
                event = exact[0]
                return TrafficCorrelation(
                    attribution=TrafficAttribution.APP_CONFIRMED,
                    bundle_id=event.bundle_id,
                    process_id=event.process_id,
                    matched_event_count=1,
                    connection_id=proxy.connection_id,
                    method="socket_tuple",
                    rationale="Unique exact local IP:port match between the Frida-observed app socket and mitmproxy client peer endpoint.",
                )
            if len(exact) > 1:
                return TrafficCorrelation(
                    attribution=TrafficAttribution.UNATTRIBUTED,
                    matched_event_count=len(exact),
                    connection_id=proxy.connection_id,
                    method="ambiguous_socket_tuple",
                    rationale="Multiple runtime sockets matched the client tuple; app attribution is ambiguous.",
                )

        candidates = []
        for event in events:
            try:
                event_ip = self._normalize_ip(event.destination_ip)
            except ValueError:
                continue
            if (
                event_ip == proxy_ip
                and event.destination_port == proxy.destination_port
                and abs(event.timestamp - proxy.timestamp) <= self.time_window_seconds
            ):
                candidates.append(event)

        if len(candidates) == 1:
            event = candidates[0]
            return TrafficCorrelation(
                attribution=TrafficAttribution.APP_CORRELATED,
                bundle_id=event.bundle_id,
                process_id=event.process_id,
                matched_event_count=1,
                connection_id=proxy.connection_id,
                method="destination_time",
                rationale=(
                    "Exactly one target-process connect() event matched destination IP, "
                    "port, and time window. This is correlation, not definitive socket-to-flow identity."
                ),
            )

        if len(candidates) > 1:
            return TrafficCorrelation(
                attribution=TrafficAttribution.DEVICE_LEVEL if device_level_capture else TrafficAttribution.UNATTRIBUTED,
                matched_event_count=len(candidates),
                connection_id=proxy.connection_id,
                method="ambiguous_destination_time",
                rationale="Multiple runtime socket events matched; app attribution is ambiguous.",
            )

        return TrafficCorrelation(
            attribution=TrafficAttribution.DEVICE_LEVEL if device_level_capture else TrafficAttribution.UNATTRIBUTED,
            connection_id=proxy.connection_id,
            rationale="No runtime socket event matched the proxy endpoint and time window.",
        )
