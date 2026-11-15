import json
import logging
from pathlib import Path
import re
from typing import Dict, List, Set, Tuple
from urllib.parse import unquote
from datetime import datetime, timezone

from tir_ios.core.models import (
    EvidenceConfidence,
    Finding,
    Severity,
    TLSAssessment,
    TLSObservation,
    TrafficAttribution,
)
from tir_ios.core.rule_registry import RuleRegistry


logger = logging.getLogger(__name__)

QUERY_LEAK_PATTERNS: Dict[str, Tuple[re.Pattern[str], Severity | None]] = {
    "JWT Token in URL Query": (
        re.compile(r"\\beyJ[A-Za-z0-9_-]{10,}\\.[A-Za-z0-9_-]{10,}\\.[A-Za-z0-9_-]{10,}\\b"),
        Severity.HIGH,
    ),
    "Secret / Token Parameter in URL Query": (
        re.compile(r"(?i)^(?:password|passwd|pwd|secret|token|access_token|refresh_token|api_key|apikey|session_id)$"),
        Severity.MEDIUM,
    ),
    "Email / PII in URL Query": (
        re.compile(r"\\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}\\b"),
        Severity.LOW,
    ),
}

APPLE_SYSTEM_DOMAINS = (
    ".apple.com",
    ".icloud.com",
    ".mzstatic.com",
    ".push.apple.com",
)


class ProxyTrafficAuditor:
    """
    Passive mitmproxy addon for TLS observations and URL-query exposure.

    A completed client TLS handshake is deliberately recorded as an observation.
    It MUST NOT create TIR-IOS-DAST-020: the event does not establish that the
    app accepted a deliberately mismatched pin or that the traffic belongs to
    the target app.
    """

    def __init__(
        self,
        output_json_path: Path | None = None,
        registry: RuleRegistry | None = None,
    ):
        self.output_json_path = Path(output_json_path) if output_json_path else None
        self.registry = registry or RuleRegistry.default()
        self._findings: List[Finding] = []
        self._observations: List[TLSObservation] = []
        self._seen: Set[Tuple[str, str]] = set()
        self._seen_tls: Set[Tuple[str, str]] = set()

    def tls_established_client(self, data: object) -> None:
        """Record only that the client-side TLS handshake completed."""
        try:
            context = getattr(data, "context", None)
            client_conn = getattr(context, "client", None)
            sni = getattr(client_conn, "sni", None) or ""
            if not sni or self._is_apple_domain(sni):
                return

            connection_id = getattr(client_conn, "id", None)
            connection_id = str(connection_id) if connection_id is not None else None
            fingerprint = (sni.lower(), connection_id or "")
            if fingerprint in self._seen_tls:
                return
            self._seen_tls.add(fingerprint)

            self._observations.append(
                TLSObservation(
                    host=sni,
                    observed_at=datetime.now(timezone.utc).isoformat(),
                    assessment=TLSAssessment.TLS_HANDSHAKE_OBSERVED,
                    attribution=TrafficAttribution.UNATTRIBUTED,
                    connection_id=connection_id,
                    notes=(
                        "Client-side TLS handshake with the proxy completed. "
                        "This does not establish app attribution or test certificate pinning."
                    ),
                )
            )
        except Exception:
            logger.exception("Unable to record client TLS handshake observation")

    def record_pinning_test(
        self,
        *,
        host: str,
        expected_spki_sha256: str,
        observed_spki_sha256: str,
        baseline_request_succeeded: bool,
        proxy_certificate_trusted: bool,
        mismatch_request_succeeded: bool,
        attribution: TrafficAttribution = TrafficAttribution.UNATTRIBUTED,
        bundle_id: str | None = None,
        process_id: int | None = None,
        connection_id: str | None = None,
        evidence: str = "",
    ) -> TLSObservation:
        """
        Record an explicit controlled pin-mismatch test.

        A verified bypass requires a successful baseline, a trusted interception
        certificate, a genuine SPKI mismatch, and a successful app request while
        that mismatched certificate is presented. Missing any condition leaves
        the result inconclusive; no pinning finding is emitted.
        """
        expected = self._normalize_fingerprint(expected_spki_sha256)
        observed = self._normalize_fingerprint(observed_spki_sha256)
        mismatch = bool(expected and observed and expected != observed)
        verified_bypass = (
            mismatch
            and baseline_request_succeeded
            and proxy_certificate_trusted
            and mismatch_request_succeeded
        )

        if verified_bypass:
            assessment = TLSAssessment.PINNING_BYPASS_VERIFIED
            confidence = EvidenceConfidence.VERIFIED
        elif mismatch and baseline_request_succeeded and proxy_certificate_trusted and not mismatch_request_succeeded:
            assessment = TLSAssessment.PINNING_ENFORCED
            confidence = EvidenceConfidence.HIGH
        else:
            assessment = TLSAssessment.PINNING_TEST_INCONCLUSIVE
            confidence = EvidenceConfidence.LOW

        observation = TLSObservation(
            host=host,
            assessment=assessment,
            attribution=attribution,
            bundle_id=bundle_id,
            process_id=process_id,
            connection_id=connection_id,
            expected_spki_sha256=expected,
            observed_spki_sha256=observed,
            baseline_request_succeeded=baseline_request_succeeded,
            proxy_certificate_trusted=proxy_certificate_trusted,
            mismatch_request_succeeded=mismatch_request_succeeded,
            notes=f"confidence={confidence.value}; {evidence}".strip(),
        )
        self._observations.append(observation)

        if verified_bypass:
            attribution_note = f" Traffic attribution: {attribution.value}."
            self._add_unique(
                rule_id="TIR-IOS-DAST-020",
                location=f"TLS pin-mismatch test -> https://{host}",
                evidence=(
                    "Controlled pin-mismatch test verified that the application request "
                    "succeeded with a trusted interception certificate whose SPKI SHA-256 "
                    f"({observed}) differed from the configured expected pin ({expected})."
                    f"{attribution_note} {evidence}"
                ).strip(),
            )
        return observation

    def request(self, flow: object) -> None:
        """Inspect outgoing HTTP(S) request URLs and query parameters."""
        try:
            req = getattr(flow, "request", None)
            if req is None:
                return

            host = getattr(req, "pretty_host", "") or ""
            if not host or self._is_apple_domain(host):
                return

            scheme = getattr(req, "scheme", "https")
            path = getattr(req, "path", "/").split("?")[0]
            endpoint = f"{scheme}://{host}{path}"

            if scheme.lower() == "http":
                self._add_unique(
                    rule_id="TIR-IOS-DAST-021",
                    location=endpoint,
                    evidence=f"Cleartext HTTP request transmitted to {endpoint}.",
                    title_suffix="(Cleartext HTTP Transmission)",
                    severity_override=Severity.HIGH,
                )

            query = getattr(req, "query", None)
            if query:
                for key, val in query.items():
                    decoded_val = unquote(str(val))
                    self._inspect_query_param(endpoint, str(key), decoded_val)
        except Exception:
            logger.exception("Unable to inspect proxy request")

    def done(self) -> None:
        """Flush findings and observations to JSON when mitmproxy exits."""
        if self.output_json_path:
            self.export_findings(self.output_json_path)

    def _inspect_query_param(self, endpoint: str, key: str, value: str) -> None:
        if not value:
            return

        key_pattern, key_sev = QUERY_LEAK_PATTERNS["Secret / Token Parameter in URL Query"]
        if key_pattern.match(key):
            self._add_unique(
                rule_id="TIR-IOS-DAST-021",
                location=endpoint,
                evidence=f"Sensitive query parameter '{key}={self._redact(value)}' exposed in URL.",
                title_suffix=f"(Parameter: {key})",
                severity_override=key_sev,
            )
            return

        for label in ("JWT Token in URL Query", "Email / PII in URL Query"):
            val_pattern, val_sev = QUERY_LEAK_PATTERNS[label]
            if val_pattern.search(value):
                self._add_unique(
                    rule_id="TIR-IOS-DAST-021",
                    location=endpoint,
                    evidence=f"{label} detected in query parameter '{key}={self._redact(value)}'.",
                    title_suffix=f"({label})",
                    severity_override=val_sev,
                )

    def get_findings(self) -> List[Finding]:
        return list(self._findings)

    def get_observations(self) -> List[TLSObservation]:
        return list(self._observations)

    def export_findings(self, out_path: Path) -> None:
        out_path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "schema_version": "1.1.0",
            "findings": [f.to_dict() for f in self._findings],
            "observations": [o.to_dict() for o in self._observations],
        }
        out_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    @staticmethod
    def _normalize_fingerprint(value: str) -> str:
        return re.sub(r"[^a-fA-F0-9]", "", value or "").lower()

    def _add_unique(
        self,
        rule_id: str,
        location: str,
        evidence: str,
        title_suffix: str = "",
        severity_override: Severity | None = None,
    ) -> None:
        fp = (rule_id, location, evidence)
        if fp in self._seen:
            return
        self._seen.add(fp)
        self._findings.append(
            self.registry.build_finding(
                rule_id=rule_id,
                location=location,
                evidence=evidence,
                title_suffix=title_suffix,
                severity_override=severity_override,
            )
        )

    @staticmethod
    def _is_apple_domain(host: str) -> bool:
        lower = host.lower().strip(".")
        return any(lower == d.lstrip(".") or lower.endswith(d) for d in APPLE_SYSTEM_DOMAINS)

    @staticmethod
    def _redact(value: str) -> str:
        if len(value) <= 8:
            return value[:2] + "****"
        return f"{value[:4]}...{value[-4:]}"


addons = [ProxyTrafficAuditor(output_json_path=Path("proxy_findings.json"))]
