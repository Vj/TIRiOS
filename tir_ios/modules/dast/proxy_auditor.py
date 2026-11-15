import json
from pathlib import Path
import re
from typing import Dict, List, Set, Tuple
from urllib.parse import unquote

from tir_ios.core.models import Finding, Severity
from tir_ios.core.rule_registry import RuleRegistry


QUERY_LEAK_PATTERNS: Dict[str, Tuple[re.Pattern[str], Severity | None]] = {
    "JWT Token in URL Query": (
        re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
        Severity.HIGH,
    ),
    "Secret / Token Parameter in URL Query": (
        re.compile(r"(?i)^(?:password|passwd|pwd|secret|token|access_token|refresh_token|api_key|apikey|session_id)$"),
        Severity.MEDIUM,
    ),
    "Email / PII in URL Query": (
        re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
        Severity.LOW,
    ),
}

# Ignore Apple OS background telemetry domains during device-wide proxy capture.
APPLE_SYSTEM_DOMAINS = (
    ".apple.com",
    ".icloud.com",
    ".mzstatic.com",
    ".push.apple.com",
)


class ProxyTrafficAuditor:
    """
    Passive mitmproxy addon for TLS-interception observations and URL data exposure.

    Proxy events do not identify the originating iOS process. Set
    app_scope_verified=True only when the operator has independently isolated the
    capture to the assessed app. Set pinning_expected=True only when an independent
    test requirement says the observed host must reject the proxy certificate.
    """

    def __init__(
        self,
        output_json_path: Path | None = None,
        registry: RuleRegistry | None = None,
        app_scope_verified: bool = False,
        pinning_expected: bool = False,
    ):
        self.output_json_path = Path(output_json_path) if output_json_path else None
        self.registry = registry or RuleRegistry.default()
        self.app_scope_verified = app_scope_verified
        self.pinning_expected = pinning_expected
        self._findings: List[Finding] = []
        self._seen: Set[Tuple[str, str, str]] = set()
        self._errors: List[str] = []

    # --- mitmproxy Addon Event Hooks ---

    def tls_established_client(self, data: object) -> None:
        """
        Record a completed client-side TLS handshake with mitmproxy's certificate.

        A handshake is an interception observation for one host, not proof by
        itself that the assessed app is missing certificate pinning.
        """
        try:
            context = getattr(data, "context", None)
            client_conn = getattr(context, "client", None)
            sni = getattr(client_conn, "sni", None) or ""
            if not sni or self._is_apple_domain(sni):
                return

            pinning_gap_supported = self.app_scope_verified and self.pinning_expected
            self._add_unique(
                rule_id="TIR-IOS-DAST-020",
                location=f"TLS Handshake -> https://{sni}",
                evidence=(
                    f"mitmproxy completed the client-side TLS handshake using a proxy-issued "
                    f"certificate for '{sni}'. This establishes interception for this flow only; "
                    "it does not establish pinning behavior for other hosts or prove that this "
                    "host is required to reject the proxy certificate."
                ),
                title_suffix=(
                    "(Interception succeeded despite stated pinning expectation)"
                    if pinning_gap_supported
                    else "(Interception observation; pinning weakness not established)"
                ),
                severity_override=Severity.MEDIUM if pinning_gap_supported else Severity.INFO,
                cvss_override=5.9 if pinning_gap_supported else 0.0,
                confidence="Medium" if pinning_gap_supported else "High",
                evidence_source="mitmproxy client-side TLS handshake",
                verification_status=(
                    "Observed; interception succeeded despite an independently stated pinning expectation"
                    if pinning_gap_supported
                    else "Observed; pinning weakness not established"
                ),
            )
        except Exception as exc:
            self._record_error("tls_established_client", exc)

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

            # A device-wide capture cannot safely attribute this traffic to one app.
            if scheme.lower() == "http":
                self._add_unique(
                    rule_id="TIR-IOS-DAST-021",
                    location=endpoint,
                    evidence=f"Cleartext HTTP request observed at {endpoint}.",
                    title_suffix="(Cleartext HTTP Transmission)",
                    severity_override=Severity.HIGH,
                    cvss_override=7.5,
                    evidence_source="mitmproxy HTTP request event",
                )

            query = getattr(req, "query", None)
            if query:
                for key, val in query.items():
                    decoded_val = unquote(str(val))
                    self._inspect_query_param(endpoint, str(key), decoded_val)
        except Exception as exc:
            self._record_error("request", exc)

    def done(self) -> None:
        """Flush findings and non-fatal hook errors to JSON when mitmproxy exits."""
        if self.output_json_path:
            self.export_findings(self.output_json_path)

    # --- Inspection & Export Helpers ---

    def _inspect_query_param(self, endpoint: str, key: str, value: str) -> None:
        if not value:
            return

        key_pattern, key_severity = QUERY_LEAK_PATTERNS["Secret / Token Parameter in URL Query"]
        if key_pattern.match(key):
            self._add_unique(
                rule_id="TIR-IOS-DAST-021",
                location=endpoint,
                evidence=f"Sensitive query parameter '{key}={self._redact(value)}' observed in URL.",
                title_suffix=f"(Parameter: {key})",
                severity_override=key_severity,
                cvss_override=self._cvss_for_severity(key_severity),
                evidence_source="mitmproxy HTTP request event",
            )
            return

        for label in ("JWT Token in URL Query", "Email / PII in URL Query"):
            value_pattern, severity = QUERY_LEAK_PATTERNS[label]
            if value_pattern.search(value):
                self._add_unique(
                    rule_id="TIR-IOS-DAST-021",
                    location=endpoint,
                    evidence=f"{label} detected in query parameter '{key}={self._redact(value)}'.",
                    title_suffix=f"({label})",
                    severity_override=severity,
                    cvss_override=self._cvss_for_severity(severity),
                    evidence_source="mitmproxy HTTP request event",
                )

    def get_findings(self) -> List[Finding]:
        return list(self._findings)

    def get_errors(self) -> List[str]:
        """Return sanitized hook errors without exposing request contents or secrets."""
        return list(self._errors)

    def export_findings(self, out_path: Path) -> None:
        out_path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "findings": [finding.to_dict() for finding in self._findings],
            "errors": self.get_errors(),
        }
        out_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    def _add_unique(
        self,
        rule_id: str,
        location: str,
        evidence: str,
        title_suffix: str = "",
        severity_override: Severity | None = None,
        cvss_override: float | None = None,
        confidence: str | None = None,
        evidence_source: str = "mitmproxy traffic observation",
        verification_status: str | None = None,
    ) -> None:
        if self.app_scope_verified:
            evidence += " Capture scope was explicitly isolated to the assessed app by the operator."
            confidence = confidence or "High"
            verification_status = verification_status or "Observed in operator-verified target-app capture"
        else:
            evidence += (
                " The proxy event does not identify the originating app/process; "
                "attribution to the assessed app is unverified."
            )
            severity_override = Severity.INFO
            cvss_override = 0.0
            confidence = "Low"
            verification_status = "Observed; app attribution unverified"

        fingerprint = (rule_id, location, evidence)
        if fingerprint in self._seen:
            return
        self._seen.add(fingerprint)
        self._findings.append(
            self.registry.build_finding(
                rule_id=rule_id,
                location=location,
                evidence=evidence,
                title_suffix=title_suffix,
                severity_override=severity_override,
                cvss_override=cvss_override,
                confidence=confidence or "Unassessed",
                evidence_source=evidence_source,
                verification_status=verification_status or "Not Verified",
            )
        )

    def _record_error(self, hook: str, exc: Exception) -> None:
        # Exception messages may contain URLs or request data; retain type and hook only.
        entry = f"{hook}: {type(exc).__name__}"
        if entry not in self._errors:
            self._errors.append(entry)

    @staticmethod
    def _cvss_for_severity(severity: Severity | None) -> float:
        return {
            Severity.HIGH: 7.5,
            Severity.MEDIUM: 5.3,
            Severity.LOW: 3.1,
            Severity.INFO: 0.0,
            Severity.CRITICAL: 9.1,
        }.get(severity, 0.0)

    @staticmethod
    def _is_apple_domain(host: str) -> bool:
        lower = host.lower().strip(".")
        return any(lower == domain.lstrip(".") or lower.endswith(domain) for domain in APPLE_SYSTEM_DOMAINS)

    @staticmethod
    def _redact(value: str) -> str:
        if len(value) <= 8:
            return value[:2] + "****"
        return f"{value[:4]}...{value[-4:]}"


# mitmdump entry point: tir_ios/modules/dast/proxy_auditor.py
addons = [ProxyTrafficAuditor(output_json_path=Path("proxy_findings.json"))]
