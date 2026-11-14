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

# Ignore Apple OS background telemetry domains during app proxy capture
APPLE_SYSTEM_DOMAINS = (
    ".apple.com",
    ".icloud.com",
    ".mzstatic.com",
    ".push.apple.com",
)


class ProxyTrafficAuditor:
    """
    Passive mitmproxy addon that records TLS pinning acceptance (TIR-IOS-DAST-020)
    and sensitive parameters exposed in URL query strings (TIR-IOS-DAST-021).
    """

    def __init__(
        self,
        output_json_path: Path | None = None,
        registry: RuleRegistry | None = None,
    ):
        self.output_json_path = Path(output_json_path) if output_json_path else None
        self.registry = registry or RuleRegistry.default()
        self._findings: List[Finding] = []
        self._seen: Set[Tuple[str, str]] = set()

    # --- mitmproxy Addon Event Hooks ---

    def tls_established_client(self, data: object) -> None:
        """
        Triggered when the mobile client completes a TLS handshake with mitmproxy's
        interception CA—indicating certificate/public-key pinning is not enforced
        for that destination SNI host.
        """
        try:
            context = getattr(data, "context", None)
            client_conn = getattr(context, "client", None)
            sni = getattr(client_conn, "sni", None) or ""
            if not sni or self._is_apple_domain(sni):
                return

            self._add_unique(
                rule_id="TIR-IOS-DAST-020",
                location=f"TLS Handshake -> https://{sni}",
                evidence=(
                    f"Target app accepted proxy-issued TLS certificate for '{sni}' "
                    "without triggering certificate or SPKI public-key pinning failure."
                ),
            )
        except Exception:
            pass

    def request(self, flow: object) -> None:
        """Inspects outgoing HTTP(S) request URLs and query parameters for data exposure."""
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

            # 1. Check for unencrypted cleartext HTTP requests
            if scheme.lower() == "http":
                self._add_unique(
                    rule_id="TIR-IOS-DAST-021",
                    location=endpoint,
                    evidence=f"Cleartext HTTP request transmitted to {endpoint}.",
                    title_suffix="(Cleartext HTTP Transmission)",
                    severity_override=Severity.HIGH,
                )

            # 2. Check URL query keys and values for tokens, credentials, or PII
            query = getattr(req, "query", None)
            if query:
                for key, val in query.items():
                    decoded_val = unquote(str(val))
                    self._inspect_query_param(endpoint, str(key), decoded_val)
        except Exception:
            pass

    def done(self) -> None:
        """Flushes collected findings to JSON when mitmproxy exits."""
        if self.output_json_path:
            self.export_findings(self.output_json_path)

    # --- Inspection & Export Helpers ---

    def _inspect_query_param(self, endpoint: str, key: str, value: str) -> None:
        if not value:
            return

        # Match sensitive parameter names (e.g., ?access_token=...)
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

        # Match JWTs or PII values regardless of parameter name
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

    def export_findings(self, out_path: Path) -> None:
        out_path.parent.mkdir(parents=True, exist_ok=True)
        payload = {"findings": [f.to_dict() for f in self._findings]}
        out_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")

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


# Entry point when invoked directly via `mitmdump -s tir_ios/modules/dast/proxy_auditor.py`
addons = [ProxyTrafficAuditor(output_json_path=Path("proxy_findings.json"))]