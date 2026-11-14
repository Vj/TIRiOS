import re
import threading
from typing import Dict, List, Set, Tuple

from tir_ios.core.device_bridge import IOSDeviceBridge
from tir_ios.core.models import Finding, Severity
from tir_ios.core.rule_registry import RuleRegistry


LOG_LEAK_PATTERNS: Dict[str, Tuple[re.Pattern[str], Severity | None]] = {
    "Bearer / Authorization Token in Logs": (
        re.compile(r"(?i)(?:authorization|bearer)\s*[:=]\s*['\"]?[A-Za-z0-9._\-]{16,}"),
        Severity.HIGH,
    ),
    "JWT Token Written to Syslog": (
        re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
        Severity.HIGH,
    ),
    "Password / Secret Parameter Logged": (
        re.compile(r"(?i)(?:password|passwd|pwd|secret|api_key|access_token)\s*[:=]\s*['\"]?[^\s&\"',}{]{6,}"),
        Severity.HIGH,
    ),
    "Email Address / PII in Plaintext Logs": (
        re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
        Severity.LOW,
    ),
}


class SyslogLeakMonitor:
    def __init__(
        self,
        bridge: IOSDeviceBridge,
        executable_name: str,
        registry: RuleRegistry | None = None,
    ):
        self.bridge = bridge
        self.executable_name = executable_name
        self.registry = registry or RuleRegistry.default()
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None
        self._findings: List[Finding] = []
        self._seen: Set[Tuple[str, str]] = set()
        self._lock = threading.Lock()

    def start(self) -> None:
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._watch_loop, daemon=True)
        self._thread.start()

    def stop(self) -> List[Finding]:
        self._stop_event.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=3.0)
        with self._lock:
            return list(self._findings)

    def _watch_loop(self) -> None:
        for line in self.bridge.stream_syslog(process_filter=self.executable_name):
            if self._stop_event.is_set():
                break
            self._inspect_line(line)

    def _inspect_line(self, line: str) -> None:
        for rule_name, (pattern, severity_override) in LOG_LEAK_PATTERNS.items():
            match = pattern.search(line)
            if not match:
                continue
            redacted = self._redact_snippet(match.group(0))
            key = (rule_name, redacted)
            with self._lock:
                if key in self._seen:
                    continue
                self._seen.add(key)
                self._findings.append(
                    self.registry.build_finding(
                        rule_id="TIR-IOS-DAST-001",
                        location=f"iOS Unified Log (Process: {self.executable_name})",
                        evidence=f"Matched pattern '{rule_name}': {redacted}",
                        title_suffix=f"({rule_name})",
                        severity_override=severity_override,
                    )
                )

    @staticmethod
    def _redact_snippet(text: str) -> str:
        if len(text) <= 12:
            return text[:4] + "****"
        return f"{text[:8]}...{text[-4:]}"