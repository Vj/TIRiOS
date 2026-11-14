# TIRiOS — Threat Inspection & Response for iOS

**TIRiOS** is a modular, cross-platform Python Vulnerability Assessment and Penetration Testing (VAPT) framework for iOS applications. Designed as the iOS counterpart to **TIR**, it performs automated Static Application Security Testing (SAST), Dynamic Application Security Testing (DAST), passive network traffic auditing, and executive PDF/JSON reporting aligned with the **OWASP Mobile Application Security Verification Standard (MASVS v2.0)** and **OWASP MASTG**.

---

## Key Capabilities

### 1. Static Application Security Testing (SAST)
Runs natively on **Windows, macOS, and Linux** without requiring Xcode or macOS-specific command-line utilities (`otool`, `plutil`):
- **Mach-O Binary Inspection (`lief`):** Verifies Position Independent Executable (`MH_PIE`), Stack Smashing Protection (`___stack_chk_fail` / `___stack_chk_guard`), Automatic Reference Counting (`_objc_release` / `_swift_release`), FairPlay DRM encryption flags (`LC_ENCRYPTION_INFO`), insecure C/PRNG imports (`strcpy`, `sprintf`, `gets`, `rand`), and weak cryptographic algorithms/modes (`MD5`, `SHA-1`, `DES`, `3DES`, `RC4`, `ECB`).
- **Configuration & Entitlements Auditing (`plistlib` + `lief`):** Audits `Info.plist` for App Transport Security (`NSAppTransportSecurity`) exceptions, exposed custom URL schemes (`CFBundleURLTypes`), privacy usage descriptions, and debuggable entitlements (`get-task-allow`) embedded in the Mach-O code signature or `embedded.mobileprovision`.
- **Secrets & Entropy Scanner:** Scans Mach-O string sections (`__cstring`, `__ustring`, `__cfstring`), binary/XML `.plist` files, and bundled `.json`/`.js`/`.strings`/`.config` assets using deterministic secret signatures and Shannon entropy analysis with automatic secret redaction.

### 2. Dynamic Application Security Testing (DAST)
Connects to test iOS hardware over USB/Wi-Fi via **`pymobiledevice3`** (`usbmuxd`), **`Frida`**, and **`mitmproxy`**:
- **Unified Log / `NSLog` Leak Monitor:** Streams live device `syslog` entries filtered by `CFBundleExecutable` to flag runtime credential, token, or PII leakage (`MASTG-TEST-0053`).
- **Sandbox Storage & Backup Diffing:** Captures pre- and post-session snapshots of the app sandbox container via `HouseArrestService`, inspects newly created/modified SQLite, CoreData, Realm, and binary `.plist` files for plaintext secrets (`MASTG-TEST-0051`), and verifies `NSURLIsExcludedFromBackupKey` (`com.apple.MobileBackup`) attributes (`MASTG-TEST-0057`).
- **Runtime IPC & Platform Instrumentation (`Frida`):** Passively observes `WKWebView` JavaScript bridges and `allowFileAccessFromFileURLs`, `LAContext` biometric policy usage (`SecAccessControlCreateWithFlags` binding), global `UIPasteboard` writes, Keychain accessibility attributes (`SecItemAdd` / `SecItemUpdate`), background UI snapshot masking, and jailbreak/anti-debugging defense telemetry.
- **Passive Proxy Traffic Auditor (`mitmproxy`):** Audits TLS certificate pinning acceptance (`tls_established_client`), cleartext HTTP traffic, and sensitive credentials or PII transmitted in URL query parameters.

### 3. Standardized Compliance & Reporting
- **Centralized OWASP MASVS v2.0 Registry:** All rules (`TIR-IOS-SAST-*` and `TIR-IOS-DAST-*`) map to OWASP MASVS v2.0 categories, MASTG test IDs, CWE identifiers, and CVSS v3.1 scores in `tir_ios/rules/masvs_registry.json`.
- **Unified Merging & WeasyPrint PDF Reports:** Combines SAST, DAST, and proxy findings into a deduplicated JSON report and renders a print-ready executive VAPT PDF report.

---

## Project Structure

```text
tir_ios/
├── pyproject.toml
├── README.md
├── tir_ios/
│   ├── cli.py                          # Click CLI entry point (scan, dast, merge)
│   ├── core/
│   │   ├── device_bridge.py            # pymobiledevice3 / usbmuxd device bridge
│   │   ├── ipa_extractor.py            # Zip-Slip-safe .ipa extractor & bundle resolver
│   │   ├── models.py                   # Finding & ScanReport data models
│   │   └── rule_registry.py            # OWASP MASVS v2.0 JSON rule loader
│   ├── modules/
│   │   ├── sast/
│   │   │   ├── macho_inspector.py      # LIEF Mach-O header, symbol & crypto checks
│   │   │   ├── plist_auditor.py        # ATS, URL schemes, permissions & entitlements
│   │   │   └── secrets_scan.py         # Regex & Shannon entropy secret scanner
│   │   └── dast/
│   │       ├── agents/
│   │       │   ├── audit_agent.js      # Frida agent: WKWebView, LAContext, Pasteboard
│   │       │   └── resilience_agent.js # Frida agent: Keychain ACLs, Snapshots, JB/Debug
│   │       ├── frida_runner.py         # Frida orchestrator for runtime IPC/auth checks
│   │       ├── keychain_auditor.py     # Keychain accessibility & snapshot evaluator
│   │       ├── proxy_auditor.py        # Passive mitmproxy addon for TLS & URL query checks
│   │       ├── resilience_auditor.py   # Runtime resilience & defense evaluator
│   │       ├── storage_monitor.py      # Sandbox container diff & SQLite/plist scanner
│   │       └── syslog_monitor.py       # Live Unified Log PII/token leak detector
│   ├── reporting/
│   │   ├── merger.py                   # Deduplicated multi-phase report merger
│   │   ├── pdf_generator.py            # Jinja2 + WeasyPrint HTML-to-PDF generator
│   │   └── templates/
│   │       └── report.html.j2          # Print-ready executive report template
│   └── rules/
│       └── masvs_registry.json         # Rule-to-MASVS v2.0 / MASTG / CVSS mapping
└── tests/                              # Cross-platform pytest unit test suite
```

---

## Installation

### Prerequisites
- **Python 3.11+**
- **System libraries for WeasyPrint** (for PDF generation):
  - **macOS:** `brew install pango libffi`
  - **Ubuntu/Debian:** `sudo apt-get install -y libpango-1.0-0 libpangocairo-1.0-0 libgdk-pixbuf2.0-0 libffi-dev shared-mime-info`
  - **Windows:** Install the GTK3 runtime or follow the [WeasyPrint Windows installation guide](https://doc.courtbouillon.org/weasyprint/stable/first_steps.html#windows).
- **For DAST (Optional):** An authorized iOS test device connected via USB with developer pairing enabled (`usbmuxd`), `frida-server` running on the device (or `FridaGadget.dylib` embedded for non-jailbroken testing), and `mitmproxy` installed on the host.

### Setup

```bash
git clone <your-repo-url> tir_ios
cd tir_ios

python -m venv .venv
source .venv/bin/activate        # On Windows: .venv\Scripts\activate

pip install -e ".[dev]"
```

---

## Usage

### 1. Static Analysis (`tir-ios scan`)
Analyze an `.ipa` package and generate JSON and/or executive PDF reports:

```bash
# Output JSON report only
tir-ios scan TargetApp.ipa -o sast_report.json

# Output both JSON and executive PDF reports
tir-ios scan TargetApp.ipa -o sast_report.json --pdf TIRiOS_SAST_Report.pdf
tir-ios scan TargetApp.ipa -o sast_report.json --pdf TIRiOS_SAST_Report.pdf
tir-ios scan C:\Users\ADMIN\Downloads\DVIA-v2 --pdf TIRiOS_SAST_Report.pdf
```
# Generate JSON + HTML + PDF in one scan
tir-ios scan "C:\Users\ADMIN\Downloads\DVIA-v2\DVIA-v2.ipa" -o DVIA_SAST.json --html TIRiOS_SAST_Report.html --pdf TIRiOS_SAST_Report.pdf

# Or generate only HTML (requires zero native PDF/GTK dependencies)
tir-ios scan "C:\Users\ADMIN\Downloads\DVIA-v2\DVIA-v2.ipa" --html TIRiOS_SAST_Report.html

### 2. Dynamic Analysis (`tir-ios dast`)
Connect an authorized iOS test device over USB and run live `syslog` monitoring, sandbox container storage diffing, and Frida runtime checks:

```bash
tir-ios dast com.example.targetapp \
  --executable TargetApp \
  --duration 90 \
  -o dast_report.json
```

### 3. Passive Network Traffic Auditing (`mitmdump`)
Configure your test iOS device's Wi-Fi HTTP proxy to point to your workstation (`<HOST_IP>:8080`) with the `mitmproxy` CA certificate trusted, then run:

```bash
mitmdump -p 8080 -s tir_ios/modules/dast/proxy_auditor.py
```
When stopped (`Ctrl+C`), findings are exported automatically to `proxy_findings.json`.

### 4. Merge SAST, DAST & Proxy Reports (`tir-ios merge`)
Combine findings from multiple testing phases into a single deduplicated JSON and executive PDF report:

```bash
tir-ios merge sast_report.json dast_report.json proxy_findings.json \
  -o final_audit.json \
  --pdf TIRiOS_Final_VAPT_Report.pdf
```

---

## Running Unit Tests

All SAST and log-monitoring unit tests use synthetic Mach-O stubs and temporary `.ipa` fixtures, requiring no physical iOS device:

```bash
pytest -v
```

---

## OWASP MASVS v2.0 Coverage Matrix

| Rule ID | Phase | Domain | OWASP MASVS v2.0 | MASTG ID | Default Severity |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `TIR-IOS-SAST-001` | SAST | Position Independent Executable (PIE) | `MASVS-RESILIENCE-1` | `MASTG-TEST-0086` | High |
| `TIR-IOS-SAST-002` | SAST | Stack Smashing Canaries | `MASVS-CODE-2` | `MASTG-TEST-0087` | Medium |
| `TIR-IOS-SAST-003` | SAST | Automatic Reference Counting (ARC) | `MASVS-CODE-2` | `MASTG-TEST-0088` | Medium |
| `TIR-IOS-SAST-004` | SAST | FairPlay Binary Encryption (`cryptid`) | `MASVS-RESILIENCE-3` | `MASTG-TEST-0085` | Info |
| `TIR-IOS-SAST-005` | SAST | Insecure C / Weak PRNG APIs | `MASVS-CODE-2` | `MASTG-TEST-0089` | Low |
| `TIR-IOS-SAST-006` | SAST | Weak Cryptographic Algorithms / Modes | `MASVS-CRYPTO-1` | `MASTG-TEST-0061` | High |
| `TIR-IOS-SAST-010..012` | SAST | App Transport Security (ATS) Exceptions | `MASVS-NETWORK-1` | `MASTG-TEST-0065` | High / Medium |
| `TIR-IOS-SAST-013..014` | SAST | Custom URL Schemes & Privacy Permissions | `MASVS-PLATFORM-1` | `MASTG-TEST-0074..75` | Low / Info |
| `TIR-IOS-SAST-015` | SAST | Debuggable Entitlement (`get-task-allow`) | `MASVS-RESILIENCE-2` | `MASTG-TEST-0084` | High |
| `TIR-IOS-SAST-020..021` | SAST | Hardcoded Secrets & High-Entropy Strings | `MASVS-STORAGE-1` | `MASTG-TEST-0052` | Critical / Medium |
| `TIR-IOS-DAST-001` | DAST | Unified Log / `NSLog` PII & Token Leakage | `MASVS-STORAGE-2` | `MASTG-TEST-0053` | High |
| `TIR-IOS-DAST-002` | DAST | Plaintext Sensitive Data in Sandbox Storage | `MASVS-STORAGE-1` | `MASTG-TEST-0051` | High |
| `TIR-IOS-DAST-003` | DAST | Missing `NSURLIsExcludedFromBackupKey` | `MASVS-STORAGE-2` | `MASTG-TEST-0057` | Medium |
| `TIR-IOS-DAST-004` | DAST | Weak Keychain Accessibility Attributes | `MASVS-STORAGE-1` | `MASTG-TEST-0051` | Medium |
| `TIR-IOS-DAST-005` | DAST | Unmasked Background UI Snapshot | `MASVS-STORAGE-2` | `MASTG-TEST-0056` | Low |
| `TIR-IOS-DAST-010..011` | DAST | `WKWebView` JS Bridges & File Access | `MASVS-PLATFORM-2` | `MASTG-TEST-0077` | High / Medium |
| `TIR-IOS-DAST-012` | DAST | `LAContext` Biometrics Without Keychain ACL | `MASVS-AUTH-2` | `MASTG-TEST-0064` | Medium |
| `TIR-IOS-DAST-013` | DAST | Unrestricted Global `UIPasteboard` Writes | `MASVS-STORAGE-2` | `MASTG-TEST-0055` | Low |
| `TIR-IOS-DAST-020` | DAST | Missing / Bypassable TLS Pinning | `MASVS-NETWORK-2` | `MASTG-TEST-0067` | Medium |
| `TIR-IOS-DAST-021` | DAST | Cleartext HTTP / Sensitive URL Query Params | `MASVS-NETWORK-1` | `MASTG-TEST-0066` | High / Medium |
| `TIR-IOS-DAST-030..031` | DAST | Jailbreak & Anti-Debugging Resilience | `MASVS-RESILIENCE-1..2` | `MASTG-TEST-0081..83` | Low |

---

## Disclaimer
**TIRiOS** is intended strictly for authorized security assessments, internal application security testing, and compliance auditing on applications and devices for which you hold explicit written permission.