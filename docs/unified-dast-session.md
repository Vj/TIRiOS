# Unified DAST session

The unified runner coordinates the existing TIRiOS runtime collectors with a managed
mitmproxy process and writes one JSON evidence report.

## Install

Install the DAST extras and ensure the mitmproxy executable is on PATH:

```bash
pip install -e ".[dast]"
```

## Run

```bash
tir-ios dast-session com.example.app --executable ExampleApp \
  --duration 180 --proxy-port 8080 --output dast-session.json
```

The runner starts mitmproxy, captures a sandbox baseline, starts syslog and Frida
instrumentation, attaches the resilience auditor, and then collects for the requested
duration. Frida socket events are published as atomic snapshots for the proxy addon.
The proxy addon correlates each HTTP flow with the available runtime events and records
TLS handshake observations separately from findings. Shutdown is coordinated and partial
evidence is retained if a collector fails.

## Required device-side proxy setup

TIRiOS starts the proxy listener but does **not** change iOS network settings. Before
the exercise, configure the test iPhone's active Wi-Fi network to use a manual HTTP
proxy pointing to the host running TIRiOS and the selected proxy port. The host firewall
must allow inbound connections to that port.

For HTTPS interception, install and explicitly trust the mitmproxy CA on the test device.
Only intercept traffic for applications and systems you are authorized to assess.
A completed TLS handshake remains an observation; it is not proof that certificate
pinning is absent. A verified pinning result still requires a controlled mismatch test
and strong app-process attribution as described in [proxy evidence semantics](proxy-evidence.md).

## Report

The output contains:

- `metadata`: device, duration, proxy listener, baseline count and session error state
- `findings`: normalized DAST findings from runtime, syslog, storage and proxy checks
- `proxy_observations`: TLS observations with confidence and attribution fields

A session error is recorded in the report and also returned as a non-zero CLI exit.
The runner currently correlates BSD TCP `connect()` events. Network.framework,
QUIC/UDP, app extensions and request-level attribution inside multiplexed HTTP/2
or HTTP/3 connections are not guaranteed by this version.
