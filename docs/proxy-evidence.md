# Proxy evidence model

TIRiOS separates network observations from security conclusions.

## TLS handshake is not a pinning verdict

A completed mitmproxy client-side TLS handshake is recorded as a
`TLS_HANDSHAKE_OBSERVED` observation. It does not, by itself, prove that:

- the traffic originated from the target app;
- the app accepted a deliberately mismatched certificate pin;
- all app endpoints or networking stacks were tested; or
- certificate pinning is absent.

The observation is exported under `observations`, not `findings`.

## Conditions for a verified pinning bypass

The current explicit `record_pinning_test()` evidence API emits
`TIR-IOS-DAST-020` only when all of these conditions are true:

1. A baseline request to the same target succeeds.
2. The interception certificate is trusted by the platform trust evaluation.
3. The observed SPKI SHA-256 digest is valid and differs from the expected pin.
4. The application request succeeds while that mismatched SPKI is presented.
5. Traffic attribution is `APP_CONFIRMED`.

If any condition is missing, the result remains
`PINNING_TEST_INCONCLUSIVE`. If a trusted, mismatched pin is rejected after a
successful baseline, it is recorded as `PINNING_ENFORCED`.

This is intentionally conservative. An untrusted proxy CA being rejected proves
ordinary certificate trust validation, not necessarily certificate pinning.
Likewise, a trusted proxy CA being accepted is not proof that pinning is absent
unless a controlled, genuine pin mismatch has been exercised.

## Attribution

Attribution is explicit and is never inferred from SNI:

- `UNATTRIBUTED`: no reliable process or app association.
- `DEVICE_LEVEL`: traffic is known to come from the test device, but not the app.
- `APP_CORRELATED`: evidence correlates the flow with the app, but does not
  conclusively identify its process.
- `APP_CONFIRMED`: process/bundle-level evidence confirms the app generated
  the flow.

The current passive mitmproxy hook records handshakes as `UNATTRIBUTED`.
Frida/process correlation is a follow-on integration; do not manually promote
traffic to app-confirmed without supporting runtime evidence.

## Export format

Proxy JSON now includes `schema_version: 1.1.0`, `findings`, and
`observations`. TLS observations include timestamp, host, assessment,
confidence, attribution, optional bundle/PID/connection identifiers, expected
and observed SPKI hashes, and baseline/interception request outcomes.

Consumers should treat the new `observations` collection as additive and
continue reading `findings` as the vulnerability list.
