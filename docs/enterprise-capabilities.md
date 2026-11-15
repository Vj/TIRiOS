# Enterprise capabilities

TIRiOS enterprise workflows are exposed as first-class CLI commands and can run from a local workstation or a CI runner.

## Profile-driven assessment

```bash
tir-ios profiles list
tir-ios assessment TargetApp.ipa --profile profiles/enterprise-standard.json --source-dir ./MyApp --output-dir ./engagement-001
```

A profile controls SAST/DAST phases, optional HTML/PDF generation, evidence collection, source scanning, DAST duration and the default CI severity threshold. The assessment command runs bundle-level SAST checks and, when enabled, starts the existing device-backed DAST orchestrator. For DAST profiles, supply `--bundle-id` and `--executable`; use `--udid` to select a device. DAST requires optional DAST dependencies, an authorized paired device, Frida setup and a test-device proxy configured for the host. Partial DAST session evidence is retained if collection fails.

```bash
tir-ios assessment TargetApp.ipa --profile profiles/enterprise-standard.json --bundle-id com.example.app --executable ExampleApp --udid DEVICE_UDID
```

## Evidence repository

Artifacts are stored by SHA-256 under `objects/<first-two-hash-chars>/<sha256>`. The JSONL manifest records assessment ID, artifact kind/name, size, timestamp and digest. Repeated identical artifacts reuse the same content object while retaining separate manifest entries.

```bash
tir-ios evidence add assessment.json --store ./evidence --assessment-id ENG-001
tir-ios evidence verify --store ./evidence
```

Verification recomputes each object's digest and rejects unsafe manifest paths. This local mechanism is an integrity aid, not WORM storage: it does not provide access control, tenant isolation, encryption at rest, immutable audit logs, backups or legal retention. Production deployments should use organization-managed storage and key/retention controls.

## Advanced reports

The assessment command emits normalized JSON and can render executive/technical HTML and PDF reports using the existing Jinja2/WeasyPrint engine. Install the optional reporting extra when either format is enabled: `python -m pip install -e ".[reporting]"`. Profiles used in minimal CI environments can disable HTML/PDF output and avoid native WeasyPrint dependencies.

## Assessment comparison

```bash
tir-ios compare baseline.json current.json --output delta.json
```

Findings are matched by rule ID and location. Comparison classifies new, resolved, changed (evidence/severity/metadata changed) and persistent findings. If multiple findings share the same rule ID and location, this initial identity model may group them; treat deltas as triage assistance rather than a replacement for analyst review.

## CI/CD integration

```bash
tir-ios assessment TargetApp.ipa --profile profiles/ci-strict.json --output-dir tirios-artifacts
tir-ios ci tirios-artifacts/assessment.json --profile profiles/ci-strict.json
```

The CI command returns exit code 1 when any finding meets or exceeds the selected threshold. `--fail-on` overrides the profile threshold. A sample GitHub Actions workflow is provided at `.github/workflows/tirios-security.yml`; it runs when an IPA is present in the checked-out repository and otherwise reports a skip. For other CI providers, invoke the same commands and archive the output directory as build artifacts.

## Enterprise profile examples

- `profiles/enterprise-standard.json`: SAST, HTML/PDF, evidence; High severity gate.
- `profiles/ci-strict.json`: SAST, evidence, no HTML/PDF dependency; Medium severity gate.

Profiles are validated for supported keys and basic value types. Organization-specific settings are preserved as metadata but do not currently alter individual scanner rules.
