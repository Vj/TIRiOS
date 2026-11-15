# Enterprise capabilities

This phase adds profile-driven assessments, local content-addressed evidence storage, report comparison, CI severity gating and profile discovery.

## Commands

- tir-ios profiles list — list bundled JSON profiles.
- tir-ios assessment app.ipa --profile profiles/enterprise-standard.json --source-dir ./Source --output-dir ./engagement-001 — run SAST and generate JSON plus configured HTML/PDF reports and evidence objects.
- tir-ios compare baseline.json current.json --output delta.json — classify new, resolved and persistent findings.
- tir-ios evidence add report.json --store ./evidence --assessment-id ENG-001 and tir-ios evidence verify --store ./evidence — store and verify SHA-256-addressed artifacts.
- tir-ios ci report.json --fail-on High — return exit code 1 when a finding meets or exceeds the configured severity.

## CI/CD

A typical pipeline runs tir-ios assessment, archives JSON/HTML/PDF and evidence outputs, then invokes tir-ios ci assessment.json --fail-on High. GitHub Actions and other runners can consume the process exit code without a hosted TIRiOS service.

## Evidence integrity and retention

Objects are stored under objects/<first-two-hash-chars>/<sha256>. The JSONL manifest records assessment ID, kind, original filename, size, timestamp and digest. Verification recomputes each digest. This local mechanism is not WORM storage and does not provide access control, encryption at rest, tenant isolation, legal retention or an immutable audit log. Production deployments should use access-controlled, backed-up storage and organization-managed retention and key-management policies.

## Orchestration scope

The assessment command orchestrates IPA-based SAST and report/evidence publication. DAST remains an explicit device-backed tir-ios dast-session workflow. A profile that enables DAST is rejected rather than silently producing a partial assessment. Run DAST on an authorized device, then merge its JSON with SAST using tir-ios merge before comparison and CI gating. Cross-stage scheduling and durable session state are future work.

## Comparison semantics

The first comparison version fingerprints a finding by finding ID, location and evidence. Changes to evidence or location can therefore appear as a resolved plus a new finding; this conservative approach avoids incorrectly claiming continuity. Risk acceptance, SLA ageing and trend analytics are not yet implemented.

## Profiles

Profiles are JSON configuration validated for supported keys, severity thresholds and positive DAST duration. Bundled examples are enterprise-standard.json and ci-strict.json. The settings map is reserved for organization metadata and does not yet alter scanner internals.
