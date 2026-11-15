# Phase 3 – SAST expansion

Phase 3 adds source and bundle heuristics for Swift/Objective-C, Apple privacy manifests,
SDK inventory, OAuth/deep-link review and cryptographic API usage.

## Scan an IPA

```bash
tir-ios scan app.ipa --output report.json
```

The scanner inspects bundle privacy manifests, known SDK framework names, custom URL
schemes and the app's shipped source-like files if present. Most production IPAs do not
contain Swift or Objective-C source; binary symbol/string analysis is not equivalent to
source analysis.

## Scan with the Xcode source tree

```bash
tir-ios scan app.ipa --source-dir ./MyApp --output report.json
```

Supported source extensions include Swift, Objective-C, Objective-C++, C and C++.
Source rules are heuristic indicators and should be triaged against full call paths.

## Coverage notes

- Privacy manifest absence is informational because applicability depends on API use and
  current Apple requirements. The scanner checks parseability and declaration key types;
  it does not yet validate Apple's evolving reason-code catalog or SDK signature.
- SDK recognition is a name-based inventory, not a CVE/version or malware verdict.
- OAuth state/PKCE detection is heuristic and may miss wrapper/library implementations.
- Deep-link custom scheme findings request validation review; a registered scheme alone
  is not proof of a takeover or authorization bypass.
- Crypto matches identify source references; they do not prove sensitive data is protected
  by the matched primitive.
