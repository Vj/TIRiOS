import json
import plistlib
from unittest.mock import patch

from tir_ios.core.ipa_extractor import IPAWorkspace
from tir_ios.core.models import Severity
from tir_ios.modules.sast.secrets_scan import SecretsScanner


def test_secrets_scanner_detects_regex_and_entropy_and_masks_values(
    build_sample_ipa, mock_macho_factory
):
    raw_aws_key = "AKIAIOSFODNN7EXAMPLE"
    raw_jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
    high_entropy_token = "9xK#mP2vL8qR4zW7nB5jT1yH6cF3dG0sA"

    bplist_config = plistlib.dumps(
        {"Backend": {"StagingEndpoint": "https://api.staging.internal.example.com/v1"}},
        fmt=plistlib.FMT_BINARY,
    )
    json_config = json.dumps(
        {
            "aws_key": raw_aws_key,
            "fallback_token": high_entropy_token,
        }
    ).encode("utf-8")

    ipa_path = build_sample_ipa(
        extra_files={
            "Config.plist": bplist_config,
            "env.json": json_config,
        }
    )

    macho_bin = mock_macho_factory(
        cstrings=[
            f"Bearer {raw_jwt}",
            "550e8400-e29b-41d4-a716-446655440000",  # UUID noise (must be ignored)
            "_$s7DemoApp14ViewControllerC",          # Swift mangled symbol noise (must be ignored)
        ]
    )

    with patch("tir_ios.modules.sast.secrets_scan.lief.MachO.parse", return_value=[macho_bin]):
        with IPAWorkspace(ipa_path) as ws:
            assert ws.app_dir and ws.main_binary_path
            scanner = SecretsScanner(ws.app_dir, ws.main_binary_path, entropy_threshold=4.5)
            findings = scanner.run_all()

    titles = [f.title for f in findings]
    all_evidence = "\n".join(f.evidence for f in findings)

    assert any("AWS Access Key ID" in t for t in titles)
    assert any("Hardcoded Bearer / JWT Token" in t for t in titles)
    assert any("Internal / Staging Backend URL" in t for t in titles)
    assert any("High-Entropy String" in t for t in titles)

    # Ensure raw secrets are redacted in evidence
    assert raw_aws_key not in all_evidence
    assert "AKIA...MPLE" in all_evidence
    assert raw_jwt not in all_evidence

    # Ensure noise filters suppressed UUID and Swift mangled symbol
    assert "550e8400" not in all_evidence
    assert "_$s7DemoApp" not in all_evidence


def test_shannon_entropy_calculation():
    assert SecretsScanner.shannon_entropy("") == 0.0
    assert SecretsScanner.shannon_entropy("aaaaaaaaaaaaaaaa") == 0.0
    assert SecretsScanner.shannon_entropy("aB9$kL2@pQ7!zX4&") == 4.0