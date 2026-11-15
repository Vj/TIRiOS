import json

from click.testing import CliRunner

from tir_ios.cli import cli


def test_enterprise_commands_are_registered_and_profiles_are_discoverable():
    result = CliRunner().invoke(cli, ["profiles", "list"])
    assert result.exit_code == 0, result.output
    assert "enterprise-standard" in result.output
    assert "ci-strict" in result.output


def test_ci_command_uses_profile_threshold(tmp_path):
    report = tmp_path / "assessment.json"
    report.write_text(json.dumps({"findings": [{"severity": "Medium"}]}), encoding="utf-8")
    profile = tmp_path / "profile.json"
    profile.write_text(json.dumps({"name": "strict", "fail_on": "Medium"}), encoding="utf-8")

    result = CliRunner().invoke(cli, ["ci", str(report), "--profile", str(profile)])
    assert result.exit_code == 1
    assert "FAIL: 1 findings at or above Medium" in result.output

    result = CliRunner().invoke(cli, ["ci", str(report), "--profile", str(profile), "--fail-on", "High"])
    assert result.exit_code == 0
    assert "PASS: 0 findings at or above High" in result.output
