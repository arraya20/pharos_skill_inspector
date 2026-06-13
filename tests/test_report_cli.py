"""Tests for report renderers and the CLI entrypoint."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from pharos_skill_inspector import cli, report
from pharos_skill_inspector.models import Category, Finding, ScanResult, Severity

EXAMPLES = Path(__file__).resolve().parent.parent / "examples"


def _sample_result() -> ScanResult:
    findings = [
        Finding("W001", "Hardcoded Private Key", Severity.CRITICAL, Category.PHAROS_WEB3,
                "key found", component="scripts/x.py", line=10, evidence="0xdead…REDACTED…beef",
                recommendation="rotate", confidence=0.95),
        Finding("SC001", "Unpinned Dependency", Severity.LOW, Category.SUPPLY_CHAIN,
                "web3 unpinned | pipe", component="requirements.txt", line=2,
                evidence="web3", recommendation="pin it", confidence=0.7),
    ]
    return ScanResult(
        skill_name="demo", source="./demo", components=[],
        findings=findings, risk_score=88, risk_severity=Severity.CRITICAL,
        recommendation="DO NOT INSTALL", scanned_at="2026-06-13 00:00:00 UTC",
    )


# --- report renderers ------------------------------------------------------
def test_render_json_roundtrips():
    d = json.loads(report.render(_sample_result(), "json"))
    assert d["risk_score"] == 88
    assert d["counts_by_severity"]["CRITICAL"] == 1
    assert len(d["findings"]) == 2


def test_render_markdown_contains_table_and_escapes_pipes():
    md = report.render(_sample_result(), "markdown")
    assert "# Pharos Skill Inspector Report" in md
    assert "DO NOT INSTALL" in md
    assert "W001" in md
    # a pipe in the message must be escaped so the table isn't broken
    assert "web3 unpinned \\| pipe" in md


def test_render_sarif_is_valid_and_levels_map():
    doc = json.loads(report.render(_sample_result(), "sarif"))
    run = doc["runs"][0]
    assert doc["version"] == "2.1.0"
    assert len(run["results"]) == 2
    levels = {r["ruleId"]: r["level"] for r in run["results"]}
    assert levels["W001"] == "error" and levels["SC001"] == "note"
    # every result references a declared rule
    declared = {r["id"] for r in run["tool"]["driver"]["rules"]}
    assert {"W001", "SC001"} <= declared


def test_render_terminal_color_toggle():
    colored = report.render(_sample_result(), "terminal", color=True)
    plain = report.render(_sample_result(), "terminal", color=False)
    assert "\033[" in colored
    assert "\033[" not in plain
    assert "88/100" in plain


def test_render_terminal_no_findings():
    r = ScanResult(skill_name="empty", source="x", risk_severity=Severity.INFO,
                   recommendation="SAFE", scanned_at="t")
    out = report.render(r, "terminal", color=False)
    assert "No issues detected" in out


# --- CLI -------------------------------------------------------------------
def test_cli_scan_json_stdout(capsys):
    code = cli.main(["scan", str(EXAMPLES / "benign-skill"), "--no-network", "--format", "json"])
    out = capsys.readouterr().out
    assert code == 0
    assert json.loads(out)["recommendation"] == "SAFE"


def test_cli_scan_writes_output_file(tmp_path, capsys):
    dest = tmp_path / "r.sarif"
    code = cli.main(["scan", str(EXAMPLES / "malicious-skill"), "--no-network",
                     "--format", "sarif", "-o", str(dest)])
    assert code == 0
    doc = json.loads(dest.read_text())
    assert doc["version"] == "2.1.0"
    assert "Report written to" in capsys.readouterr().out


def test_cli_fail_on_high_returns_1():
    code = cli.main(["scan", str(EXAMPLES / "malicious-skill"), "--no-network",
                     "--no-color", "--fail-on", "high"])
    assert code == 1


def test_cli_fail_on_high_safe_skill_returns_0():
    code = cli.main(["scan", str(EXAMPLES / "benign-skill"), "--no-network",
                     "--no-color", "--fail-on", "high"])
    assert code == 0


def test_cli_nonexistent_path_returns_2(capsys):
    code = cli.main(["scan", "/tmp/psi_definitely_missing_xyz", "--no-network"])
    assert code == 2
    assert "error:" in capsys.readouterr().err


def test_cli_version_exits_zero(capsys):
    with pytest.raises(SystemExit) as exc:
        cli.main(["--version"])
    assert exc.value.code == 0
    assert "pharos-skill-inspector" in capsys.readouterr().out


def test_cli_markdown_format_stdout(capsys):
    code = cli.main(["scan", str(EXAMPLES / "malicious-skill"), "--no-network", "--format", "markdown"])
    assert code == 0
    assert "# Pharos Skill Inspector Report" in capsys.readouterr().out
