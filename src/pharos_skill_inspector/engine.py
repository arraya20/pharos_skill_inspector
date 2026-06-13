"""Scan engine: orchestrates the loader, analyzers, and scoring."""

from __future__ import annotations

from datetime import datetime, timezone

from .analyzers import Analyzer
from .analyzers.dangerous_code import DangerousCodeAnalyzer
from .analyzers.data_leakage import DataLeakageAnalyzer
from .analyzers.dependencies import DependencyAnalyzer
from .analyzers.javascript import JavaScriptAnalyzer
from .analyzers.pharos_web3 import PharosWeb3Analyzer
from .analyzers.prompt_injection import PromptInjectionAnalyzer
from .analyzers.solidity import SolidityAnalyzer
from .analyzers.taint import TaintAnalyzer
from .loader import has_executable, load
from .models import ScanResult
from .scoring import score_findings


def build_analyzers(use_network: bool = True) -> list[Analyzer]:
    return [
        PromptInjectionAnalyzer(),
        DataLeakageAnalyzer(),
        DangerousCodeAnalyzer(),
        JavaScriptAnalyzer(),
        SolidityAnalyzer(),
        DependencyAnalyzer(use_network=use_network),
        PharosWeb3Analyzer(),
        TaintAnalyzer(),
    ]


def _dedupe(findings):
    """Collapse identical findings (same rule, file, line)."""
    seen = set()
    out = []
    for f in findings:
        key = (f.rule_id, f.component, f.line, f.evidence)
        if key in seen:
            continue
        seen.add(key)
        out.append(f)
    return out


def scan(source: str, use_network: bool = True) -> ScanResult:
    """Scan a skill at ``source`` and return a populated :class:`ScanResult`."""
    skill = load(source)
    try:
        findings = []
        analyzers = build_analyzers(use_network=use_network)
        for analyzer in analyzers:
            try:
                findings.extend(analyzer.analyze(skill.components))
            except Exception as exc:  # one analyzer must not kill the scan
                skill.errors.append(f"{analyzer.name} failed: {exc}")

        findings = _dedupe(findings)
        # Sort: most severe first, then by file/line.
        findings.sort(key=lambda f: (-f.severity.rank, f.component, f.line))

        executable = has_executable(skill.components)
        score, severity, recommendation = score_findings(findings, executable)

        return ScanResult(
            skill_name=skill.name,
            source=skill.source,
            components=skill.components,
            findings=findings,
            risk_score=score,
            risk_severity=severity,
            recommendation=recommendation,
            scanned_at=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
            errors=skill.errors,
        )
    finally:
        skill.cleanup()
