"""Report renderers: terminal, JSON, Markdown, SARIF."""

from __future__ import annotations

import json

from .models import ScanResult, Severity

# ANSI colors for terminal output.
_COLORS = {
    "CRITICAL": "\033[1;91m",
    "HIGH": "\033[91m",
    "MEDIUM": "\033[93m",
    "LOW": "\033[94m",
    "INFO": "\033[90m",
    "RESET": "\033[0m",
    "BOLD": "\033[1m",
    "DIM": "\033[2m",
}


def _c(text: str, key: str, color: bool) -> str:
    if not color:
        return text
    return f"{_COLORS.get(key, '')}{text}{_COLORS['RESET']}"


def render_terminal(result: ScanResult, color: bool = True) -> str:
    L = []
    L.append("")
    L.append(_c("  Pharos Skill Inspector — Security Report", "BOLD", color))
    L.append("  " + "─" * 54)
    L.append(f"  Skill         : {result.skill_name}")
    L.append(f"  Source        : {result.source}")
    L.append(f"  Scanned       : {result.scanned_at}")
    L.append("")

    sev = result.risk_severity.value
    L.append(_c("  Risk Assessment", "BOLD", color))
    L.append(f"    Score         : {result.risk_score}/100")
    L.append(f"    Severity      : {_c(sev, sev, color)}")
    rec = result.recommendation
    rec_key = "CRITICAL" if rec == "DO NOT INSTALL" else ("MEDIUM" if rec == "CAUTION" else "LOW")
    L.append(f"    Recommendation: {_c(rec, rec_key, color)}")
    L.append("")

    counts = result.counts_by_severity()
    summary = "  ".join(
        f"{s}: {counts[s]}" for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO") if counts[s]
    ) or "no issues"
    L.append(f"  Findings ({len(result.findings)}): {summary}")
    L.append("")

    # Components table
    L.append(_c(f"  Components ({len(result.components)})", "BOLD", color))
    for comp in result.components:
        flag = "exec" if comp.executable else "    "
        L.append(f"    [{flag}] {comp.kind:11s} {comp.lines:>5} ln  {comp.path}")
    L.append("")

    if not result.findings:
        L.append(_c("  No issues detected.", "LOW", color))
    else:
        L.append(_c("  Issues", "BOLD", color))
        for f in result.findings:
            sv = f.severity.value
            L.append("")
            L.append(f"  {_c(sv, sv, color)} [{f.rule_id}] {f.title}  "
                     + _c(f"({f.category.value})", "DIM", color))
            loc = f"{f.component}:{f.line}" if f.line else f.component
            L.append(f"    Location  : {loc}")
            L.append(f"    Detail    : {f.message}")
            if f.evidence:
                L.append(f"    Evidence  : {f.evidence}")
            if f.recommendation:
                L.append(f"    Fix       : {f.recommendation}")
            L.append(f"    Confidence: {int(f.confidence * 100)}%")

    if result.errors:
        L.append("")
        L.append(_c("  Scan notes", "DIM", color))
        for e in result.errors:
            L.append(f"    - {e}")
    L.append("")
    return "\n".join(L)


def render_json(result: ScanResult) -> str:
    return json.dumps(result.to_dict(), indent=2)


def render_markdown(result: ScanResult) -> str:
    L = []
    L.append(f"# Pharos Skill Inspector Report — `{result.skill_name}`")
    L.append("")
    L.append(f"- **Source:** `{result.source}`")
    L.append(f"- **Scanned:** {result.scanned_at}")
    L.append(f"- **Risk score:** {result.risk_score}/100 ({result.risk_severity.value})")
    L.append(f"- **Recommendation:** **{result.recommendation}**")
    counts = result.counts_by_severity()
    L.append(f"- **Findings:** "
             + ", ".join(f"{s} {counts[s]}" for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")))
    L.append("")

    L.append("## Components")
    L.append("")
    L.append("| File | Kind | Lines | Executable |")
    L.append("|------|------|-------|------------|")
    for c in result.components:
        L.append(f"| `{c.path}` | {c.kind} | {c.lines} | {'yes' if c.executable else 'no'} |")
    L.append("")

    L.append("## Findings")
    L.append("")
    if not result.findings:
        L.append("No issues detected. ✅")
    else:
        L.append("| Severity | ID | Title | Location | Detail |")
        L.append("|----------|----|-------|----------|--------|")
        for f in result.findings:
            loc = f"`{f.component}:{f.line}`" if f.line else f"`{f.component}`"
            detail = f.message.replace("|", "\\|")
            L.append(f"| {f.severity.value} | {f.rule_id} | {f.title} | {loc} | {detail} |")
    L.append("")
    return "\n".join(L)


_SARIF_LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}


def render_sarif(result: ScanResult) -> str:
    rules = {}
    sarif_results = []
    for f in result.findings:
        rules.setdefault(f.rule_id, {
            "id": f.rule_id,
            "name": f.title,
            "shortDescription": {"text": f.title},
            "properties": {"category": f.category.value},
        })
        sarif_results.append({
            "ruleId": f.rule_id,
            "level": _SARIF_LEVEL[f.severity],
            "message": {"text": f.message},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": f.component},
                    "region": {"startLine": max(1, f.line)},
                }
            }],
            "properties": {"confidence": f.confidence, "severity": f.severity.value},
        })
    doc = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "pharos-skill-inspector",
                "version": "0.1.0",
                "rules": list(rules.values()),
            }},
            "results": sarif_results,
        }],
    }
    return json.dumps(doc, indent=2)


RENDERERS = {
    "terminal": render_terminal,
    "json": render_json,
    "markdown": render_markdown,
    "sarif": render_sarif,
}


def render(result: ScanResult, fmt: str, color: bool = True) -> str:
    if fmt == "terminal":
        return render_terminal(result, color=color)
    return RENDERERS[fmt](result)
