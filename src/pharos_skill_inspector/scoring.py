"""Risk scoring for scan results (SkillSpector-inspired, Pharos-tuned)."""

from __future__ import annotations

from .models import Finding, Severity

# Pharos skills frequently execute on-chain write operations. Any skill that
# carries an executable script that can move funds is inherently riskier, so we
# apply a multiplier when executable components are present.
EXECUTABLE_MULTIPLIER = 1.3

# Per-severity caps on total contribution. This stops a pile of low-severity,
# low-confidence noise (e.g. 16 unpinned deps) from alone reaching the
# "DO NOT INSTALL" band, while a single CRITICAL still dominates. CRITICAL is
# intentionally uncapped — one hardcoded key should fail the skill outright.
_SEVERITY_CAP = {
    Severity.CRITICAL: 10_000,   # effectively uncapped
    Severity.HIGH: 75,
    Severity.MEDIUM: 30,
    Severity.LOW: 12,
    Severity.INFO: 0,
}

# Risk bands -> (severity label, recommendation).
_BANDS = [
    (0, Severity.LOW, "SAFE"),
    (21, Severity.MEDIUM, "CAUTION"),
    (51, Severity.HIGH, "DO NOT INSTALL"),
    (81, Severity.CRITICAL, "DO NOT INSTALL"),
]


def score_findings(findings: list[Finding], has_executable: bool) -> tuple[int, Severity, str]:
    """Return (score 0-100, severity, recommendation).

    Confidence-weighted severity points are summed *per severity*, each capped
    (except CRITICAL) so trivial noise can't saturate the score, then optionally
    boosted by the executable multiplier and clamped to 100.
    """
    per_sev: dict[Severity, float] = {}
    for f in findings:
        conf = max(0.0, min(1.0, f.confidence))
        per_sev[f.severity] = per_sev.get(f.severity, 0.0) + f.severity.weight * conf

    raw = 0.0
    for sev, total in per_sev.items():
        raw += min(total, _SEVERITY_CAP.get(sev, 0))

    if has_executable and raw > 0:
        raw *= EXECUTABLE_MULTIPLIER

    score = int(round(min(100.0, raw)))

    severity, recommendation = Severity.LOW, "SAFE"
    for threshold, sev, rec in _BANDS:
        if score >= threshold:
            severity, recommendation = sev, rec
    if score == 0:
        severity, recommendation = Severity.INFO, "SAFE"
    return score, severity, recommendation
