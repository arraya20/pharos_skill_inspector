"""Core data models for the Pharos Skill Inspector."""

from __future__ import annotations

import enum
from dataclasses import dataclass, field, asdict
from typing import Any


class Severity(enum.Enum):
    """Severity of a finding, ordered from least to most serious."""

    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

    @property
    def rank(self) -> int:
        return {
            "INFO": 0,
            "LOW": 1,
            "MEDIUM": 2,
            "HIGH": 3,
            "CRITICAL": 4,
        }[self.value]

    @property
    def weight(self) -> int:
        """Points contributed to the risk score (SkillSpector-style)."""
        return {
            "INFO": 0,
            "LOW": 5,
            "MEDIUM": 10,
            "HIGH": 25,
            "CRITICAL": 50,
        }[self.value]

    def __lt__(self, other: "Severity") -> bool:  # enables sorting
        if not isinstance(other, Severity):
            return NotImplemented
        return self.rank < other.rank


class Category(enum.Enum):
    """High-level vulnerability categories tracked by the scanner."""

    PROMPT_INJECTION = "prompt_injection"
    DATA_LEAKAGE = "data_leakage"
    DANGEROUS_CODE = "dangerous_code"
    VULNERABLE_DEPENDENCY = "vulnerable_dependency"
    SUPPLY_CHAIN = "supply_chain"
    PHAROS_WEB3 = "pharos_web3"


@dataclass
class Finding:
    """A single detected issue."""

    rule_id: str
    title: str
    severity: Severity
    category: Category
    message: str
    component: str = ""          # relative file path
    line: int = 0
    evidence: str = ""           # the offending snippet (truncated/redacted)
    recommendation: str = ""
    confidence: float = 0.8      # 0..1

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "severity": self.severity.value,
            "category": self.category.value,
            "message": self.message,
            "component": self.component,
            "line": self.line,
            "evidence": self.evidence,
            "recommendation": self.recommendation,
            "confidence": round(self.confidence, 2),
        }


@dataclass
class Component:
    """A scannable file inside a skill."""

    path: str                    # relative path within the skill
    kind: str                    # markdown | python | javascript | typescript | solidity | json | shell | text
    lines: int = 0
    executable: bool = False
    text: str = field(default="", repr=False)

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "kind": self.kind,
            "lines": self.lines,
            "executable": self.executable,
        }


@dataclass
class ScanResult:
    """Aggregated result of scanning one skill."""

    skill_name: str
    source: str
    components: list[Component] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    risk_score: int = 0
    risk_severity: Severity = Severity.INFO
    recommendation: str = "SAFE"
    scanned_at: str = ""
    errors: list[str] = field(default_factory=list)

    def counts_by_severity(self) -> dict[str, int]:
        out = {s.value: 0 for s in Severity}
        for f in self.findings:
            out[f.severity.value] += 1
        return out

    def to_dict(self) -> dict[str, Any]:
        return {
            "skill_name": self.skill_name,
            "source": self.source,
            "scanned_at": self.scanned_at,
            "risk_score": self.risk_score,
            "risk_severity": self.risk_severity.value,
            "recommendation": self.recommendation,
            "counts_by_severity": self.counts_by_severity(),
            "components": [c.to_dict() for c in self.components],
            "findings": [f.to_dict() for f in self.findings],
            "errors": self.errors,
        }
