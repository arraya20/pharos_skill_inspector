"""Base classes and helpers shared by all analyzers."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Iterable

from ..models import Category, Component, Finding, Severity

# Patterns whose matched text may contain secrets and must be redacted in output.
_SECRET_HINT = re.compile(r"(0x[a-fA-F0-9]{12,})|(sk-[A-Za-z0-9]{8,})|([A-Za-z0-9_\-]{24,})")

MAX_EVIDENCE = 160


def redact(text: str) -> str:
    """Redact long hex/secret-looking tokens so the scanner never leaks keys."""
    def _mask(m: re.Match) -> str:
        s = m.group(0)
        if len(s) <= 10:
            return s
        return s[:6] + "…REDACTED…" + s[-4:]
    return _SECRET_HINT.sub(_mask, text)


def snippet(line_text: str) -> str:
    s = line_text.strip()
    if len(s) > MAX_EVIDENCE:
        s = s[:MAX_EVIDENCE] + "…"
    return redact(s)


def line_of(text: str, index: int) -> int:
    """1-based line number for a character offset."""
    return text.count("\n", 0, index) + 1


@dataclass
class RegexRule:
    """A declarative regex rule."""

    rule_id: str
    title: str
    severity: Severity
    category: Category
    pattern: str
    message: str
    recommendation: str
    kinds: tuple[str, ...] = ()       # restrict to component kinds; empty = all
    confidence: float = 0.8
    flags: int = re.IGNORECASE | re.MULTILINE
    exclude: str | None = None        # if matched text also matches this, skip

    def compiled(self) -> re.Pattern:
        if not hasattr(self, "_compiled"):
            object.__setattr__(self, "_compiled", re.compile(self.pattern, self.flags))
        return self._compiled

    def excluded(self) -> re.Pattern | None:
        if self.exclude is None:
            return None
        if not hasattr(self, "_excluded"):
            object.__setattr__(self, "_excluded", re.compile(self.exclude, self.flags))
        return self._excluded

    def applies_to(self, comp: Component) -> bool:
        return not self.kinds or comp.kind in self.kinds


class Analyzer:
    """Base analyzer interface."""

    name: str = "analyzer"

    def analyze(self, components: list[Component]) -> list[Finding]:  # pragma: no cover
        raise NotImplementedError


def run_regex_rules(rules: Iterable[RegexRule], components: list[Component]) -> list[Finding]:
    """Apply a set of regex rules across components, producing findings."""
    findings: list[Finding] = []
    for comp in components:
        if not comp.text:
            continue
        for rule in rules:
            if not rule.applies_to(comp):
                continue
            excl = rule.excluded()
            for m in rule.compiled().finditer(comp.text):
                matched = m.group(0)
                if excl and excl.search(matched):
                    continue
                line_no = line_of(comp.text, m.start())
                line_text = comp.text.splitlines()[line_no - 1] if comp.text else matched
                findings.append(
                    Finding(
                        rule_id=rule.rule_id,
                        title=rule.title,
                        severity=rule.severity,
                        category=rule.category,
                        message=rule.message,
                        component=comp.path,
                        line=line_no,
                        evidence=snippet(line_text),
                        recommendation=rule.recommendation,
                        confidence=rule.confidence,
                    )
                )
    return findings
