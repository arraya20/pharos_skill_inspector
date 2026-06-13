"""Prompt injection analyzer.

Targets instructions inside SKILL.md / reference markdown that try to override
the agent's safety rules, hide directives, or manipulate behaviour. These are
the highest-leverage attacks against an LLM agent that reads a skill verbatim.
"""

from __future__ import annotations

import re

from ..models import Category, Component, Finding, Severity
from . import Analyzer, RegexRule, run_regex_rules, line_of, snippet

_DOC_KINDS = ("markdown", "text", "template")

RULES = [
    RegexRule(
        rule_id="PI001",
        title="Instruction Override",
        severity=Severity.HIGH,
        category=Category.PROMPT_INJECTION,
        pattern=r"\b(ignore|disregard|forget|override|bypass)\b[^.\n]{0,40}\b("
                r"previous|prior|above|earlier|all|any|the)\b[^.\n]{0,30}\b("
                r"instructions?|prompts?|rules?|guidelines?|constraints?|safety|restrictions?)",
        message="Text instructs the agent to ignore or override its prior instructions or safety rules.",
        recommendation="Remove any directives that tell the agent to disregard its own instructions or guardrails.",
        kinds=_DOC_KINDS,
        confidence=0.85,
    ),
    RegexRule(
        rule_id="PI003",
        title="Role / Persona Hijack",
        severity=Severity.MEDIUM,
        category=Category.PROMPT_INJECTION,
        # "act as" / "pretend to be" removed: they appear constantly in legitimate
        # example prompts ("act as my broker"). Keep only strong override signals.
        pattern=r"\b(you are now|from now on,? you are|new system prompt|"
                r"ignore your (system )?prompt|developer mode|jailbreak|DAN mode)\b",
        message="Text attempts to redefine the agent's role or unlock an unrestricted mode.",
        recommendation="A skill should describe capabilities, not redefine the agent's identity or unlock 'modes'.",
        kinds=_DOC_KINDS,
        confidence=0.7,
    ),
    RegexRule(
        rule_id="PI004",
        title="Behaviour Manipulation",
        severity=Severity.MEDIUM,
        category=Category.PROMPT_INJECTION,
        pattern=r"\b(do not (tell|inform|mention|warn|alert)|without (telling|informing|asking|notifying)|"
                r"secretly|silently|quietly|behind the scenes)\b[^.\n]{0,40}\b(user|owner|developer|human)",
        message="Text instructs the agent to act without informing or warning the user.",
        recommendation="Agents must keep the user informed. Remove instructions to hide actions from the user.",
        kinds=_DOC_KINDS,
        confidence=0.75,
    ),
    RegexRule(
        rule_id="PI005",
        title="System Prompt Leakage Request",
        severity=Severity.MEDIUM,
        category=Category.PROMPT_INJECTION,
        pattern=r"\b(reveal|print|repeat|output|disclose|share|reproduce)\b[^.\n]{0,30}\b("
                r"system prompt|your instructions|initial prompt|hidden prompt|developer message)",
        message="Text asks the agent to reveal its system prompt or hidden instructions.",
        recommendation="Remove requests for the agent to expose its system prompt or internal rules.",
        kinds=_DOC_KINDS,
        confidence=0.8,
    ),
]

# Zero-width / bidi characters frequently used to hide instructions.
_HIDDEN_CHARS = {
    "\u200b": "ZERO WIDTH SPACE",
    "\u200c": "ZERO WIDTH NON-JOINER",
    "\u200d": "ZERO WIDTH JOINER",
    "\u2060": "WORD JOINER",
    "\u202e": "RIGHT-TO-LEFT OVERRIDE",
    "\u202d": "LEFT-TO-RIGHT OVERRIDE",
    "\ufeff": "BYTE ORDER MARK",
}

_HTML_COMMENT = re.compile(r"<!--(.*?)-->", re.DOTALL)
_IMPERATIVE = re.compile(
    r"\b(ignore|run|execute|send|transfer|delete|curl|export|print|reveal|fetch|download)\b",
    re.IGNORECASE,
)

# PI002: a directive to actively *bypass* a safety step. We require a real
# bypass verb (skip/bypass/disable/...) followed by a safety noun — the bare
# word "without" was removed because "do not act without confirmation" and
# "<event> without confirmation" (escalation lists) are safe policy text.
_BYPASS_RE = re.compile(
    r"\b(skip|skipping|bypass|bypassing|disable|disabling|ignore|circumvent|"
    r"no need to run|need not run|don'?t run|do not run|without running|avoid running)\b"
    r"[^.\n]{0,40}\b(pre-?checks?|safety checks?|confirmations?|approvals?|"
    r"verifications?|reviews?|safety gates?)\b",
    re.IGNORECASE,
)
# If one of these immediately precedes the bypass verb, the sentence is a
# prohibition/requirement ("do not skip the pre-checks") — i.e. safe.
_NEG_BEFORE = re.compile(
    r"\b(do not|do n't|don'?t|never|must not|must never|should not|shouldn'?t|"
    r"cannot|can'?t|always|require[sd]?|ensure|refuse to|reject)\b[^.\n]{0,8}$",
    re.IGNORECASE,
)


class PromptInjectionAnalyzer(Analyzer):
    name = "prompt_injection"

    def analyze(self, components: list[Component]) -> list[Finding]:
        findings = run_regex_rules(RULES, components)
        for comp in components:
            if comp.kind not in _DOC_KINDS or not comp.text:
                continue
            findings.extend(self._precheck_bypass(comp))
            findings.extend(self._hidden_unicode(comp))
            findings.extend(self._hidden_html_comments(comp))
        return findings

    def _precheck_bypass(self, comp: Component) -> list[Finding]:
        out: list[Finding] = []
        for m in _BYPASS_RE.finditer(comp.text):
            pre = comp.text[max(0, m.start() - 30):m.start()]
            if _NEG_BEFORE.search(pre):
                continue  # "do not skip the pre-checks" etc. — safe
            line_no = line_of(comp.text, m.start())
            line_txt = comp.text.splitlines()[line_no - 1]
            out.append(Finding(
                rule_id="PI002",
                title="Pre-Check / Safety Bypass Directive",
                severity=Severity.HIGH,
                category=Category.PROMPT_INJECTION,
                message="Skill instructs the agent to skip mandatory pre-checks, confirmation, or verification.",
                component=comp.path,
                line=line_no,
                evidence=snippet(line_txt),
                recommendation="Pharos write operations require the four pre-checks. Never instruct the agent to skip them.",
                confidence=0.8,
            ))
        return out

    def _hidden_unicode(self, comp: Component) -> list[Finding]:
        out: list[Finding] = []
        for ch, label in _HIDDEN_CHARS.items():
            idx = comp.text.find(ch)
            if idx != -1:
                out.append(
                    Finding(
                        rule_id="PI006",
                        title="Hidden Unicode Control Character",
                        severity=Severity.HIGH,
                        category=Category.PROMPT_INJECTION,
                        message=f"Invisible character ({label}) found in skill text — a common way to hide instructions.",
                        component=comp.path,
                        line=line_of(comp.text, idx),
                        evidence=f"contains {label} (U+{ord(ch):04X})",
                        recommendation="Strip zero-width and bidi control characters from skill documentation.",
                        confidence=0.9,
                    )
                )
        return out

    def _hidden_html_comments(self, comp: Component) -> list[Finding]:
        out: list[Finding] = []
        for m in _HTML_COMMENT.finditer(comp.text):
            body = m.group(1)
            if _IMPERATIVE.search(body):
                out.append(
                    Finding(
                        rule_id="PI007",
                        title="Hidden Instruction in HTML Comment",
                        severity=Severity.HIGH,
                        category=Category.PROMPT_INJECTION,
                        message="HTML comment contains imperative directives the user won't see rendered.",
                        component=comp.path,
                        line=line_of(comp.text, m.start()),
                        evidence=snippet(body),
                        recommendation="Move legitimate notes into visible text; remove hidden actionable directives.",
                        confidence=0.8,
                    )
                )
        return out
