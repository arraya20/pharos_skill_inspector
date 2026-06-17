"""Data leakage analyzer.

Detects exfiltration of secrets, environment variables, and conversation/context
data to external destinations. Tuned for the Pharos Skill Engine, where the
crown-jewel secret is the wallet ``$PRIVATE_KEY``.
"""

from __future__ import annotations

from ..models import Category, Severity
from . import Analyzer, RegexRule, run_regex_rules

_CODE_KINDS = ("python", "javascript", "typescript", "shell", "template")

RULES = [
    RegexRule(
        rule_id="DL001",
        title="Environment Variable Harvesting",
        severity=Severity.HIGH,
        category=Category.DATA_LEAKAGE,
        # Match whole-environment use (bare `os.environ`, `.items()`, `.copy()`,
        # `dict(os.environ)`, `process.env`) but NOT a single-key read: the
        # negative lookaheads exclude `os.environ["X"]` and `os.environ.get(...)`,
        # and `process.env.X`, which are normal scoped lookups.
        pattern=r"(os\.environ(?!\s*\[)(?!\s*\.get\b)|process\.env\b(?!\.\w))",
        message="Code reads the entire environment block, which can sweep up API keys and the wallet private key.",
        recommendation="Read only the specific variables you need; never enumerate the whole environment.",
        kinds=_CODE_KINDS,
        confidence=0.75,
    ),
    RegexRule(
        rule_id="DL002",
        title="External Data Transmission",
        severity=Severity.MEDIUM,
        category=Category.DATA_LEAKAGE,
        pattern=r"\b(requests\.(post|put|patch)|httpx\.(post|put)|urllib\.request\.urlopen|"
                r"fetch\s*\(|axios\.(post|put)|XMLHttpRequest)\b",
        message="Code transmits data to an external endpoint.",
        recommendation="Confirm the destination is a trusted Pharos endpoint and that no secrets are included in the payload.",
        kinds=_CODE_KINDS,
        confidence=0.5,
    ),
    RegexRule(
        rule_id="DL003",
        title="Secret Sent Over Network",
        severity=Severity.CRITICAL,
        category=Category.DATA_LEAKAGE,
        pattern=r"(requests\.(post|put|get)|httpx\.\w+|fetch|axios\.\w+|urlopen)\s*\([^)\n]{0,200}"
                r"(PRIVATE_KEY|private_key|privateKey|mnemonic|seed_?phrase|secret|api[_-]?key|password)",
        message="A secret (private key, mnemonic, API key, or password) is passed directly into a network call.",
        recommendation="Never transmit secrets off the machine. This is a credential-exfiltration pattern.",
        kinds=_CODE_KINDS,
        confidence=0.9,
    ),
    RegexRule(
        rule_id="DL004",
        title="Secret Written to File",
        severity=Severity.HIGH,
        category=Category.DATA_LEAKAGE,
        pattern=r"(open\s*\([^)\n]{0,80}['\"][wa]\b|\.write\s*\(|fs\.writeFile)[^\n]{0,120}"
                r"(PRIVATE_KEY|private_key|privateKey|mnemonic|seed)",
        message="A secret value is written to a file, where it can be read or committed to git.",
        recommendation="Keep secrets only in the process environment; do not persist them to disk.",
        kinds=_CODE_KINDS,
        confidence=0.8,
    ),
    RegexRule(
        rule_id="DL005",
        title="Secret Logged to Console",
        severity=Severity.MEDIUM,
        category=Category.DATA_LEAKAGE,
        pattern=r"(print|console\.log|echo|logging\.\w+|logger\.\w+)\s*\(?[^\n]{0,60}"
                r"(PRIVATE_KEY|private_key|privateKey|mnemonic|seed_?phrase)",
        message="A secret is printed or logged, which can leak it into terminal history or log files.",
        recommendation="Never log secret material. Log a derived public address instead if you need a reference.",
        kinds=_CODE_KINDS,
        confidence=0.7,
    ),
    RegexRule(
        rule_id="DL006",
        title="Conversation / Context Exfiltration",
        severity=Severity.HIGH,
        category=Category.DATA_LEAKAGE,
        pattern=r"\b(send|post|upload|transmit|forward)\b[^.\n]{0,40}\b("
                r"conversation|chat history|context|messages|transcript)\b[^.\n]{0,40}\b("
                r"to|external|server|endpoint|webhook|url)",
        message="Instruction or code forwards the conversation/context to an external destination.",
        recommendation="Do not exfiltrate conversation context. Remove this behaviour.",
        confidence=0.7,
    ),
    RegexRule(
        rule_id="DL007",
        title="Sensitive File Access",
        severity=Severity.MEDIUM,
        category=Category.DATA_LEAKAGE,
        # Note: ``(?<![\w.])\.env`` avoids matching ``process.env`` / ``import.meta.env``
        # property access, which is normal code, not sensitive-file access.
        pattern=r"(~/\.ssh|/\.ssh/|id_rsa|\.aws/credentials|\.netrc|(?<![\w.])\.env\b|"
                r"\.config/gcloud|wallet\.json|(?<![\w.])\.pem\b)",
        message="Code references credential or key files outside the skill's scope.",
        recommendation="A skill should not read SSH keys, cloud credentials, or wallet keystores.",
        kinds=_CODE_KINDS,
        confidence=0.6,
    ),
]


class DataLeakageAnalyzer(Analyzer):
    name = "data_leakage"

    def analyze(self, components):
        return run_regex_rules(RULES, components)
