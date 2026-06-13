"""Solidity on-chain risk analyzer.

Pharos Skill Engine skills ship Solidity contracts (ERC20 templates, airdrop
distributors, custom skill contracts) that the agent deploys with the user's
funds. This analyzer flags well-known smart-contract risk patterns on a
comment/string-masked copy of the source.

Heuristic (not a full Slither-grade analyzer): high recall, review in context.
"""

from __future__ import annotations

import re

from ..models import Category, Component, Finding, Severity
from . import Analyzer, line_of, snippet
from .textproc import mask_code

_PATTERNS = [
    ("SOL001", "tx.origin Authentication", Severity.HIGH,
     r"\btx\.origin\b",
     "Uses tx.origin, which is phishable for authentication and breaks with meta-transactions.",
     "Use msg.sender for authorization, never tx.origin.", 0.85),
    ("SOL002", "selfdestruct", Severity.HIGH,
     r"\b(selfdestruct|suicide)\s*\(",
     "Contract can self-destruct, potentially removing code and forwarding the balance.",
     "Avoid selfdestruct; it can rug deployed funds and breaks integrations.", 0.8),
    ("SOL003", "delegatecall", Severity.HIGH,
     r"\.\s*delegatecall\s*\(",
     "Uses delegatecall, which executes external code in this contract's storage context.",
     "Restrict delegatecall targets to trusted, immutable addresses; never to user input.", 0.75),
    ("SOL004", "Low-Level call With Value", Severity.MEDIUM,
     r"\.\s*call\s*\{[^}]*value",
     "Low-level call forwarding value; vulnerable to reentrancy if state isn't updated first.",
     "Apply checks-effects-interactions and a reentrancy guard.", 0.6),
    ("SOL005", "Arbitrary External Call", Severity.HIGH,
     r"\b(address|IERC20|I[A-Z]\w+)\s*\(\s*\w+\s*\)\s*\.\s*(call|transfer|transferFrom|approve)\s*\(",
     "Calls a method on an address supplied at runtime — possible arbitrary external call.",
     "Validate/allow-list target addresses before calling them.", 0.5),
    ("SOL006", "Unprotected Ether Withdrawal", Severity.HIGH,
     r"function\s+\w*(withdraw|claim|drain|sweep)\w*\s*\([^)]*\)\s*(external|public)(?![^{]*\b(onlyOwner|require\s*\(\s*msg\.sender)\b)",
     "A withdraw/claim function appears to lack an owner/sender access check.",
     "Gate fund-moving functions with access control (onlyOwner / require(msg.sender == ...)).", 0.5),
    ("SOL007", "Hardcoded Address", Severity.LOW,
     r"0x[a-fA-F0-9]{40}\b",
     "Hardcoded 20-byte address in contract source; verify it is a trusted Pharos address.",
     "Confirm the address against the Pharos canonical contract / token registry.", 0.45),
    ("SOL008", "Floating / Outdated Pragma", Severity.LOW,
     r"pragma\s+solidity\s+\^",
     "Floating pragma (^) lets the contract compile with unexpected compiler versions.",
     "Pin an exact, audited compiler version (e.g. pragma solidity 0.8.24;).", 0.5),
]

_COMPILED = [(rid, title, sev, re.compile(pat), msg, rec, conf)
             for (rid, title, sev, pat, msg, rec, conf) in _PATTERNS]


class SolidityAnalyzer(Analyzer):
    name = "solidity"

    def analyze(self, components: list[Component]) -> list[Finding]:
        findings: list[Finding] = []
        for comp in components:
            if comp.kind != "solidity" or not comp.text:
                continue
            masked = mask_code(comp.text, template_literals=False)
            raw_lines = comp.text.splitlines()
            for rid, title, sev, pat, msg, rec, conf in _COMPILED:
                for m in pat.finditer(masked):
                    line_no = line_of(masked, m.start())
                    ev = raw_lines[line_no - 1] if 0 < line_no <= len(raw_lines) else ""
                    findings.append(Finding(
                        rule_id=rid, title=title, severity=sev,
                        category=Category.PHAROS_WEB3, message=msg,
                        component=comp.path, line=line_no, evidence=snippet(ev),
                        recommendation=rec, confidence=conf,
                    ))
        return findings
