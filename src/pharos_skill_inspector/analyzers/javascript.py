"""Token-aware JavaScript / TypeScript analyzer.

Two passes:
  * **masked** — dangerous *call expressions* are matched on a comment/string
    -masked copy (see ``textproc.mask_code``) so they never fire inside comments
    or string literals.
  * **raw** — dangerous *module imports* (``require('child_process')`` etc.) are
    matched on the original source, because the module name lives inside a string
    literal that masking would blank.
"""

from __future__ import annotations

import re

from ..models import Category, Component, Finding, Severity
from . import Analyzer, line_of, snippet
from .textproc import mask_code

_JS_KINDS = ("javascript", "typescript", "template")

# Patterns matched on the MASKED source (real code only).
_MASKED = [
    ("JS001", "eval() Call", Severity.HIGH, Category.DANGEROUS_CODE,
     r"\beval\s*\(",
     "Dynamic code execution via eval().",
     "Remove eval(); use explicit logic or JSON.parse for data.", 0.85),
    ("JS002", "Function Constructor", Severity.HIGH, Category.DANGEROUS_CODE,
     r"\bnew\s+Function\s*\(",
     "Dynamic code execution via the Function constructor.",
     "Avoid the Function constructor; it executes arbitrary strings as code.", 0.85),
    ("JS003", "child_process Execution", Severity.HIGH, Category.DANGEROUS_CODE,
     r"\bchild_process\s*\.\s*(exec|execSync|spawn|spawnSync|fork)\s*\(|\.\s*(execSync|spawnSync)\s*\(",
     "Spawns external OS processes.",
     "Avoid shelling out; if required, pass argument arrays and never interpolate untrusted input.", 0.75),
    ("JS004", "vm Module Sandbox Escape Risk", Severity.MEDIUM, Category.DANGEROUS_CODE,
     r"\bvm\s*\.\s*runIn\w*\s*\(",
     "Uses the Node 'vm' module to execute code; vm is not a security boundary.",
     "Do not rely on 'vm' for sandboxing untrusted code.", 0.6),
    ("JS006", "Full Environment Enumeration", Severity.HIGH, Category.DATA_LEAKAGE,
     r"(Object\.(keys|entries|values|assign)\s*\(\s*process\.env|\{\s*\.\.\.\s*process\.env|JSON\.stringify\s*\(\s*process\.env)",
     "Reads the entire process environment, which can sweep up API keys and the wallet key.",
     "Read only the specific env vars you need.", 0.75),
    ("JS010", "Wallet From Raw Private Key", Severity.HIGH, Category.PHAROS_WEB3,
     r"\bnew\s+(ethers\.)?Wallet\s*\(|\bprivateKeyToAccount\s*\(",
     "Instantiates a signing wallet from a private key in code.",
     "Load the key from $PRIVATE_KEY at runtime; never embed or pass key literals.", 0.6),
    ("JS011", "On-Chain Write Operation", Severity.MEDIUM, Category.PHAROS_WEB3,
     r"\.(sendTransaction|signTransaction|writeContract|deployContract)\s*\(|\.deploy\s*\(",
     "Performs an on-chain write/deploy via ethers/viem.",
     "Ensure writes are gated by the Pharos pre-checks and explicit user confirmation.", 0.5),
]

# Patterns matched on the RAW source (module-name string literals needed).
_RAW = [
    ("JS003", "child_process Import", Severity.HIGH, Category.DANGEROUS_CODE,
     r"\brequire\s*\(\s*['\"]child_process['\"]\s*\)|\bfrom\s+['\"]child_process['\"]|import\s+['\"]child_process['\"]",
     "Imports the child_process module, used to spawn external OS processes.",
     "Avoid shelling out; if required, pass argument arrays and never interpolate untrusted input.", 0.7),
    ("JS004", "vm Module Import", Severity.MEDIUM, Category.DANGEROUS_CODE,
     r"\brequire\s*\(\s*['\"]vm['\"]\s*\)|\bfrom\s+['\"]vm['\"]",
     "Imports the Node 'vm' module; vm is not a security sandbox.",
     "Do not rely on 'vm' for sandboxing untrusted code.", 0.55),
    ("JS005", "Dynamic require()", Severity.MEDIUM, Category.DANGEROUS_CODE,
     r"\brequire\s*\(\s*(?!['\"])[A-Za-z_$]",
     "require() called with a non-literal module path (dynamic import).",
     "Use static, literal module paths so the dependency surface is auditable.", 0.5),
]

_MASKED_C = [(rid, t, s, c, re.compile(p), m, r, cf) for (rid, t, s, c, p, m, r, cf) in _MASKED]
_RAW_C = [(rid, t, s, c, re.compile(p), m, r, cf) for (rid, t, s, c, p, m, r, cf) in _RAW]


class JavaScriptAnalyzer(Analyzer):
    name = "javascript"

    def analyze(self, components: list[Component]) -> list[Finding]:
        findings: list[Finding] = []
        for comp in components:
            if comp.kind not in _JS_KINDS or not comp.text:
                continue
            raw_lines = comp.text.splitlines()
            masked = mask_code(comp.text, template_literals=True)
            seen: set[tuple] = set()
            for source, rules in ((masked, _MASKED_C), (comp.text, _RAW_C)):
                for rid, title, sev, cat, pat, msg, rec, conf in rules:
                    for mt in pat.finditer(source):
                        line_no = line_of(source, mt.start())
                        key = (rid, line_no)
                        if key in seen:
                            continue
                        seen.add(key)
                        ev = raw_lines[line_no - 1] if 0 < line_no <= len(raw_lines) else ""
                        findings.append(Finding(
                            rule_id=rid, title=title, severity=sev, category=cat,
                            message=msg, component=comp.path, line=line_no,
                            evidence=snippet(ev), recommendation=rec, confidence=conf,
                        ))
        return findings
