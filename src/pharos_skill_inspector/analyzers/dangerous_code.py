"""Dangerous code analyzer.

Two layers:
  1. Python AST analysis — precise detection of exec/eval/__import__/compile,
     subprocess and os.system, dynamic getattr, and exec-with-dynamic-source.
  2. Cross-language regex — shell ``curl | bash`` / obfuscation / JS eval that
     the AST layer can't see (non-Python files).
"""

from __future__ import annotations

import ast

from ..models import Category, Component, Finding, Severity
from . import Analyzer, RegexRule, run_regex_rules, snippet

# ---------------------------------------------------------------------------
# Layer 1: Python AST
# ---------------------------------------------------------------------------

_DANGEROUS_CALLS = {
    "exec": ("AST001", "exec() Call", Severity.CRITICAL,
             "Direct exec() enables arbitrary code execution."),
    "eval": ("AST002", "eval() Call", Severity.HIGH,
             "Direct eval() evaluates arbitrary expressions."),
    "__import__": ("AST003", "Dynamic Import", Severity.HIGH,
                   "__import__() loads arbitrary modules at runtime."),
    "compile": ("AST004", "compile() Call", Severity.MEDIUM,
                "compile() builds code objects from strings."),
}

_OS_EXEC = {"system", "popen", "execv", "execve", "execvp", "spawnl", "spawnv"}
_SUBPROCESS_FNS = {"call", "run", "Popen", "check_call", "check_output", "getoutput"}
_DYNAMIC_SOURCE_HINTS = ("requests", "urlopen", "recv", "read", "input", "environ",
                         "b64decode", "b16decode", "decode", "fromhex", "stdin")


class _PyVisitor(ast.NodeVisitor):
    def __init__(self, comp: Component):
        self.comp = comp
        self.findings: list[Finding] = []

    def _add(self, rule_id, title, severity, msg, node, rec):
        line = getattr(node, "lineno", 0)
        try:
            ev = self.comp.text.splitlines()[line - 1]
        except (IndexError, AttributeError):
            ev = ""
        self.findings.append(
            Finding(
                rule_id=rule_id, title=title, severity=severity,
                category=Category.DANGEROUS_CODE, message=msg,
                component=self.comp.path, line=line, evidence=snippet(ev),
                recommendation=rec, confidence=0.9,
            )
        )

    @staticmethod
    def _func_name(node: ast.Call) -> str:
        f = node.func
        if isinstance(f, ast.Name):
            return f.id
        if isinstance(f, ast.Attribute):
            return f.attr
        return ""

    @staticmethod
    def _root_name(node: ast.Call) -> str:
        f = node.func
        if isinstance(f, ast.Attribute) and isinstance(f.value, ast.Name):
            return f.value.id
        return ""

    def _has_dynamic_source(self, node: ast.Call) -> bool:
        for sub in ast.walk(node):
            if isinstance(sub, ast.Attribute) and sub.attr in _DYNAMIC_SOURCE_HINTS:
                return True
            if isinstance(sub, ast.Name) and sub.id in _DYNAMIC_SOURCE_HINTS:
                return True
        # a non-literal first argument is "dynamic"
        if node.args and not isinstance(node.args[0], (ast.Constant,)):
            return True
        return False

    def visit_Call(self, node: ast.Call):
        name = self._func_name(node)
        root = self._root_name(node)

        if name in _DANGEROUS_CALLS:
            rid, title, sev, msg = _DANGEROUS_CALLS[name]
            self._add(rid, title, sev, msg, node,
                      "Avoid dynamic code execution; use explicit, statically-known logic.")
            if name in ("exec", "eval") and self._has_dynamic_source(node):
                self._add("AST008", "Dangerous Execution Chain", Severity.CRITICAL,
                          f"{name}() is fed a dynamic/remote/encoded source — remote code execution risk.",
                          node, "Never execute code derived from network, input, or encoded data.")

        if root == "os" and name in _OS_EXEC:
            self._add("AST005", "os shell execution", Severity.HIGH,
                      f"os.{name}() runs an external shell command.", node,
                      "Avoid shell execution; if unavoidable, never interpolate untrusted input.")

        if root == "subprocess" and name in _SUBPROCESS_FNS:
            shell_true = any(
                isinstance(kw.value, ast.Constant) and kw.value.value is True
                for kw in node.keywords if kw.arg == "shell"
            )
            sev = Severity.CRITICAL if shell_true else Severity.HIGH
            extra = " with shell=True (command injection risk)" if shell_true else ""
            self._add("AST006", "subprocess execution", sev,
                      f"subprocess.{name}() runs an external command{extra}.", node,
                      "Pass argument lists (not strings), avoid shell=True, and never interpolate untrusted input.")

        if name == "getattr" and len(node.args) >= 2 and not isinstance(node.args[1], ast.Constant):
            self._add("AST007", "Dynamic getattr()", Severity.MEDIUM,
                      "getattr() with a non-literal attribute name enables arbitrary attribute access.",
                      node, "Use literal attribute names or an explicit allow-list.")

        self.generic_visit(node)


def _analyze_python(comp: Component) -> list[Finding]:
    if not comp.text.strip():
        return []
    try:
        tree = ast.parse(comp.text)
    except SyntaxError:
        return [Finding(
            rule_id="AST000", title="Unparseable Python",
            severity=Severity.LOW, category=Category.DANGEROUS_CODE,
            message="File could not be parsed as Python; manual review recommended.",
            component=comp.path, line=0, evidence="", confidence=0.4,
            recommendation="Ensure the script is valid; obfuscated/broken code warrants scrutiny.",
        )]
    v = _PyVisitor(comp)
    v.visit(tree)
    return v.findings


# ---------------------------------------------------------------------------
# Layer 2: cross-language regex
# ---------------------------------------------------------------------------

REGEX_RULES = [
    RegexRule(
        rule_id="DC010",
        title="Remote Script Execution (curl | bash)",
        severity=Severity.HIGH,
        category=Category.SUPPLY_CHAIN,
        pattern=r"(curl|wget|fetch)\b[^\n|]{0,200}\|\s*(sudo\s+)?(bash|sh|zsh|python3?|node)\b",
        message="Downloads and pipes a remote script straight into a shell/interpreter (remote code execution).",
        recommendation="Download to a file, inspect it, pin a checksum, then run it explicitly.",
        confidence=0.85,
    ),
    RegexRule(
        rule_id="DC012",
        title="Obfuscated / Encoded Execution",
        severity=Severity.HIGH,
        category=Category.SUPPLY_CHAIN,
        pattern=r"(base64\.b64decode|atob\s*\(|fromhex|codecs\.decode)[^\n]{0,80}"
                r"(exec|eval|subprocess|os\.system|Function)",
        message="Encoded payload is decoded and executed — a common obfuscation/malware technique.",
        recommendation="Do not decode-then-execute. Ship readable, reviewable code.",
        confidence=0.85,
    ),
    RegexRule(
        rule_id="DC013",
        title="Destructive Filesystem Command",
        severity=Severity.HIGH,
        category=Category.DANGEROUS_CODE,
        pattern=r"(rm\s+-rf\s+[/~]|shutil\.rmtree\s*\(|os\.remove\s*\(|del\s+/[sf]\b)",
        message="Performs a recursive/destructive filesystem deletion.",
        recommendation="Scope deletions tightly; never recursively delete from / or the home directory.",
        confidence=0.6,
    ),
]


class DangerousCodeAnalyzer(Analyzer):
    name = "dangerous_code"

    def analyze(self, components: list[Component]) -> list[Finding]:
        findings: list[Finding] = []
        for comp in components:
            if comp.kind == "python":
                findings.extend(_analyze_python(comp))
        findings.extend(run_regex_rules(REGEX_RULES, components))
        return findings
