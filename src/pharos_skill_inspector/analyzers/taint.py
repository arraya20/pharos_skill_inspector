"""Taint tracking for secret/private-key flows in Python.

Catches multi-line flows that the line-oriented regex rules miss, e.g.::

    key = os.environ["PRIVATE_KEY"]      # source
    payload = {"k": key}                  # propagation
    requests.post(url, json=payload)      # sink  -> CRITICAL

Intra-procedural, flow-insensitive def-use analysis over the Python AST:
  1. A value is *tainted* if it reads a secret-named env var, is a private-key
     literal, or copies the whole environment.
  2. Taint propagates through assignments to fixpoint.
  3. If a tainted value reaches a network / file-write / shell / log *sink*,
     a finding is raised.
"""

from __future__ import annotations

import ast
import re

from ..models import Category, Component, Finding, Severity
from . import Analyzer, snippet

_SECRET_NAME = re.compile(
    r"(private[_-]?key|mnemonic|seed[_-]?phrase|secret|api[_-]?key|password|passwd|privkey)",
    re.IGNORECASE,
)
_PRIVKEY_LITERAL = re.compile(r"0x[a-fA-F0-9]{64}\b")

# Sink classification: (rule_id, title, severity, message, recommendation).
_NETWORK_SINK = ("TT001", "Credential Exfiltration to Network", Severity.CRITICAL,
                 "A secret value flows into a network call — credential exfiltration.",
                 "Never transmit secrets off the machine; remove this data flow.")
_FILE_SINK = ("TT002", "Secret Written to File", Severity.HIGH,
              "A secret value flows into a file write — it can be read or committed to git.",
              "Keep secrets only in the process environment; do not persist them.")
_SHELL_SINK = ("TT003", "Secret Passed to Shell Command", Severity.HIGH,
               "A secret value is interpolated into a shell/subprocess command.",
               "Avoid passing keys on the command line; they leak into history and process lists.")
_LOG_SINK = ("TT004", "Secret Logged", Severity.MEDIUM,
             "A secret value flows into print/logging output.",
             "Never log secret material; log a derived public address instead.")


def _attr_chain(node: ast.AST) -> str:
    """Return a dotted name for Name/Attribute chains, else ''."""
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
    return ".".join(reversed(parts))


def _references_whole_environ(node: ast.AST) -> bool:
    """True if ``node`` is a *whole-environment* reference.

    Matches a bare ``os.environ`` / ``environ`` reference (e.g.
    ``e = os.environ``), ``dict(os.environ)``, and ``os.environ.copy()`` — i.e.
    the cases that sweep up every variable including the wallet key. It
    deliberately does NOT match single-key reads like ``os.environ["X"]`` or
    ``os.environ.get("X")`` (those are handled — and scoped to secret names —
    elsewhere), so adding this source doesn't over-taint ordinary env lookups.

    Only the top-level expression is inspected (callers pass the assignment RHS
    or an individual sink argument), never walked subtrees, which is what keeps
    ``os.environ.get("USERNAME")`` from being flagged via its inner attribute.
    """
    chain = _attr_chain(node)
    if chain == "environ" or chain == "os.environ" or chain.endswith(".environ"):
        return True
    if isinstance(node, ast.Call):
        fchain = _attr_chain(node.func)
        if fchain.endswith("environ.copy"):
            return True
        if fchain == "dict":
            for a in node.args:
                ac = _attr_chain(a)
                if ac == "environ" or ac == "os.environ" or ac.endswith(".environ"):
                    return True
    return False


def _classify_sink(call: ast.Call) -> tuple | None:
    chain = _attr_chain(call.func)
    last = chain.rsplit(".", 1)[-1] if chain else ""

    if (re.search(r"(requests|httpx|session)\.(get|post|put|patch|delete|request)$", chain)
            or chain.endswith("urlopen")
            or last in {"send", "sendall", "sendto"}
            or re.search(r"(socket|client|conn|websocket|ws)\.", chain) and last in {"send", "sendall"}):
        return _NETWORK_SINK
    if last in {"system", "popen", "run", "call", "check_call", "check_output", "Popen", "getoutput"}:
        return _SHELL_SINK
    if last in {"write", "writelines", "writeFile", "writeFileSync", "dump"} or chain.endswith("fs.writeFile"):
        return _FILE_SINK
    if last in {"print"} or chain == "print" or re.search(r"(logging|logger|log)\.\w+$", chain):
        return _LOG_SINK
    return None


class _SourceChecker:
    """Determines whether an expression subtree is tainted."""

    def __init__(self, tainted: set[str]):
        self.tainted = tainted

    def is_source_node(self, node: ast.AST) -> bool:
        # private-key literal
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            if _PRIVKEY_LITERAL.search(node.value):
                return True
        # os.getenv("PRIVATE_KEY") / os.environ.get("SECRET")
        if isinstance(node, ast.Call):
            chain = _attr_chain(node.func)
            if chain.endswith("os.getenv") or chain.endswith("environ.get") or chain == "getenv":
                for a in node.args:
                    if isinstance(a, ast.Constant) and isinstance(a.value, str) and _SECRET_NAME.search(a.value):
                        return True
            # dict(os.environ) — whole environment copy
            if chain == "dict":
                for a in node.args:
                    if _attr_chain(a).endswith("os.environ") or _attr_chain(a).endswith("environ"):
                        return True
        # os.environ["PRIVATE_KEY"]
        if isinstance(node, ast.Subscript):
            base = _attr_chain(node.value)
            if base.endswith("environ"):
                key = node.slice
                if isinstance(key, ast.Constant) and isinstance(key.value, str) and _SECRET_NAME.search(key.value):
                    return True
                return True  # any environ[...] indexing is sensitive
        return False

    def taints(self, node: ast.AST) -> bool:
        """True if any sub-expression is a source or references a tainted name."""
        # Whole-environment references are checked on the top node only (never
        # on walked subtrees) so a single-key read like os.environ.get("X")
        # isn't tainted via its inner `os.environ` attribute.
        if _references_whole_environ(node):
            return True
        for sub in ast.walk(node):
            if isinstance(sub, ast.Name) and sub.id in self.tainted:
                return True
            if self.is_source_node(sub):
                return True
        return False


class TaintAnalyzer(Analyzer):
    name = "taint"

    def analyze(self, components: list[Component]) -> list[Finding]:
        findings: list[Finding] = []
        for comp in components:
            if comp.kind != "python" or not comp.text.strip():
                continue
            try:
                tree = ast.parse(comp.text)
            except SyntaxError:
                continue
            findings.extend(self._analyze_tree(tree, comp))
        return findings

    def _analyze_tree(self, tree: ast.AST, comp: Component) -> list[Finding]:
        # 1) Propagate taint across assignments to a fixpoint.
        tainted: set[str] = set()
        checker = _SourceChecker(tainted)
        changed = True
        assigns = [n for n in ast.walk(tree) if isinstance(n, (ast.Assign, ast.AnnAssign, ast.AugAssign))]
        while changed:
            changed = False
            for node in assigns:
                value = node.value
                if value is None:
                    continue
                if checker.taints(value):
                    for tgt in self._targets(node):
                        if tgt not in tainted:
                            tainted.add(tgt)
                            changed = True

        # 2) Inspect sinks.
        raw_lines = comp.text.splitlines()
        out: list[Finding] = []
        seen: set[tuple] = set()
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            sink = _classify_sink(node)
            if sink is None:
                continue
            args = list(node.args) + [kw.value for kw in node.keywords]
            if not any(checker.taints(a) for a in args):
                continue
            rid, title, sev, msg, rec = sink
            line_no = getattr(node, "lineno", 0)
            key = (rid, line_no)
            if key in seen:
                continue
            seen.add(key)
            ev = raw_lines[line_no - 1] if 0 < line_no <= len(raw_lines) else ""
            out.append(Finding(
                rule_id=rid, title=title, severity=sev, category=Category.DATA_LEAKAGE,
                message=msg, component=comp.path, line=line_no,
                evidence=snippet(ev), recommendation=rec, confidence=0.8,
            ))
        return out

    @staticmethod
    def _targets(node) -> list[str]:
        names: list[str] = []
        targets = []
        if isinstance(node, ast.Assign):
            targets = node.targets
        elif isinstance(node, (ast.AnnAssign, ast.AugAssign)):
            targets = [node.target]
        for t in targets:
            for sub in ast.walk(t):
                if isinstance(sub, ast.Name):
                    names.append(sub.id)
        return names
