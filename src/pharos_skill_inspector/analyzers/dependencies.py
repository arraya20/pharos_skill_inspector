"""Dependency analyzer.

Parses Python (requirements.txt / pyproject) and npm (package.json) manifests,
then:
  * Flags unpinned dependencies (SC-style).
  * Flags likely typosquats of popular Web3/Python packages.
  * Queries OSV.dev (https://api.osv.dev) for known CVEs, with a small offline
    fallback list when the network is unavailable.
"""

from __future__ import annotations

import json
import re
import urllib.error
import urllib.request

from ..models import Category, Component, Finding, Severity
from . import Analyzer

OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
_TIMEOUT = 6.0

# Popular packages used to detect typosquatting (Web3-heavy for Pharos).
_POPULAR = {
    "pypi": {"web3", "eth-account", "eth-abi", "requests", "cryptography",
             "ecdsa", "pycryptodome", "hexbytes", "eth-keys", "eth-utils"},
    "npm": {"ethers", "viem", "web3", "axios", "@openzeppelin/contracts",
            "hardhat", "@nomicfoundation/hardhat-toolbox", "dotenv"},
}

# Minimal offline CVE fallback (used only when OSV.dev is unreachable).
_OFFLINE_VULNS = {
    ("pypi", "requests"): [("2.19.1", "CVE-2018-18074", "Credential leak on redirect")],
    ("pypi", "cryptography"): [("3.2", "CVE-2020-25659", "Bleichenbacher timing oracle")],
    ("npm", "axios"): [("0.21.0", "CVE-2021-3749", "ReDoS in trim")],
    ("npm", "web3"): [("1.2.0", "GHSA-q5q9", "Prototype pollution")],
}

_PEP_PIN = re.compile(r"^([A-Za-z0-9._-]+)\s*(?:\[[^\]]*\])?\s*(==|>=|<=|~=|===|>|<|!=)?\s*([0-9][^,;\s]*)?")

# npm "specifiers" that are not registry version ranges and can't be CVE-checked.
_NPM_NON_REGISTRY = re.compile(
    r"^(git\+|git:|github:|gitlab:|bitbucket:|file:|link:|portal:|workspace:|npm:|"
    r"https?:|ssh:|\.{0,2}/)",
    re.IGNORECASE,
)
# An exact, pinned npm version: 1.2.3 / 1.2.3-rc.1 / 1.2.3+build (no range operators).
_NPM_EXACT = re.compile(r"^v?(\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.\-]+)?)$")
# Leading concrete version inside a range, e.g. ^1.2.3, >=1.2.3, ~1.2, 1.2.x
_NPM_LEADING_VER = re.compile(r"(\d+\.\d+\.\d+|\d+\.\d+|\d+)")


def _levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


class _Dep:
    __slots__ = ("name", "version", "ecosystem", "pinned", "is_range", "line", "component", "skip_cve")

    def __init__(self, name, version, ecosystem, pinned, line, component,
                 is_range=False, skip_cve=False):
        self.name = name
        self.version = version          # concrete version for CVE lookup, or ""
        self.ecosystem = ecosystem      # "pypi" | "npm"
        self.pinned = pinned            # exact pin (==/exact)
        self.is_range = is_range        # a range/caret/tilde/wildcard spec
        self.line = line
        self.component = component
        self.skip_cve = skip_cve        # git/url/alias specs: not registry-checkable


def parse_npm_spec(spec: str) -> tuple[str, bool, bool, bool]:
    """Parse an npm version spec.

    Returns ``(version, pinned, is_range, skip_cve)`` where:
      * ``version`` is a concrete version usable for an OSV query (may be "").
      * ``pinned`` is True only for an exact version (no range operators).
      * ``is_range`` is True for caret/tilde/comparator/wildcard/dist-tag specs.
      * ``skip_cve`` is True for git/url/file/alias specs that aren't registry
        versions and therefore can't be CVE-checked.

    The branches are intentionally explicit (and mutually exclusive) so a
    wildcard like ``*`` is never confused with a non-registry source.
    """
    spec = (spec or "").strip()

    # Empty spec: nothing to assert.
    if not spec:
        return "", False, False, False

    # Non-registry source (git/url/file/link/workspace/alias/...): can't be
    # CVE-checked and isn't a registry version range -> skip_cve.
    if _NPM_NON_REGISTRY.match(spec):
        return "", False, False, True

    # Wildcard / dist-tag (*, x, latest, next): an unpinned *registry* install
    # with no resolvable version. It is a range (unpinned), but still registry
    # sourced, so skip_cve stays False (otherwise it'd be misreported as a
    # git/URL/local source).
    if spec.lower() in ("*", "x", "latest", "next"):
        return "", False, True, False

    # Exact, pinned version (1.2.3 / v2.0.0-rc.1 / 1.2.3+build).
    m = _NPM_EXACT.match(spec)
    if m:
        return m.group(1), True, False, False

    # Range: caret/tilde/comparators/x-ranges/hyphen ranges/OR.
    lead = _NPM_LEADING_VER.search(spec)
    version = lead.group(1) if lead else ""
    # Pad partial versions (1.2 -> 1.2.0) so OSV can match.
    if version and version.count(".") == 1:
        version += ".0"
    elif version and "." not in version:
        version += ".0.0"
    return version, False, True, False


def _parse_requirements(comp: Component) -> list[_Dep]:
    deps = []
    for i, raw in enumerate(comp.text.splitlines(), 1):
        line = raw.split("#", 1)[0].strip()
        if not line or line.startswith("-"):
            continue
        # PEP 508 direct reference (name @ url) — not a registry version.
        if "@" in line and "://" in line.split("@", 1)[1]:
            name = line.split("@", 1)[0].split("[", 1)[0].strip().lower()
            if name:
                deps.append(_Dep(name, "", "pypi", False, i, comp.path, skip_cve=True))
            continue
        m = _PEP_PIN.match(line)
        if not m or not m.group(1):
            continue
        name, op, ver = m.group(1), m.group(2), m.group(3)
        pinned = op in ("==", "===") and bool(ver)
        is_range = bool(op) and not pinned
        deps.append(_Dep(name.lower(), ver or "", "pypi", pinned, i, comp.path, is_range=is_range))
    return deps


def _parse_package_json(comp: Component) -> list[_Dep]:
    deps = []
    try:
        data = json.loads(comp.text)
    except (json.JSONDecodeError, ValueError):
        return deps
    for section in ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies"):
        for name, spec in (data.get(section) or {}).items():
            version, pinned, is_range, skip_cve = parse_npm_spec(str(spec))
            deps.append(_Dep(name.lower(), version, "npm", pinned, 0, comp.path,
                             is_range=is_range, skip_cve=skip_cve))
    return deps


def _collect(components: list[Component]) -> list[_Dep]:
    deps: list[_Dep] = []
    for comp in components:
        base = comp.path.rsplit("/", 1)[-1].lower()
        if base == "requirements.txt" or base.endswith(".requirements.txt"):
            deps.extend(_parse_requirements(comp))
        elif base == "package.json":
            deps.extend(_parse_package_json(comp))
    return deps


def _osv_lookup(deps: list[_Dep]) -> dict[int, list] | None:
    """Return {dep_index: [vuln_ids]} from OSV.dev, or None if unreachable.

    Only deps with a concrete, registry version are queried. Deps with a
    non-registry spec (git/url/alias) or no resolvable version are skipped, so
    we never make a CVE claim we can't substantiate.
    """
    eco_map = {"pypi": "PyPI", "npm": "npm"}
    eligible = [i for i, d in enumerate(deps) if d.version and not d.skip_cve]
    if not eligible:
        return {}
    queries = [
        {"package": {"name": deps[i].name, "ecosystem": eco_map[deps[i].ecosystem]},
         "version": deps[i].version}
        for i in eligible
    ]
    body = json.dumps({"queries": queries}).encode()
    req = urllib.request.Request(
        OSV_BATCH_URL, data=body, headers={"Content-Type": "application/json"}
    )
    try:
        with urllib.request.urlopen(req, timeout=_TIMEOUT) as resp:
            payload = json.loads(resp.read().decode())
    except (urllib.error.URLError, TimeoutError, OSError, ValueError):
        return None
    out: dict[int, list] = {}
    for pos, result in enumerate(payload.get("results", [])):
        vulns = result.get("vulns") or []
        if vulns and pos < len(eligible):
            out[eligible[pos]] = [v.get("id", "UNKNOWN") for v in vulns]
    return out


class DependencyAnalyzer(Analyzer):
    name = "dependencies"

    def __init__(self, use_network: bool = True):
        self.use_network = use_network

    def analyze(self, components: list[Component]) -> list[Finding]:
        deps = _collect(components)
        if not deps:
            return []
        findings: list[Finding] = []

        # Unpinned + typosquat checks (offline, always run).
        for d in deps:
            if d.skip_cve and not d.pinned:
                findings.append(Finding(
                    rule_id="SC007", title="Non-Registry Dependency Source",
                    severity=Severity.MEDIUM, category=Category.SUPPLY_CHAIN,
                    message=f"Dependency '{d.name}' is installed from a git/URL/local source, bypassing registry review and CVE tracking.",
                    component=d.component, line=d.line, evidence=d.name,
                    recommendation="Prefer published, version-pinned registry packages so installs are auditable.",
                    confidence=0.6,
                ))
            elif not d.pinned:
                findings.append(Finding(
                    rule_id="SC001", title="Unpinned Dependency",
                    severity=Severity.LOW, category=Category.SUPPLY_CHAIN,
                    message=f"Dependency '{d.name}' is not pinned to an exact version"
                            + (" (range/caret/tilde)." if d.is_range else "."),
                    component=d.component, line=d.line, evidence=d.name,
                    recommendation="Pin to an exact version (==/exact) for reproducible, auditable installs.",
                    confidence=0.7,
                ))
            for popular in _POPULAR.get(d.ecosystem, set()):
                dist = _levenshtein(d.name, popular)
                if 0 < dist <= 1 and d.name != popular:
                    findings.append(Finding(
                        rule_id="SC006", title="Possible Typosquatting",
                        severity=Severity.HIGH, category=Category.SUPPLY_CHAIN,
                        message=f"Dependency '{d.name}' closely resembles popular package '{popular}'.",
                        component=d.component, line=d.line, evidence=d.name,
                        recommendation=f"Verify the package name. Did you mean '{popular}'?",
                        confidence=0.65,
                    ))

        # Known-CVE checks (OSV.dev live, offline fallback otherwise).
        osv = self._osv_lookup_or_none(deps)
        if osv is not None:
            for idx, vuln_ids in osv.items():
                d = deps[idx]
                # A range spec may resolve to a fixed version, so lower confidence.
                conf = 0.6 if d.is_range else 0.9
                note = (" The manifest uses a range, so the installed version may differ."
                        if d.is_range else "")
                findings.append(Finding(
                    rule_id="SC004", title="Known Vulnerable Dependency",
                    severity=Severity.HIGH, category=Category.VULNERABLE_DEPENDENCY,
                    message=f"'{d.name}' {d.version or ''} has known advisories: "
                            f"{', '.join(vuln_ids[:5])}.{note}",
                    component=d.component, line=d.line, evidence=f"{d.name}=={d.version}",
                    recommendation="Upgrade to a patched version listed in the advisory.",
                    confidence=conf,
                ))
        else:
            findings.extend(self._offline_cve(deps))
        return findings

    def _osv_lookup_or_none(self, deps):
        if not self.use_network:
            return None
        return _osv_lookup(deps)

    def _offline_cve(self, deps: list[_Dep]) -> list[Finding]:
        out = []
        for d in deps:
            for bad_ver, cve, desc in _OFFLINE_VULNS.get((d.ecosystem, d.name), []):
                if d.version and d.version == bad_ver:
                    out.append(Finding(
                        rule_id="SC004", title="Known Vulnerable Dependency (offline DB)",
                        severity=Severity.HIGH, category=Category.VULNERABLE_DEPENDENCY,
                        message=f"'{d.name}' {d.version}: {cve} — {desc}.",
                        component=d.component, line=d.line, evidence=f"{d.name}=={d.version}",
                        recommendation="Upgrade to a patched version. (Offline fallback DB; run online for full coverage.)",
                        confidence=0.85,
                    ))
        return out
