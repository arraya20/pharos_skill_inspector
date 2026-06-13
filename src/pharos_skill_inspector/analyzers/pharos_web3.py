"""Pharos Web3 / on-chain analyzer — the Pharos-specific differentiator.

Pharos Skill Engine skills drive REAL on-chain actions through ``cast``/``forge``
using a wallet ``$PRIVATE_KEY``. That gives them an attack surface generic skill
scanners miss:

  * Hardcoded private keys / mnemonics (the #1 rule in the Skill Engine docs:
    "Never hardcode your private key ... always use the $PRIVATE_KEY env var").
  * Private-key exfiltration (key flows to a network call or a file).
  * Hidden / hardcoded transaction recipients (silent fund redirection).
  * Unlimited ERC20 approvals (wallet-drain primitive).
  * Non-Pharos RPC endpoints (key harvesting / MITM via a swapped RPC).
  * Auto-broadcast writes that bypass the mandatory Write-Operation pre-checks.
  * Capability/intent mismatch: SKILL.md advertises read-only but the code
    performs write operations (under-declared capability).
"""

from __future__ import annotations

import re

from ..models import Category, Component, Finding, Severity
from . import Analyzer, RegexRule, run_regex_rules, line_of, snippet, redact

_CODE_KINDS = ("python", "javascript", "typescript", "shell", "template", "solidity")

# Domains considered legitimate (Pharos + well-known infra / explorers / public
# chain RPCs / package registries). A skill using these is not "swapping the RPC".
_ALLOWED_RPC = re.compile(
    r"("
    # Pharos
    r"dplabs-internal\.com|pharos\.xyz|pharosnetwork\.xyz|pharosscan\.xyz|socialscan\.io|"
    # Foundry installer + localhost
    r"paradigm\.xyz|localhost|127\.0\.0\.1|0\.0\.0\.0|"
    # package registries (lockfile resolved URLs)
    r"registry\.npmjs\.org|registry\.yarnpkg\.com|npmjs\.org|pypi\.org|files\.pythonhosted\.org|"
    # well-known RPC / node infra
    r"alchemy\.com|alchemyapi\.io|infura\.io|quicknode\.com|quiknode\.pro|ankr\.com|"
    r"publicnode\.com|llamarpc\.com|blockpi\.network|drpc\.org|blastapi\.io|nodereal\.io|"
    r"chainstack\.com|getblock\.io|1rpc\.io|omniatech\.io|tenderly\.co|"
    # explorers
    r"etherscan\.io|polygonscan\.com|bscscan\.com|arbiscan\.io|basescan\.org|blockscout\.com|"
    # public chain endpoints
    r"solana\.com|sui\.io|cloudflare-eth\.com|ethereum\.org|binance\.org|polygon-rpc\.com"
    r")",
    re.IGNORECASE,
)
_URL_RE = re.compile(r"https?://[^\s'\"`)]+", re.IGNORECASE)
# Require a *real* RPC signal before flagging a URL: either the URL host/path
# itself mentions rpc, or the surrounding line is an explicit RPC/provider
# assignment. (The old loose match flagged AI-provider URLs and npm packages
# that merely contained the word "provider"/"rpc".)
_RPC_URL_HINT = re.compile(r"(rpc|json-?rpc)", re.IGNORECASE)
_RPC_LINE_HINT = re.compile(
    r"(rpc[_-]?url|--rpc-url|\bRPC\b|JsonRpcProvider|getDefaultProvider|"
    r"createPublicClient|new\s+ethers\.providers|new\s+Web3|HttpProvider|"
    r"\.connect\(|chainId)",
    re.IGNORECASE,
)
# Dependency lockfiles: full of registry tarball URLs; never an RPC config.
_LOCKFILES = {
    "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "npm-shrinkwrap.json",
    "bun.lockb", "composer.lock", "cargo.lock", "poetry.lock", "gemfile.lock",
}

# Private key literal: 0x + 64 hex chars.
_PRIVKEY_RE = re.compile(r"0x[a-fA-F0-9]{64}\b")
# A mnemonic: 12 or 24 lowercase words on one line (rough heuristic).
_MNEMONIC_RE = re.compile(r"\b([a-z]{3,8}\s+){11}([a-z]{3,8})(\s+([a-z]{3,8}\s+){11}([a-z]{3,8}))?\b")
# Max-uint approval values.
_MAX_UINT = re.compile(
    r"(0x[fF]{64}|2\s*\*\*\s*256\s*-\s*1|115792089237316195423570985008687907853269984665640564039457584007913129639935|MaxUint256|ethers\.MaxUint256|type\(uint256\)\.max)"
)

RULES = [
    RegexRule(
        rule_id="W004",
        title="Auto-Broadcast Write Without Pre-Checks",
        severity=Severity.MEDIUM,
        category=Category.PHAROS_WEB3,
        pattern=r"forge\s+script[^\n]*--broadcast|cast\s+send\b",
        message="Skill issues an on-chain write (cast send / forge --broadcast). Verify it is gated by the four pre-checks and explicit user confirmation.",
        recommendation="Ensure every write runs the Write-Operation pre-checks (private key, address, network, balance) and asks the user before broadcasting.",
        kinds=_CODE_KINDS + ("markdown",),
        confidence=0.5,
    ),
    RegexRule(
        rule_id="W007",
        title="Private Key Passed on Command Line",
        severity=Severity.MEDIUM,
        category=Category.PHAROS_WEB3,
        pattern=r"--private-key\s+(0x[a-fA-F0-9]{64}|[\"']?0x[a-fA-F0-9]{64})",
        message="A literal private key is passed on the command line instead of the $PRIVATE_KEY env var.",
        recommendation="Use --private-key $PRIVATE_KEY; never inline the key (it leaks into shell history and process lists).",
        kinds=_CODE_KINDS + ("markdown",),
        confidence=0.9,
    ),
    RegexRule(
        rule_id="W009",
        title="Private Key Read From File",
        severity=Severity.HIGH,
        category=Category.PHAROS_WEB3,
        pattern=r"(open|read_text|readFileSync|cat)\s*\(?[^\n]{0,60}(private[_-]?key|\.key|keystore|wallet\.json)",
        message="Code reads wallet key material from a file rather than the process environment.",
        recommendation="Keep the key only in $PRIVATE_KEY; do not persist or read it from disk.",
        kinds=_CODE_KINDS,
        confidence=0.6,
    ),
]


class PharosWeb3Analyzer(Analyzer):
    name = "pharos_web3"

    def analyze(self, components: list[Component]) -> list[Finding]:
        findings = run_regex_rules(RULES, components)
        for comp in components:
            if not comp.text:
                continue
            findings.extend(self._hardcoded_secrets(comp))
            findings.extend(self._unlimited_approval(comp))
            base = comp.path.rsplit("/", 1)[-1].lower()
            if (comp.kind in ("json", "text", "python", "javascript", "typescript", "shell", "template")
                    and base not in _LOCKFILES):
                findings.extend(self._foreign_rpc(comp))
        findings.extend(self._capability_mismatch(components))
        return findings

    # -- hardcoded private key / mnemonic ----------------------------------
    def _hardcoded_secrets(self, comp: Component) -> list[Finding]:
        out: list[Finding] = []
        for m in _PRIVKEY_RE.finditer(comp.text):
            # Ignore obvious placeholders / zero keys.
            val = m.group(0)
            if val.lower() == "0x" + "0" * 64:
                continue
            line_no = line_of(comp.text, m.start())
            out.append(Finding(
                rule_id="W001", title="Hardcoded Private Key",
                severity=Severity.CRITICAL, category=Category.PHAROS_WEB3,
                message="A 64-hex private key literal is embedded in the skill. Anyone who installs it can drain the wallet.",
                component=comp.path, line=line_no,
                evidence=redact(val),
                recommendation="Remove the key immediately and rotate the wallet. Use the $PRIVATE_KEY env var.",
                confidence=0.95,
            ))
        for m in _MNEMONIC_RE.finditer(comp.text):
            line_no = line_of(comp.text, m.start())
            line_txt = comp.text.splitlines()[line_no - 1]
            # Heuristic guard: require a seed/mnemonic hint nearby to cut false positives.
            window = comp.text[max(0, m.start() - 60): m.end() + 20].lower()
            if not re.search(r"(mnemonic|seed|phrase|wallet|recovery)", window):
                continue
            out.append(Finding(
                rule_id="W002", title="Hardcoded Mnemonic / Seed Phrase",
                severity=Severity.CRITICAL, category=Category.PHAROS_WEB3,
                message="A 12/24-word mnemonic appears to be embedded in the skill.",
                component=comp.path, line=line_no, evidence="[mnemonic redacted]",
                recommendation="Remove the seed phrase and rotate the wallet. Never ship recovery phrases.",
                confidence=0.7,
            ))
        return out

    # -- unlimited ERC20 approval ------------------------------------------
    def _unlimited_approval(self, comp: Component) -> list[Finding]:
        out: list[Finding] = []
        for m in re.finditer(r"approve\b", comp.text):
            # look at the rest of the same logical statement / line
            line_no = line_of(comp.text, m.start())
            window = comp.text[m.start(): m.start() + 200]
            if _MAX_UINT.search(window):
                line_txt = comp.text.splitlines()[line_no - 1]
                out.append(Finding(
                    rule_id="W005", title="Unlimited Token Approval",
                    severity=Severity.HIGH, category=Category.PHAROS_WEB3,
                    message="ERC20 approve() grants an unlimited (max-uint) allowance — a wallet-drain primitive if the spender is malicious.",
                    component=comp.path, line=line_no, evidence=snippet(line_txt),
                    recommendation="Approve only the exact amount required, and revoke approvals after use.",
                    confidence=0.8,
                ))
        return out

    # -- foreign / non-Pharos RPC ------------------------------------------
    def _foreign_rpc(self, comp: Component) -> list[Finding]:
        out: list[Finding] = []
        for m in _URL_RE.finditer(comp.text):
            url = m.group(0)
            if _ALLOWED_RPC.search(url):
                continue
            line_no = line_of(comp.text, m.start())
            line_txt = comp.text.splitlines()[line_no - 1]
            # Require a genuine RPC signal: the URL itself looks like an RPC
            # endpoint, OR the line is an explicit RPC/provider assignment.
            if not (_RPC_URL_HINT.search(url) or _RPC_LINE_HINT.search(line_txt)):
                continue
            out.append(Finding(
                rule_id="W006", title="Non-Pharos RPC Endpoint",
                severity=Severity.HIGH, category=Category.PHAROS_WEB3,
                message=f"An RPC/provider endpoint points to a non-Pharos host: {url}",
                component=comp.path, line=line_no, evidence=snippet(line_txt),
                recommendation="Use the official Pharos RPC. A swapped RPC can harvest keys or feed forged chain state.",
                confidence=0.6,
            ))
        return out

    # -- capability / intent mismatch --------------------------------------
    def _capability_mismatch(self, components: list[Component]) -> list[Finding]:
        skill_md = next((c for c in components if c.path.lower().endswith("skill.md")), None)
        if skill_md is None:
            return []
        text = skill_md.text.lower()
        declares_write = bool(re.search(
            r"(cast send|forge .*--broadcast|transfer|deploy|airdrop|approve|write operation|send transaction)",
            text,
        ))
        # Does any code component actually perform a write?
        does_write = False
        loc = None
        for c in components:
            if c.kind in _CODE_KINDS and c.text:
                m = re.search(r"(cast\s+send|forge\s+script[^\n]*--broadcast|sendTransaction|\.transfer\s*\(|writeContract)", c.text)
                if m:
                    does_write = True
                    loc = (c.path, line_of(c.text, m.start()))
                    break
        if does_write and not declares_write:
            return [Finding(
                rule_id="W008", title="Undeclared On-Chain Write Capability",
                severity=Severity.HIGH, category=Category.PHAROS_WEB3,
                message="Skill code performs on-chain write/transfer operations that SKILL.md does not declare in its Capability Index.",
                component=loc[0] if loc else skill_md.path,
                line=loc[1] if loc else 0, evidence="write operation not declared in SKILL.md",
                recommendation="Declare every write capability in the SKILL.md Capability Index so users and agents can audit intent.",
                confidence=0.7,
            )]
        return []
