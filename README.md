# Pharos Skill Inspector

**Open-source security scanner for [Pharos](https://www.pharos.xyz) AI agent skills.**
Detect **prompt injection**, **data leakage**, **vulnerable dependencies**, **dangerous code**, and **on-chain (Web3) risks** *before* you install or publish a skill.

Built for the [Pharos AI Agent Carnival](https://www.pharos.xyz/agent-carnival) Skill Hackathon, and inspired by [NVIDIA/SkillSpector](https://github.com/NVIDIA/SkillSpector).

---

## Why this exists

Pharos [Skill Engine](https://docs.pharos.xyz/tooling-and-infrastructure/pharos-skill-engine-guide) skills aren't passive documentation — an AI agent reads `SKILL.md` and then executes real `cast`/`forge` commands that **move funds, deploy contracts, and run airdrops** using your wallet `$PRIVATE_KEY`.

That makes a malicious or careless skill far more dangerous than a normal package. A single hidden instruction or a swapped RPC endpoint can drain a wallet. Generic scanners don't understand this on-chain attack surface — **Pharos Skill Inspector does.**

> Research on 42k+ skills (Liu et al., 2026, cited by SkillSpector) found **26.1%** contain a vulnerability and **5.2%** show likely malicious intent. Skills with executable scripts are **2.12×** more likely to be vulnerable — and Pharos skills are executable by design.

## What it detects

| Category | Examples |
|----------|----------|
| **Prompt injection** | Instruction override, pre-check/safety bypass, role hijack, behaviour manipulation, system-prompt leakage, hidden Unicode (zero-width/RTL), hidden HTML-comment directives |
| **Data leakage** | Env-variable harvesting, secrets sent over the network, secrets written to disk / logged, conversation exfiltration, SSH/cloud/wallet credential access; **multi-line taint tracking** (private-key/secret source → network/file/shell/log sink) |
| **Dangerous code** | Python AST: `exec`/`eval`/`__import__`/`compile`, `subprocess`(+`shell=True`), `os.system`, dynamic `getattr`, exec-with-dynamic-source; **token-aware JS/TS** (`eval`/`Function`/`child_process`, env enumeration) that ignores comments/strings; cross-language `curl \| bash`, obfuscated/encoded execution, destructive FS commands |
| **Vulnerable dependencies** | Live [OSV.dev](https://osv.dev) CVE lookups (PyPI/npm) with offline fallback, robust semver/range parsing, unpinned versions, non-registry (git/url) sources, typosquatting of popular Web3 packages |
| **Pharos Web3 (on-chain)** | Hardcoded private keys / mnemonics, key passed on CLI or read from file, key exfiltration, **unlimited ERC20 approvals**, **non-Pharos RPC endpoints**, auto-broadcast writes without pre-checks, **capability/intent mismatch** (SKILL.md says read-only, code writes); **Solidity contract risks** (`tx.origin` auth, `selfdestruct`, `delegatecall`, unprotected withdrawals, floating pragma) |

Each finding includes a rule ID, severity, location, redacted evidence, confidence, and a concrete fix. Secrets are **always redacted** in output — the scanner never echoes a private key.

## Install

```bash
git clone https://github.com/arraya20/pharos_skill_inspector pharos-skill-inspector
cd pharos-skill-inspector

python3 -m venv .venv && source .venv/bin/activate
pip install -e .            # add ".[dev]" for the test suite
```

Zero required runtime dependencies — it runs on a clean Python 3.10+ install (OSV.dev lookups use the standard library).

## Usage

```bash
# Scan a skill directory, a single SKILL.md, or a .zip archive
pharos-skill-inspector scan ./my-skill/
pharos-skill-inspector scan ./my-skill/SKILL.md
pharos-skill-inspector scan ./my-skill.zip

# Scan a remote source by URL (auto-cloned/downloaded to a temp dir, then cleaned up)
pharos-skill-inspector scan https://github.com/owner/some-skill   # git repo (shallow clone)
pharos-skill-inspector scan https://example.com/skill.zip          # remote .zip archive

# Output formats: terminal (default), json, markdown, sarif
pharos-skill-inspector scan ./my-skill/ --format json   -o report.json
pharos-skill-inspector scan ./my-skill/ --format sarif   -o report.sarif

# Offline (skip OSV.dev network lookups)
pharos-skill-inspector scan ./my-skill/ --no-network

# CI gate: exit non-zero when risk reaches a threshold
pharos-skill-inspector scan ./my-skill/ --fail-on high
```

`psi` is a shorter alias for the same command.

### Try the examples

```bash
pharos-skill-inspector scan examples/benign-skill      # → 0/100, SAFE
pharos-skill-inspector scan examples/malicious-skill   # → 100/100, DO NOT INSTALL
```

## Risk scoring

Confidence-weighted severity points (CRITICAL +50, HIGH +25, MEDIUM +10, LOW +5),
summed **per severity with diminishing caps** (HIGH ≤75, MEDIUM ≤30, LOW ≤12;
CRITICAL uncapped) so a pile of low-severity noise can't alone reach
"DO NOT INSTALL", while a single CRITICAL still fails the skill. ×1.3 when the
skill ships executable scripts, clamped to 100.

| Score | Severity | Recommendation |
|-------|----------|----------------|
| 0–20 | LOW | SAFE |
| 21–50 | MEDIUM | CAUTION |
| 51–80 | HIGH | DO NOT INSTALL |
| 81–100 | CRITICAL | DO NOT INSTALL |

## How it works

```
load (dir / file / zip / URL)  →  detect components (md, py, js, ts, sol, json, sh)
        │
        ▼
  ┌──────────────────── static analyzers ────────────────────┐
  │ prompt_injection   regex + unicode/HTML scan              │
  │ data_leakage       regex (secret-aware)                   │
  │ dangerous_code     Python AST + cross-lang regex          │
  │ javascript         token-aware JS/TS (comment/str masked) │
  │ solidity           on-chain contract risk patterns        │
  │ dependencies       OSV.dev live + offline fallback + ...  │
  │ pharos_web3        on-chain rules (keys/RPC/approvals/...) │
  │ taint              Python def-use secret→sink flows       │
  └────────────────────────────────────────────────────────────┘
        │
        ▼
  dedupe → risk score → report (terminal / json / markdown / sarif)
```

Static analysis only; no code is executed. The architecture is modular — add a new
analyzer by subclassing `Analyzer` and registering it in `engine.build_analyzers`.

## Project layout

```
src/pharos_skill_inspector/
  models.py        Finding / Component / ScanResult / Severity / Category
  loader.py        directory / file / zip loader + SKILL.md frontmatter
  scoring.py       risk score + severity bands
  engine.py        orchestration
  report.py        terminal / json / markdown / sarif renderers
  cli.py           `pharos-skill-inspector` / `psi` entrypoint
  analyzers/       prompt_injection, data_leakage, dangerous_code (Python AST),
                   javascript (token-aware JS/TS), solidity (on-chain),
                   dependencies (OSV.dev), pharos_web3, taint (secret flows)
  analyzers/textproc.py  comment/string masking for token-aware scanning
examples/          benign-skill (clean) + malicious-skill (demonstrates rules)
tests/             pytest suite (81 tests, ~88% coverage)
.github/workflows/ CI: test matrix (Py 3.10–3.13) + example self-scan gate
```

## Development

```bash
pip install -e ".[dev]"
python -m pytest -q
python -m pytest --cov=pharos_skill_inspector --cov-report=term-missing
```

## Limitations

- Static analysis only — no dynamic/runtime behaviour, no analysis of compiled or
  encrypted content, limited to text (no image-based attacks).
- Pattern-based detection trades some precision for recall; review findings in context.
- Offline mode uses a small fallback CVE list; run online for full OSV.dev coverage.

## License

MIT. See [LICENSE](./LICENSE).

Not affiliated with or endorsed by Pharos or NVIDIA. "SkillSpector" is referenced as prior art.
