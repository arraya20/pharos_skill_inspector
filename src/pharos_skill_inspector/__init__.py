"""Pharos Skill Inspector.

Open-source security scanner for Pharos AI agent skills.

Detects prompt injection, data leakage, vulnerable dependencies, dangerous
code, and Pharos-specific on-chain (Web3) risks in skills built for the
Pharos Skill Engine.
"""

from .models import Component, Finding, ScanResult, Severity
from .engine import scan

__version__ = "0.1.0"

__all__ = [
    "Component",
    "Finding",
    "ScanResult",
    "Severity",
    "scan",
    "__version__",
]
