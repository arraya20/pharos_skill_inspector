"""Estimate gas cost for a Pharos transfer (read-only)."""

import json
from pathlib import Path


def load_rpc() -> str:
    config = json.loads((Path(__file__).parent.parent / "assets" / "networks.json").read_text())
    return config["atlantic-testnet"]["rpcUrl"]


def estimate_cost(gas_units: int, gas_price_wei: int) -> int:
    """Return the estimated cost in wei. Pure arithmetic, no side effects."""
    return gas_units * gas_price_wei


if __name__ == "__main__":
    print("RPC:", load_rpc())
    print("Estimated cost (wei):", estimate_cost(21000, 1_000_000_000))
