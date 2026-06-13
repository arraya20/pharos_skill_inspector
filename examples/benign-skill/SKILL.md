---
name: pharos-gas-estimator
description: "Estimate gas costs for Pharos transactions before you send them"
risk: low
source: community
---

# Pharos Gas Estimator

A safe, read-only skill that estimates gas costs for a planned transaction on
the Pharos network so users know the cost before broadcasting anything.

## When to Use This Skill

- Use when the user asks "how much gas will this cost"
- Use before sending a transaction, to preview the fee

## Capability Index

| User Need | Capability | Detailed Instructions |
|-----------|------------|----------------------|
| Estimate gas for a transfer | cast estimate (read-only) | → references/query.md |
| Get current gas price | cast gas-price (read-only) | → references/query.md |

## How It Works

1. Read the official Pharos RPC from `assets/networks.json`.
2. Run `cast estimate` to compute the gas units required.
3. Multiply by `cast gas-price` and present the cost to the user.

This skill never sends transactions and never reads your private key.
