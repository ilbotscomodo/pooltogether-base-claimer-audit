# PoolTogether V5 Claimer Economics — Base, September–October 2026

**An open, read-only on-chain research case study from Il Bot Scomodo.**

We tested a simple question: *could a new permissionless prize-claiming bot profit from the rewards observable on a particular PoolTogether V5 PrizePool on Base?*

The answer for this historical sample was **not promising**. This repository is a reproducible audit, **not** an automated trading/claiming bot and **not** a claim of realized income.

## Scope and findings

- Chain: **Base** (8453), not all networks.
- PrizePool: `0x45b2010d8a4f08b53c9fa7544c51dfd9733732cb`.
- Prize token: WETH (`0x4200000000000000000000000000000000000006`).
- Periods: **2026-09-01 through 2026-09-30 UTC**, and **2026-10-01 through 2026-10-09 UTC**.
- Source: `ClaimedPrize` event logs, checked against block timestamps and transaction receipts using Base RPC.

| Measure | September 2026 | October 1–9, 2026 |
| --- | ---: | ---: |
| Claim events | 4,263 | 0 |
| Claim transactions | 127 | 0 |
| Rewards, WETH | 0.002847348004126521 | 0 |
| Estimated rewards, USD | $6.92 | $0 |
| Estimated attributed gas, USD | $5.68 | $0 |
| Estimated aggregate rewards minus gas, USD | **$1.24** | **$0** |

These are *system-level historical estimates*, **not** our bot's earnings. The claim reward receiver may differ from the address paying transaction gas. The audit intentionally leaves `recipient_net_usd_est` blank when that relationship prevents meaningful attribution. USD values use historical prices and are estimates; execution conditions, fees, and reward distribution may change.

**Interpretation:** The sampled Base PrizePool did not demonstrate enough accessible reward value to justify a new €25/month autonomous keeper business. Absence of events in the monitored contract during October 1–9 does **not** establish an absence of activity across PoolTogether as a whole.

## Reproduce the audit

Requirements: Python 3.10+; an Ankr RPC API key (keep it private).

```bash
python -m pip install -r requirements.txt
export ANKR_API_KEY='YOUR_PRIVATE_KEY'      # Windows PowerShell: $env:ANKR_API_KEY='YOUR_PRIVATE_KEY'
python scripts/pooltogether_audit_v5_ankr_rpc.py --probe
python scripts/pooltogether_audit_v5_ankr_rpc.py --chain Base
```

The script uses standard RPC methods, paged log collection with restartable caches, and transaction-receipt verification. It is **read-only**: no private key, wallet connection, transaction signing, token purchase, or spending. RPC provider limits, pricing, and historic node retention may differ on a future run.

The script writes results under `pooltogether_audit_v5/base/` by default. Existing `data/*.csv` files are the archived original study results.

## Recheck the archived report

```bash
python -m unittest discover -s tests -v
```

The tests verify the archived report's count, window, and arithmetic from the provided CSV; they do **not** substitute for an independent replay of the chain RPC calls.

## Caveats and methodology

1. Restrict the audit to the named Base contract and UTC windows.
2. Verify emitted event topics and related transaction receipts rather than inferring rewards from pool APY or promotional material.
3. Allocate transaction gas across claim events so multiple claims in a single transaction do not multiply gas cost.
4. Convert rewards and gas to approximate USD using historic token prices when available.
5. Keep aggregate economic estimates separate from any individual operator's profit. A new bot has no claim to historical rewards.
6. Avoid extrapolating September into expected future income. This is a feasibility screen, not financial advice.

## Data files

- `data/monthly_summary.csv` — aggregated periods and completeness flags.
- `data/operators.csv` — public reward-recipient summary; addresses are public on-chain identifiers.
- `data/events.csv` — individual archived claim events and receipt-based estimates.
- `scripts/pooltogether_audit_v5_ankr_rpc.py` — the read-only audit code.

## Author / project

**Il Bot Scomodo** — publicly documenting AI-assisted research, successes, and unsuccessful experiments, with transparent numbers.  
Research code and explanations produced with AI assistance under human oversight.

All findings are limited to the specified dataset; no revenue was earned by this project in the historical experiment.