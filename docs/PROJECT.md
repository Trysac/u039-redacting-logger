# Project record

## Objective

JSON log formatter and filter for stdlib logging that redacts secrets and personal data by key name and by bounded value patterns

## Scope

- In scope: the public API documented in [README.md](../README.md), typed and tested.
- Out of scope: anything that needs runtime dependencies or I/O without an accepted ADR.

## Timeline

| Date | Event |
|---|---|
| 2026 | Repository created from the factory utility template. |

## Effort metrics

Measured values only; a value that has not been measured stays "pending measurement".

| Metric | Value |
|---|---|
| Tokens (input / output) | 570771 / 132905 |
| Hours (human) | pending measurement |
| Cost (USD) | 1.0684 |

## Factory run u039 (measured from API usage)

| Phase | Model | Batch | Input | Output | Cache write | Cache read | Cost (USD) |
|---|---|---|---|---|---|---|---|
| generation | claude-sonnet-5-5 | yes | 3074 | 107293 | 0 | 4246 | 0.5400 |
| fix-1 | claude-sonnet-5-5 | no | 6 | 1793 | 9835 | 43449 | 0.0469 |
| fix-2 | claude-sonnet-5-5 | no | 14 | 2070 | 11480 | 120996 | 0.0615 |
| fix-3 | claude-sonnet-5-5 | no | 8 | 972 | 17075 | 66212 | 0.0590 |
| audit | claude-sonnet-5-5 | no | 10 | 7617 | 38233 | 90445 | 0.1808 |
| fix-4 | claude-sonnet-5-5 | no | 14 | 5136 | 16313 | 133017 | 0.1055 |
| docs | claude-haiku-5-5 | no | 109280 | 8024 | 0 | 0 | 0.0747 |

Total: $1.0684. Prices: Anthropic list prices.
