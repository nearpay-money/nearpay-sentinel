# Recorded fixtures

Public responses recorded from mainnet services (copied from nearpay-rails' fixtures; no account data).

| File | Source | Recorded |
|---|---|---|
| `oneclick/dry-quote.json` (+ `.request.json`) | 1Click `POST /v0/quote` (dry): appFees echoed split 50/50, signature verifies with the SDK's pinned key | 2026-11-05 |
| `oneclick/status-404.json` | 1Click `GET /v0/status` for an unknown deposit address | 2026-11-06 |
| `near/tx-intents-transfer.json` | NEAR RPC `EXPERIMENTAL_tx_status`: one `intents.near` batch with two `mt_transfer`s | 2026-11-06 |
| `near/tx-usdc-ft-transfer.json` | NEAR RPC `EXPERIMENTAL_tx_status`: a USDC NEP-141 `ft_transfer` | 2026-11-06 |
| `near/tx-unknown.json` | NEAR RPC `UNKNOWN_TRANSACTION` | 2026-11-06 |

Live 1Click statuses with deposit addresses are built by the signed 1Click double (`test/support/fakes.ts`):
a live deposit cannot be recorded without moving funds. The attestation and ticket vectors come from
`@nearpay-money/spec/test-vectors` (shared with payments and checkout).
