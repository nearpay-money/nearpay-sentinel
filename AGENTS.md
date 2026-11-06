# AGENTS.md — nearpay-sentinel

You are working in **nearpay-sentinel**, one of 27 NearPay repositories (`nearpay-brain/architecture/repositories.md`).
Scope: Independent second party with its own code, credentials and deploy pipeline: co-signs every deposit instruction shown by checkout after re-reading the quote from 1Click and matching it to an active destination in identity's registry; independently re-reconciles succeeded payments against chain evidence; owns the global quoting kill switch.

## Before changing anything

1. Read `../nearpay-brain/AGENTS.md`, then this repo's LLD (`../nearpay-brain/lld/sentinel.md`) — it is the implementation spec; do not make design decisions it already makes.
2. Contracts (requests, responses, events, errors) come from `@nearpay/spec`. If one must change, open a PR in `nearpay-spec` first; never hand-write contract types here.
3. Check your change against invariants INV-1…INV-9 in `nearpay-brain/product/requirements.md`.

## Rules for this repo

- Layout (LLD §3): `src/address-integrity`, `src/independent-reconciliation/audit.ts` and `src/co-signer/crypto.ts` are pure (no I/O, coverage-gated); the use cases sit next to them (`co-signer/attest.ts`, `independent-reconciliation/auditor.ts`, `kill-switch/`); `src/infra` adapts DB, HTTP clients and chains; `src/api` maps spec routes to use cases.
- Fail closed: any doubt means no signature. Never let an input a payer, merchant or attacker controls engage the kill switch (only a live address rails confirms, after a `security` refusal).
- Trust only the provider's signed status, identity's registry view and sentinel's own RPC reads; rails is asked only whether it issued a deposit address (and, for sampling, asset decimals) — never for a verdict.
- Every state change writes the aggregate row, a transition row and an outbox row in ONE transaction.
- Every public POST honours `Idempotency-Key` inside the same transaction as the side effect.
- Every query filters by `account_id` AND `livemode` (INV-8).
- Money is bigint base units + asset/currency (`@nearpay-internal/money`). No floats.
- Consumers dedupe by event ID (inbox table) and ignore stale `aggregate_version`.

## Never

- Import source code from another NearPay repo (depend on published packages/images only).
- Read or write another service's database.
- Add design documents here — update `nearpay-brain` and link to it.
- Commit secrets, private keys or real customer data.
- Merge changes to paths listed in `.github/CODEOWNERS` without the required human review.
