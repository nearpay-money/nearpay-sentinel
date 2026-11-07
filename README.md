# nearpay-sentinel

> Independent second party with its own code, credentials and deploy pipeline: co-signs every deposit instruction shown by checkout after re-reading the quote from 1Click and matching it to an active destination in identity's registry; independently re-reconciles succeeded payments against chain evidence; owns the global quoting kill switch.

|                                       |                                                                                                           |
| ------------------------------------- | --------------------------------------------------------------------------------------------------------- |
| Group                                 | Services                                                                                                  |
| Kind                                  | service                                                                                                   |
| Ships as                              | image: ghcr.io/nearpay-money/sentinel · route /v1/attestations/deposit_instructions; separate credentials |
| Owns                                  | IntegrityCheck, AuditFinding                                                                              |
| Depends on (published artifacts only) | spec, kit (read-only replicas, 1Click, RPCs)                                                              |
| First built in                        | Stage 1 (step 1.2)                                                                                        |

## Documentation

This repo stays surgical: design docs live in [`nearpay-brain`](../nearpay-brain/README.md), not here.

- `nearpay-brain/lld/sentinel.md` — **low-level design (dev-ready; implement from this)**
- `nearpay-brain/lld/audits/sentinel.md` — audit findings already folded into the LLD
- `nearpay-brain/roadmap/development-plan.md` — stage and step this repo is built in
- `nearpay-brain/architecture/hld.md` — system design
- `nearpay-brain/architecture/repositories.md` — repo topology and dependency rules
- `nearpay-brain/architecture/security.md`
- `nearpay-brain/decisions/ADR-0012-independent-verification.md`

## Layout

```
nearpay-sentinel/
├── src/
│   ├── main.ts                       process entry: `api` | `worker` | `migrate` | `healthcheck`
│   ├── ops.ts                        Stage 1 ops CLI entry (`node dist/ops.js <command>`, run inside sentinel-api)
│   ├── config.ts                     NP_* configuration (secrets from files)
│   ├── api/                          spec route bindings (co-signing, keys, ops kill switch)
│   ├── app/                          context (cache, metrics, ports) and process wiring
│   ├── address-integrity/            pure: R2–R7 and intents checks, registry match, what an asset id says
│   ├── co-signer/                    ticket gate, RFC 8785 + Ed25519 signing, the co-signing use case
│   ├── independent-reconciliation/   audit rules (pure) and the auditor (own chain reads, findings)
│   ├── kill-switch/                  engage/release, log, outbox events
│   ├── consumers/                    rails settled → audit job; identity destination disabled → cache eviction
│   ├── infra/                        Kysely schemas (own DB, identity's registry view), 1Click/sandbox, NEAR/EVM, rails clients
│   ├── ops/                          ops CLI commands
│   └── workers/                      jobs: audit.execution, kit purge
├── migrations/                       plain SQL (kit tables first, then 0001_sentinel.sql)
├── test/
│   ├── unit/ property/               spec test vectors (tickets, attestations), R1–R7 fixtures, audit rules; any mutation fails verification
│   ├── integration/                  co-signing over HTTP (signed 1Click double), the real nearpay-sandbox image, Anvil, NEAR RPC, NATS, Valkey, ops CLI
│   ├── contract/                     route/subject coverage, provider wire schemas
│   ├── fixtures/                     recorded provider and mainnet responses (see fixtures/README.md)
│   └── support/                      stack (registry view emulation, rails mock from the spec), fakes, Anvil, keys
└── Dockerfile                        distroless Node 22 image, `node dist/main.js <process>`
```

## Commands

| Command                                                                                                     | What it does                                                                                                                                                        |
| ----------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `pnpm install`                                                                                              | Install (Node 22, pnpm 9); `@nearpay/*` and `@nearpay-internal/*` come from the local registry (`.npmrc`, `nearpay-deploy/scripts/up.sh` starts it)                 |
| `pnpm test`                                                                                                 | Unit and property tests                                                                                                                                             |
| `pnpm test:integration`                                                                                     | Integration and contract tests: Postgres, NATS, Valkey, Anvil and the `nearpay/sandbox:local` image in Testcontainers (needs Docker; build the sandbox image first) |
| `pnpm verify`                                                                                               | typecheck + lint + unit tests with the coverage gate (≥ 90 % branches on the pure rules) + integration tests + build                                                |
| `docker build --network host --build-arg NP_REGISTRY_URL=http://127.0.0.1:4873 -t nearpay/sentinel:local .` | Image (what `up.sh` runs)                                                                                                                                           |

## Configuration

| Variable                                                           | Process     | Meaning                                                                                                                                                 |
| ------------------------------------------------------------------ | ----------- | ------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `NP_DB_URL_FILE`                                                   | all         | Own database (app role; migrator role for `migrate`)                                                                                                    |
| `NP_REGISTRY_DB_URL_FILE`                                          | api, worker | identity's database as `sentinel_ro` (SELECT on `sentinel_destination_registry` only; 300 ms)                                                           |
| `NP_SENTINEL_SIGNING_KEY_FILE`                                     | api         | Ed25519 PKCS#8 PEM; **the kid is the file name** `sentinel-<kid>.pem` (else `local-` + 12 hex of the key's SHA-256)                                     |
| `NP_SENTINEL_KEY_NOT_AFTER`, `NP_SENTINEL_ANNOUNCED_KEYS`          | api         | Key retirement and rotation announcements for `GET /v1/attestations/keys` (informational; checkout pins keys at build)                                  |
| `NP_PAYMENTS_TICKET_PUBKEY`                                        | api         | Payments' attestation-ticket key (raw Ed25519, base64url)                                                                                               |
| `NP_IDENTITY_URL`, `NP_SERVICE_CLIENT_SECRET_FILE`, `NP_RAILS_URL` | all         | Service token (client `sentinel`: `rails.read`, `sandbox.use`); rails is asked only "did NearPay issue this address?" and, for sampling, asset decimals |
| `NP_TREASURY_ACCOUNT`, `NP_TEST_TREASURY_ACCOUNT`                  | api         | Fee recipients R6 requires. **Unset live treasury: every live request is refused**                                                                      |
| `NP_ONECLICK_BASE_URL`, `NP_ONECLICK_API_KEY_FILE`                 | api, worker | 1Click `/v0/status` with sentinel's own key (2 s, 1 retry); signatures verified with the SDK's pinned key                                               |
| `NP_SANDBOX_BASE_URL`, `NP_SANDBOX_SIGNING_PUBKEY`                 | api, worker | Test mode (nearpay-sandbox) and its quote key; unset: test-mode requests are unavailable                                                                |
| `NP_PROVIDER_SPLIT`, `NP_REFERRAL`, `NP_INTENTS_CONTRACT`          | all         | 1Click appFees split (R6), referral (R3), Intents contract                                                                                              |
| `NP_VALKEY_URL`                                                    | api, worker | Shared attestation cache (`att:<deposit_key>`); down → in-process per replica                                                                           |
| `NP_NATS_URL`                                                      | worker      | Events in and out                                                                                                                                       |
| `NP_AUDIT_SAMPLE_RATE`, `NP_AUDIT_ALWAYS_USD`                      | worker      | Audit sampling (1.0 in Stages 1–2; at or above USD 10,000 always)                                                                                       |
| `NP_NEAR_RPC_URLS`, `NP_EVM_RPC_URLS_1`, `…_8453`, `…_42161`       | worker      | Shared public pools; `NP_SENTINEL_NEAR_RPC_URLS_FILE` / `NP_SENTINEL_EVM_RPC_URLS_<id>_FILE` (own provider accounts) take precedence                    |

## Behaviour

- **Co-signing (`POST /v1/attestations/deposit_instructions`, anonymous):** the payments ticket gates the request before any provider call (`401 ticket_invalid`). A cached signed attestation is re-served until it expires while its destination is still active. Otherwise sentinel re-reads the deposit from the provider (R1; `503` when it cannot), then checks the provider signature (R2), referral (R3), that checkout's instructions — address, memo, origin asset, amount, deadline **and the deposit chain** — are the provider's (R4), that the recipient is exactly one active destination in identity's registry (R5; several → the single signature-verified one, else `ambiguous`), the appFees (R6, amended: 1Click splits them 50/50 and does not sign them; one treasury entry keeping its share, at most one other, ≤ 500 bps; fee-free passes) and freshness (R7). It signs RFC 8785 JCS of the attestation with Ed25519 and records every outcome in `attestations`.
- **Reactions:** `security` → `409 attestation_refused`; the global kill switch engages **only** when rails confirms NearPay issued the live address. A spoof is counted per IP (5 in 10 min → `429 rate_limited`); rails unreachable → refuse and page. `ambiguous` → `409 attestation_refused`; `stale` (settled, deadline near, or a destination since disabled) → `409 attestation_stale`; registry or provider down → `503 attestation_unavailable`. No input an account or payer controls can engage the switch.
- **Audit (`sentinel-auditor`):** every `evt.rails.execution.settled` is sampled into an `audit.execution` job with two findings: `destination` (the recipient was the account's destination, active when the execution was created) and `settlement` (rails' settlement is self-consistent, then sentinel's own read: EVM receipt ≤ `finalized` with the ERC-20 contract derived from the asset id or the native value; NEAR FINAL with `mt_transfer` by the Intents contract or NEP-141 `ft_transfer`; the sandbox's simulated chain in test mode; the provider's signed status for Tier B). A transaction is never attributed to more than it moved. Not final / not found / unreachable retries for ~85 min, then `unverifiable`. Non-pass findings emit `evt.sentinel.audit_finding.created`.
- **Attested asset (CR-15-07):** every signed attestation carries `asset {asset_id, symbol, decimals}` of the asset the payer sends, read from the provider's token registry with sentinel's own credentials (live 1Click `/v0/tokens`, test: the sandbox's; cached 10 min, stale ≤ 6 h) and, for route quotes, consistent with the signed `amountInFormatted`; otherwise `503 attestation_unavailable`.
- **Kill switch:** one versioned row; every change appends `kill_switch_log` (append-only) and emits `evt.sentinel.kill_switch.engaged|released` in the same transaction. Console (`/ops/kill_switch…`): engage by one operator without step-up; release only by a request (step-up, expires after 1 h, one pending) approved by a **different** `ops_admin` with a fresh step-up (`approver_conflict` otherwise; repeated by a DB check). `POST /internal/kill-switch` and the ops CLI keep engage; their single-person release works only when `NP_ENV` is `local` or `test` and answers `409 two_person_required` on any other value (`server`, unknown, empty). Every console write emits `evt.sentinel.ops_action.recorded`.
- **Refund legs** (`kind: refund`) are audited too: the `destination` finding checks the refund source (`origin.refund_to`), the `settlement` finding the delivery to the payer.

## Ops CLI (Stage 1)

```sh
docker compose -p nearpay exec sentinel-api /nodejs/bin/node dist/ops.js kill-switch
```

`kill-switch` · `kill-switch-engage <reason>` · `kill-switch-release <reason>` (one operator, logged; only when `NP_ENV` is `local`/`test`, otherwise refused with `two_person_required` — use the console's two-person release) · `findings [--all] [--limit N]` · `finding-ack <fnd_…> <note>` · `attestations <pa_… | deposit key | deposit address>`.

## Status

Stage 2 (step 2.2) implemented against `@nearpay/spec` / `@nearpay-internal/spec` 0.2.0 and kit 0.2.0: console routes (kill switch, two-person release, log, findings), operator-action events, attested origin asset (CR-15-07), refund-leg audit; the Stage 1 1Click body normalisation is gone (spec transcribes the live shape).

## Built with

TypeScript 5, Node 22, `@nearpay-internal/*` kit (service, db, bus, http, auth, chains, intents, ids), `@defuse-protocol/one-click-sdk-typescript` (quote signatures), `canonicalize` (RFC 8785), `ioredis` (Valkey cache), `bs58`, Kysely + pg, NATS JetStream; tests with Vitest, fast-check, Testcontainers, Anvil (Foundry) and `@noble/curves`. Code and documentation are written with AI assistance (Claude) under human direction and review.
