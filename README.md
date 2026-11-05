# nearpay-sentinel

> Independent second party with its own code, credentials and deploy pipeline: co-signs every deposit instruction shown by checkout after re-reading the quote from 1Click and matching it to an active destination in identity's registry; independently re-reconciles succeeded payments against chain evidence; owns the global quoting kill switch.

| | |
|---|---|
| Group | Services |
| Kind | service |
| Ships as | image: ghcr.io/nearpay-money/sentinel · route /v1/attestations/deposit_instructions; separate credentials |
| Owns | IntegrityCheck, AuditFinding |
| Depends on (published artifacts only) | spec, kit (read-only replicas, 1Click, RPCs) |
| Roadmap phase | P1 Core payments |

## Documentation

This repo stays surgical: design docs live in [`nearpay-brain`](../nearpay-brain/README.md), not here.

- `nearpay-brain/architecture/hld.md` — system design
- `nearpay-brain/architecture/repositories.md` — repo topology and dependency rules
- `nearpay-brain/architecture/security.md`
- `nearpay-brain/decisions/ADR-0012-independent-verification.md`

## Layout

```
nearpay-sentinel/
├── src/
│   ├── address-integrity/
│   ├── co-signer/
│   ├── independent-reconciliation/
│   └── kill-switch/
├── test/
│   ├── integration/
│   └── unit/
└── .github/
    └── workflows/
```

## Status

Scaffold only. Implementation starts in phase **P1 Core payments** (`nearpay-brain/roadmap/roadmap.md`).
