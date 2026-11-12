-- Resilience amendments (2026-11-12 backend audit; ADR-0028 amendment; lld/sentinel.md §5, §9, §18).
-- Additive and forward-only.
--
-- integrity_breaches.drift: the breach was classified provider-wide drift when recorded (SENTINEL-1: the same
--   format/semantics refusal on several merchants): refused and recorded, never quarantined, never counted
--   toward the systemic rule. Informational: the corroboration window re-derives drift from the reasons.
-- token_lists: the last good provider token list per registry (SENTINEL-4), loaded after a restart while it
--   is younger than 6 hours, so a 1Click /v0/tokens outage at boot does not refuse every live attestation.
alter table integrity_breaches add column drift boolean not null default false;

create table token_lists (
  registry text primary key check (registry in ('live','test')),
  body jsonb not null,
  fetched_at timestamptz not null,
  updated_at timestamptz not null default now());
