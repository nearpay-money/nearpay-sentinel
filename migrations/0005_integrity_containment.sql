-- Integrity containment (ADR-0028, lld/sentinel.md §5 "Containment", owner directive 2026-11-12: "the service
-- should never stop"). Additive and forward-only.
--
-- integrity_breaches: every `security` refusal on a deposit address rails confirmed NearPay issued, with full
--   detail (append-only). `evidence = 'pipeline'` rows on live addresses feed the corroboration (systemic)
--   rule; `request` rows (fields only the caller supplied) are recorded but never stop anything.
-- quarantines: one row per (account, mode); `active` until `expires_at` (auto-expiry) or until ops clear it.
--   While active, sentinel signs no deposit instructions for that account's destinations in that mode.
-- quarantine_log: every quarantine change (append-only), the transition record.
-- audit_findings gains check_kind 'attestation' (a pipeline breach on a live NearPay address; emitted as
--   evt.sentinel.audit_finding.created so compliance opens a case and notify pages).

create table integrity_breaches (
  id uuid primary key,
  livemode boolean not null,
  evidence text not null check (evidence in ('pipeline','request')),
  rules text[] not null,                     -- R2 … R6 / intents
  reasons text[] not null,
  attempt_id text not null,
  deposit_address text,
  deposit_memo text,
  execution_id text,                         -- rails' answer (scoping only, never a verdict)
  account_id uuid,                           -- rails' answer: the execution's account
  destination_account_id uuid,               -- identity's registry: the account the quote pays (R5 matched)
  client_ip text,
  quarantined boolean not null default false,
  systemic boolean not null default false,   -- this refusal completed the corroboration and engaged the switch
  created_at timestamptz not null default now());
create index integrity_breaches_window on integrity_breaches (created_at) where livemode and evidence = 'pipeline';
create index integrity_breaches_account on integrity_breaches (account_id, livemode, created_at desc);
create trigger integrity_breaches_append_only before update or delete on integrity_breaches
  for each row execute function sentinel_append_only();

create table quarantines (
  account_id uuid not null,
  livemode boolean not null,
  status text not null check (status in ('active','cleared')),
  reason text not null,
  breach_id uuid references integrity_breaches(id),
  created_by text not null,
  created_at timestamptz not null default now(),
  expires_at timestamptz not null,
  cleared_at timestamptz,
  cleared_by text,
  clear_note text,
  version integer not null default 1,
  updated_at timestamptz not null default now(),
  primary key (account_id, livemode),
  check (status <> 'cleared' or (cleared_at is not null and cleared_by is not null)));
create index quarantines_active on quarantines (expires_at) where status = 'active';

create table quarantine_log (
  id uuid primary key,
  account_id uuid not null,
  livemode boolean not null,
  action text not null check (action in ('quarantined','extended','cleared')),
  reason text not null,
  actor text not null,
  expires_at timestamptz,
  version integer not null,
  created_at timestamptz not null default now());
create index quarantine_log_account on quarantine_log (account_id, livemode, created_at desc);
create trigger quarantine_log_append_only before update or delete on quarantine_log
  for each row execute function sentinel_append_only();

alter table audit_findings drop constraint audit_findings_check_kind_check;
alter table audit_findings add constraint audit_findings_check_kind_check
  check (check_kind in ('destination','settlement','attestation'));
