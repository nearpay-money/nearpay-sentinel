-- nearpay-sentinel (lld/sentinel.md §4). Kit tables (outbox, inbox, idempotency_keys, jobs, dead_letters)
-- come from @nearpay-internal/db migrations. Sentinel reads identity's registry view with its own
-- read-only role (sentinel_ro); it never reads payments' or rails' databases.

create table attestations (
  id uuid primary key,
  livemode boolean not null,
  kind text not null check (kind in ('route_quote','intents_transfer')),
  deposit_key text not null,                 -- provider|address|memo  or  binding
  attempt_id text not null,
  account_id uuid,
  destination_id uuid,
  result text not null check (result in ('signed','rejected','unavailable')),
  class text,                                -- security|ambiguous|stale|unavailable (rejections)
  reasons text[] not null default '{}',
  response jsonb,
  client_ip text,
  expires_at timestamptz,
  created_at timestamptz not null default now());
create index att_key on attestations (deposit_key, created_at desc);
create index att_destination on attestations (destination_id) where result = 'signed';

-- One row per (execution, check): `destination` (the recipient was the account's registered destination
-- when the execution was created) and `settlement` (sentinel's own read of the chain, the sandbox's
-- simulated chain, or the provider's signed status for Tier B). A settlement row that passed on a chain
-- transaction keeps (tx_chain, tx_hash, recipient, asset_id, amount): one transaction can never be
-- attributed to more than it moved (§7, double-use).
create table audit_findings (
  id uuid primary key,
  execution_id text not null,
  account_id uuid not null,
  livemode boolean not null,
  check_kind text not null check (check_kind in ('destination','settlement')),
  result text not null check (result in ('pass','mismatch','unverifiable')),
  details jsonb not null,
  tx_chain text,
  tx_hash text,
  recipient text,
  asset_id text,
  amount numeric(78,0),
  created_at timestamptz not null default now(),
  acknowledged_at timestamptz,
  acknowledged_by text,
  unique (execution_id, check_kind));
create index findings_open on audit_findings (created_at) where result <> 'pass' and acknowledged_at is null;
create index findings_tx on audit_findings (tx_chain, tx_hash) where result = 'pass' and tx_hash is not null;

-- The global quoting kill switch: one row; its version orders engage/release for consumers.
create table kill_switch (
  id smallint primary key check (id = 1),
  engaged boolean not null,
  reason text not null,
  actor text not null,
  version integer not null,
  updated_at timestamptz not null default now());
insert into kill_switch (id, engaged, reason, actor, version) values (1, false, 'initial', 'system', 0);

create table kill_switch_log (
  id uuid primary key,
  engaged boolean not null,
  reason text not null,
  actor text not null,
  version integer not null,
  created_at timestamptz not null default now());

create function sentinel_append_only() returns trigger language plpgsql as $$
begin
  raise exception '% is append-only', tg_table_name;
end $$;
create trigger kill_switch_log_append_only before update or delete on kill_switch_log
  for each row execute function sentinel_append_only();
