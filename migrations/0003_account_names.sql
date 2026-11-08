-- Spec 0.2.1 (lld/sentinel.md §"Spec 0.2.1 contract changes"): display names of merchant accounts for the
-- console's audit findings (`OpsAuditFinding.account_display_name`), from `evt.identity.account.created` /
-- `.updated`. Display only — never used by the co-signer (which reads identity's registry view).
-- Additive and forward-only.
create table account_names (
  account_id uuid primary key,             -- acct_… as uuid
  display_name text not null,
  version integer not null,                -- envelope aggregate.version of the last applied account event
  updated_at timestamptz not null default now());
