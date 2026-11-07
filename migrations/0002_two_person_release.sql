-- Stage 2 (lld/sentinel.md §4, §6): two-person kill-switch release and console finding acknowledgement.
-- Additive and forward-only.

-- A release request (`OpsApproval`, `opa_` id) waiting for a second operator. `requested_by` / `decided_by`
-- are operator user ids (`usr_…` as uuid), always the `sub` of the verified ops token.
create table release_requests (
  id uuid primary key,
  reason text not null,
  status text not null check (status in ('pending','approved','rejected','expired')),
  requested_by uuid not null,
  requested_role text not null check (requested_role in ('ops','ops_admin')),
  requested_at timestamptz not null default now(),
  decided_by uuid,
  decided_role text check (decided_role in ('ops','ops_admin')),
  decided_at timestamptz,
  decision_note text,
  expires_at timestamptz not null,
  switch_version integer not null,           -- version of the engaged switch the request is for
  -- the two-person rule, repeated in the database: an approval is by a different operator holding ops_admin
  -- (a rejection may be the requester withdrawing, so the rule binds approvals)
  constraint release_approver_differs check (status <> 'approved' or (decided_by is not null and decided_by <> requested_by)),
  constraint release_decided_by_admin check (
    status not in ('approved','rejected') or (decided_by is not null and decided_role = 'ops_admin' and decided_at is not null)),
  constraint release_pending_undecided check (status <> 'pending' or (decided_by is null and decided_at is null)),
  constraint release_expires_after_request check (expires_at > requested_at));
-- at most one pending request (for the singleton switch)
create unique index release_one_pending on release_requests ((true)) where status = 'pending';
create index release_requested_at on release_requests (requested_at desc);

-- Only pending → approved | rejected | expired; a decided request and the request half never change.
create function sentinel_release_transition() returns trigger language plpgsql as $$
begin
  if tg_op = 'DELETE' then
    raise exception 'release_requests rows are never deleted';
  end if;
  if old.status <> 'pending' then
    raise exception 'release request % is already %', old.id, old.status;
  end if;
  if new.id <> old.id or new.reason <> old.reason or new.requested_by <> old.requested_by
     or new.requested_role <> old.requested_role or new.requested_at <> old.requested_at
     or new.expires_at <> old.expires_at or new.switch_version <> old.switch_version then
    raise exception 'release request % may only be decided', old.id;
  end if;
  return new;
end $$;
create trigger release_requests_transition before update or delete on release_requests
  for each row execute function sentinel_release_transition();

-- Console acknowledgement note (`OpsAuditFinding.acknowledgement_note`); `acknowledged_by` is the operator
-- (`usr_…`) or the CLI actor.
alter table audit_findings add column acknowledgement_note text;
