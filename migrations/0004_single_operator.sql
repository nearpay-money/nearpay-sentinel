-- Adaptive two-person rule (lld/sentinel.md §6 "Single-operator platforms"). Additive and forward-only.
--
-- A second, different operator approves a release only while two or more operators can approve. The request
-- records how many active ops_admin operators identity reported when it was made (`requested_admins`; null =
-- unknown, two-person). With one, the requester may complete it alone after the configured wait, with a new
-- confirmation and a written reason; the row is marked `single_operator`. The database still refuses a
-- same-operator approval unless it is marked, was requested with at most one approver, carries a reason and was
-- decided after the request.
alter table release_requests
  add column requested_admins integer check (requested_admins is null or requested_admins >= 0),
  add column single_operator boolean not null default false;

alter table release_requests drop constraint release_approver_differs;
alter table release_requests add constraint release_approver_differs check (
  status <> 'approved' or (
    decided_by is not null and (
      decided_by <> requested_by
      or (single_operator and requested_admins is not null and requested_admins <= 1
          and decision_note is not null and length(btrim(decision_note)) > 0
          and decided_at is not null and decided_at > requested_at))));
-- the marker only ever describes an approval by the requester
alter table release_requests add constraint release_single_operator_self check (
  not single_operator or (status = 'approved' and decided_by = requested_by));

-- the request half (now including requested_admins) never changes once written
create or replace function sentinel_release_transition() returns trigger language plpgsql as $$
begin
  if tg_op = 'DELETE' then
    raise exception 'release_requests rows are never deleted';
  end if;
  if old.status <> 'pending' then
    raise exception 'release request % is already %', old.id, old.status;
  end if;
  if new.id <> old.id or new.reason <> old.reason or new.requested_by <> old.requested_by
     or new.requested_role <> old.requested_role or new.requested_at <> old.requested_at
     or new.expires_at <> old.expires_at or new.switch_version <> old.switch_version
     or new.requested_admins is distinct from old.requested_admins then
    raise exception 'release request % may only be decided', old.id;
  end if;
  return new;
end $$;
