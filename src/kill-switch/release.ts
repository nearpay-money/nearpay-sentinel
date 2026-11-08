/**
 * Console kill-switch use cases (lld/sentinel.md §6): state, engage (one operator, no step-up), and the
 * two-person release — request (step-up), approve by a different `ops_admin` (step-up; releases in the same
 * transaction), reject/withdraw. Rules are in ./two-person.ts; here every decision runs with the switch row
 * and the request row locked, and every write commits with its log/outbox rows in ONE transaction.
 */
import { emit } from "@nearpay-internal/db";
import { fromUuid, toUuid, uuidv7 } from "@nearpay-internal/ids";
import { ApiError } from "@nearpay-internal/service";
import type { OpsApproval, OpsKillSwitch as OpsKillSwitchSchema } from "@nearpay-internal/spec";
import type { z } from "zod";
import type { Sentinel, Tx } from "../app/context.js";
import { recordOpsAction } from "../app/ops-action.js";
import type { ReleaseRequestsTable } from "../infra/db/schema.js";
import { expirePending, KILL_SWITCH_ID, type KillSwitchState, setKillSwitch } from "./kill-switch.js";
import {
  canApprove,
  canReject,
  canRequest,
  effectiveStatus,
  type Operator,
  RELEASE_TTL_MS,
  type Refusal,
  type ReleaseRequest,
  releaseActor,
  type SwitchView,
  staleReason,
} from "./two-person.js";

type Ctx = Pick<Sentinel, "db" | "log" | "metrics" | "now">;
export type OpsKillSwitch = z.infer<typeof OpsKillSwitchSchema>;

type Outcome<T> = { readonly refusal: Refusal } | ({ readonly refusal?: undefined } & T);

interface Row {
  id: string;
  reason: string;
  status: ReleaseRequestsTable["status"];
  requested_by: string;
  requested_role: "ops" | "ops_admin";
  requested_at: Date;
  decided_by: string | null;
  decided_role: "ops" | "ops_admin" | null;
  decided_at: Date | null;
  decision_note: string | null;
  expires_at: Date;
  switch_version: number;
}

const unix = (d: Date) => Math.floor(d.getTime() / 1000);

function domain(r: Row): ReleaseRequest {
  return {
    id: r.id,
    reason: r.reason,
    status: r.status,
    requestedBy: fromUuid("usr", r.requested_by),
    requestedRole: r.requested_role,
    expiresAtMs: r.expires_at.getTime(),
    switchVersion: r.switch_version,
    decidedBy: r.decided_by ? fromUuid("usr", r.decided_by) : null,
  };
}

/** `OpsApproval` view of a release request (a pending request past its validity reads `expired`). */
export function approvalView(r: Row, sw: SwitchView, nowMs: number): OpsApproval {
  return {
    id: fromUuid("opa", r.id),
    object: "ops_approval",
    action: "kill_switch.release",
    target: { type: "kill_switch", id: KILL_SWITCH_ID },
    reason: r.reason,
    status: effectiveStatus(domain(r), sw, nowMs),
    requested_by: { id: fromUuid("usr", r.requested_by), role: r.requested_role },
    requested_at: unix(r.requested_at),
    decided_by: r.decided_by && r.decided_role ? { id: fromUuid("usr", r.decided_by), role: r.decided_role } : null,
    decided_at: r.decided_at ? unix(r.decided_at) : null,
    decision_note: r.decision_note,
    expires_at: unix(r.expires_at),
  };
}

function stateView(st: KillSwitchState, pending: OpsApproval | null): OpsKillSwitch {
  return {
    engaged: st.engaged,
    reason: st.reason,
    actor: st.actor,
    updated_at: st.updated_at.toISOString(),
    version: st.version,
    pending_release: pending,
  };
}

async function lockSwitch(t: Tx): Promise<KillSwitchState> {
  return t.selectFrom("kill_switch").selectAll().where("id", "=", 1).forUpdate().executeTakeFirstOrThrow();
}

async function pendingRow(t: Tx | Ctx["db"], lock: boolean): Promise<Row | undefined> {
  const q = t.selectFrom("release_requests").selectAll().where("status", "=", "pending");
  return (lock ? q.forUpdate() : q).executeTakeFirst();
}

function refuse(r: Refusal): never {
  if (r.error === "state_conflict") throw new ApiError("state_conflict", { message: `${r.reason}.` });
  // the catalogue message is "This approval needs a different approver: {reason}" — fill it
  if (r.error === "approver_conflict") throw new ApiError("approver_conflict", { params: { reason: r.reason } });
  // permission_denied's catalogue message has an {action} placeholder (step_up_required has none)
  throw new ApiError(r.error, { params: { action: "perform this action" } });
}

/** `GET /ops/kill_switch`. */
export async function opsKillSwitch(s: Ctx): Promise<OpsKillSwitch> {
  const st = await s.db.selectFrom("kill_switch").selectAll().where("id", "=", 1).executeTakeFirstOrThrow();
  const p = await pendingRow(s.db, false);
  const now = s.now();
  const view = p ? approvalView(p, st, now) : null;
  return stateView(st, view && view.status === "pending" ? view : null);
}

/**
 * `POST /ops/kill_switch/engage`: one operator, no step-up. Engaging an engaged switch changes nothing (no
 * event); any pending release request is expired either way (an operator pressing engage objects to it).
 */
export async function engageByOperator(s: Ctx, op: Operator, reason: string): Promise<OpsKillSwitch> {
  const st = await s.db.transaction().execute(async (t) => {
    const cur = await lockSwitch(t);
    const expired = await expirePending(t, `engaged again by ${op.id}`);
    const next = await setKillSwitch(s, true, reason, op.id, t);
    if (next.version !== cur.version || expired > 0)
      await recordOpsAction(t, {
        actor: op,
        action: "kill_switch.engaged",
        target: { type: "kill_switch", id: KILL_SWITCH_ID },
      });
    return next;
  });
  return stateView(st, null);
}

/**
 * `POST /ops/kill_switch/release_requests`: only while engaged, one pending at a time; emits
 * `evt.sentinel.kill_switch.release_requested` (notify pages the security contacts).
 */
export async function requestRelease(
  s: Ctx,
  op: Operator,
  reason: string,
): Promise<{ approval: OpsApproval; replayed: boolean }> {
  const nowMs = s.now();
  const out = await s.db
    .transaction()
    .execute(async (t): Promise<Outcome<{ approval: OpsApproval; replayed: boolean }>> => {
      const sw = await lockSwitch(t);
      let pending = await pendingRow(t, true);
      if (pending && staleReason(domain(pending), sw, nowMs) !== null) {
        await expire(t, pending.id, staleReason(domain(pending), sw, nowMs) as string);
        pending = undefined;
      }
      const v = canRequest(op, sw, pending ? domain(pending) : null, reason, nowMs);
      if (!v.ok) return { refusal: v };
      if (v.replay && pending) return { approval: approvalView(pending, sw, nowMs), replayed: true };
      const id = uuidv7();
      const row = await t
        .insertInto("release_requests")
        .values({
          id,
          reason: reason.slice(0, 500),
          status: "pending",
          requested_by: toUuid(op.id, "usr"),
          requested_role: op.role,
          requested_at: new Date(nowMs),
          expires_at: new Date(nowMs + RELEASE_TTL_MS),
          switch_version: sw.version,
        })
        .returningAll()
        .executeTakeFirstOrThrow();
      const approval = approvalView(row, sw, nowMs);
      await emit(t, {
        subject: "evt.sentinel.kill_switch.release_requested",
        aggregate: { type: "ops_approval", id: approval.id, version: 1 },
        accountId: null,
        livemode: null,
        data: { object: approval },
      });
      await recordOpsAction(t, {
        actor: op,
        action: "kill_switch.release_requested",
        target: { type: "kill_switch", id: KILL_SWITCH_ID },
        approval: id,
      });
      return { approval, replayed: false };
    });
  if (out.refusal) refuse(out.refusal);
  if (!out.replayed) s.log.warn({ operator: op.id, approval: out.approval.id }, "ALERT kill-switch release requested");
  return out;
}

async function expire(t: Tx, id: string, why: string): Promise<void> {
  await t
    .updateTable("release_requests")
    .set({ status: "expired", decision_note: why.slice(0, 500) })
    .where("id", "=", id)
    .where("status", "=", "pending")
    .execute();
}

async function lockRequest(t: Tx, opa: string): Promise<Row> {
  const row = await t
    .selectFrom("release_requests")
    .selectAll()
    .where("id", "=", toUuid(opa, "opa"))
    .forUpdate()
    .executeTakeFirst();
  if (!row) throw ApiError.missing("ops_approval", opa, "id");
  return row;
}

/**
 * `POST /ops/kill_switch/release_requests/{id}/approve`: the second operator. In one transaction: request
 * `approved`, switch released (version + 1, log row with actor `<requester>+<approver>`, outbox `released`)
 * and the operator action. A request that is no longer valid is recorded `expired` and answered 409.
 */
export async function approveRelease(s: Ctx, op: Operator, opa: string, note?: string): Promise<OpsKillSwitch> {
  const nowMs = s.now();
  const out = await s.db.transaction().execute(async (t): Promise<Outcome<{ state: KillSwitchState }>> => {
    const sw = await lockSwitch(t);
    const row = await lockRequest(t, opa);
    const v = canApprove(op, domain(row), sw, nowMs);
    if (!v.ok) {
      if (v.error === "state_conflict" && v.expire) await expire(t, row.id, v.reason);
      return { refusal: v };
    }
    if (v.replay) return { state: sw };
    await t
      .updateTable("release_requests")
      .set({
        status: "approved",
        decided_by: toUuid(op.id, "usr"),
        decided_role: op.role,
        decided_at: new Date(nowMs),
        decision_note: note ? note.slice(0, 500) : null,
      })
      .where("id", "=", row.id)
      .execute();
    const actor = releaseActor(fromUuid("usr", row.requested_by), op.id);
    const next = await setKillSwitch(s, false, row.reason, actor, t);
    if (next.engaged || next.version !== sw.version + 1) throw new Error("release did not apply"); // rolls back
    await recordOpsAction(t, {
      actor: op,
      action: "kill_switch.release_approved",
      target: { type: "kill_switch", id: KILL_SWITCH_ID },
      approval: row.id,
    });
    return { state: next };
  });
  if (out.refusal) refuse(out.refusal);
  return stateView(out.state, null);
}

/** `POST /ops/kill_switch/release_requests/{id}/reject`: rejects or (by the requester) withdraws. */
export async function rejectRelease(s: Ctx, op: Operator, opa: string, note: string): Promise<OpsApproval> {
  const nowMs = s.now();
  const out = await s.db.transaction().execute(async (t): Promise<Outcome<{ approval: OpsApproval }>> => {
    const sw = await lockSwitch(t);
    const row = await lockRequest(t, opa);
    const v = canReject(op, domain(row), sw, nowMs);
    if (!v.ok) {
      if (v.error === "state_conflict" && v.expire) await expire(t, row.id, v.reason);
      return { refusal: v };
    }
    if (v.replay) return { approval: approvalView(row, sw, nowMs) };
    const updated = await t
      .updateTable("release_requests")
      .set({
        status: "rejected",
        decided_by: toUuid(op.id, "usr"),
        decided_role: op.role,
        decided_at: new Date(nowMs),
        decision_note: note.slice(0, 500),
      })
      .where("id", "=", row.id)
      .returningAll()
      .executeTakeFirstOrThrow();
    await recordOpsAction(t, {
      actor: op,
      action:
        fromUuid("usr", row.requested_by) === op.id ? "kill_switch.release_withdrawn" : "kill_switch.release_rejected",
      target: { type: "kill_switch", id: KILL_SWITCH_ID },
      approval: row.id,
    });
    return { approval: approvalView(updated, sw, nowMs) };
  });
  if (out.refusal) refuse(out.refusal);
  return out.approval;
}

/** `GET /ops/kill_switch/log`: newest first, `before_version` cursor. */
export async function killSwitchLog(
  s: Pick<Sentinel, "db">,
  q: { limit?: number | undefined; before_version?: number | undefined },
) {
  const limit = q.limit ?? 10;
  let query = s.db
    .selectFrom("kill_switch_log")
    .selectAll()
    .orderBy("version", "desc")
    .limit(limit + 1);
  if (q.before_version !== undefined) query = query.where("version", "<", q.before_version);
  const rows = await query.execute();
  return {
    object: "list" as const,
    data: rows.slice(0, limit).map((r) => ({
      engaged: r.engaged,
      reason: r.reason,
      actor: r.actor,
      version: r.version,
      created_at: unix(r.created_at),
    })),
    has_more: rows.length > limit,
    url: "/ops/kill_switch/log",
  };
}
