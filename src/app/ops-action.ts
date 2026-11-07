/**
 * Unified console audit trail (lld/sentinel.md §6, T-12): every console write sentinel executes also
 * emits `evt.sentinel.ops_action.recorded` (`OpsActionEvent`, ids only) through the outbox in the same
 * transaction; identity copies it into `audit_events`. `kill_switch_log` and `release_requests` stay the
 * detail source.
 */
import { emit } from "@nearpay-internal/db";
import { fromUuid, isId, toUuid, uuidv7 } from "@nearpay-internal/ids";
import type { Tx } from "./context.js";

export interface OpsActor {
  /** Operator user id (`usr_…`), the `sub` of the verified ops token. */
  readonly id: string;
  readonly role: "ops" | "ops_admin";
}

export interface OpsActionInput {
  readonly actor: OpsActor;
  /** `<object>.<verb>`, e.g. `kill_switch.engaged`, `kill_switch.release_approved`, `finding.acknowledged`. */
  readonly action: string;
  readonly target: { readonly type: string; readonly id: string };
  /** Merchant account concerned (`acct_…`), if any. */
  readonly accountId?: string | null;
  readonly livemode?: boolean | null;
  /** Two-person approval (uuid) the action completed or belongs to, if any. */
  readonly approval?: string | null;
}

export async function recordOpsAction(tx: Tx, a: OpsActionInput): Promise<string> {
  if (!isId("usr", a.actor.id)) throw new Error(`ops action without an operator id (${a.action})`);
  const id = uuidv7();
  // the same clock as the outbox rows written before it in this transaction, so the relay keeps their order
  const at = new Date();
  await emit(tx, {
    subject: "evt.sentinel.ops_action.recorded",
    // The outbox keys aggregates by prefixed id and `ops_action` has no prefix of its own: the action uuid
    // goes out as `aud_…` (it becomes identity's audit event), the object carries the bare uuid (spec).
    aggregate: { type: "ops_action", id: fromUuid("aud", id), version: 1 },
    accountId: a.accountId ? toUuid(a.accountId, "acct") : null,
    livemode: a.livemode ?? null,
    occurredAt: at,
    data: {
      object: {
        id,
        actor: { sub: a.actor.id, ops_role: a.actor.role },
        action: a.action,
        target: { type: a.target.type, id: a.target.id },
        account_id: a.accountId ?? null,
        approval: a.approval ? fromUuid("opa", a.approval) : null,
        occurred_at: at.toISOString(),
      },
    },
  });
  return id;
}
