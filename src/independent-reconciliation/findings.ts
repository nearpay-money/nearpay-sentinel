/**
 * Console audit findings (lld/sentinel.md §6): list (default: not `pass` and not acknowledged), get, and
 * acknowledge with a note. Acknowledging only closes the finding in sentinel; the compliance case is worked
 * separately. Acknowledgement writes the finding row and the operator action in one transaction.
 */

import type { RouteQuery } from "@nearpay/spec";
import { sql } from "@nearpay-internal/db";
import { fromUuid, isId, toUuid } from "@nearpay-internal/ids";
import { ApiError } from "@nearpay-internal/service";
import type { listOpsFindings, OpsAuditFinding } from "@nearpay-internal/spec";
import type { z } from "zod";
import type { Sentinel } from "../app/context.js";
import { type OpsActor, recordOpsAction } from "../app/ops-action.js";
import type { AuditFindingsTable } from "../infra/db/schema.js";

type FindingView = z.infer<typeof OpsAuditFinding>;
type Query = RouteQuery<typeof listOpsFindings>;

interface Row {
  id: string;
  execution_id: string;
  account_id: string;
  livemode: boolean;
  check_kind: AuditFindingsTable["check_kind"];
  result: AuditFindingsTable["result"];
  details: Record<string, unknown>;
  tx_chain: string | null;
  tx_hash: string | null;
  created_at: Date;
  acknowledged_at: Date | null;
  acknowledged_by: string | null;
  acknowledgement_note: string | null;
}

const unix = (d: Date) => Math.floor(d.getTime() / 1000);

export function findingView(r: Row): FindingView {
  return {
    id: fromUuid("fnd", r.id),
    object: "audit_finding",
    execution_id: r.execution_id as FindingView["execution_id"],
    account_id: fromUuid("acct", r.account_id) as FindingView["account_id"],
    livemode: r.livemode,
    check_kind: r.check_kind,
    result: r.result,
    details: r.details,
    created: unix(r.created_at),
    tx_chain: r.tx_chain,
    tx_hash: r.tx_hash,
    acknowledged_at: r.acknowledged_at ? unix(r.acknowledged_at) : null,
    acknowledged_by: r.acknowledged_by,
    acknowledgement_note: r.acknowledgement_note,
  } as FindingView;
}

const COLUMNS = [
  "id",
  "execution_id",
  "account_id",
  "livemode",
  "check_kind",
  "result",
  "details",
  "tx_chain",
  "tx_hash",
  "created_at",
  "acknowledged_at",
  "acknowledged_by",
  "acknowledgement_note",
] as const;

async function cursorRow(
  s: Pick<Sentinel, "db">,
  ref: string,
  param: string,
): Promise<{ id: string; created_at: Date }> {
  if (!isId("fnd", ref)) throw ApiError.invalid("must be a fnd_… id", param);
  const row = await s.db
    .selectFrom("audit_findings")
    .select(["id", "created_at"])
    .where("id", "=", toUuid(ref, "fnd"))
    .executeTakeFirst();
  if (!row) throw ApiError.missing("audit_finding", ref, param);
  return row;
}

/** `GET /ops/findings`: ordered by `(created desc, id desc)`; `result` defaults to "not pass", `acknowledged` to false. */
export async function listFindings(s: Pick<Sentinel, "db">, q: Query) {
  const limit = q.limit ?? 10;
  let query = s.db.selectFrom("audit_findings").select(COLUMNS);
  query = q.result ? query.where("result", "=", q.result as Row["result"]) : query.where("result", "<>", "pass");
  query =
    q.acknowledged === "true"
      ? query.where("acknowledged_at", "is not", null)
      : query.where("acknowledged_at", "is", null);
  if (q.account) query = query.where("account_id", "=", toUuid(q.account, "acct"));
  if (q.execution) query = query.where("execution_id", "=", q.execution);
  if (q.livemode) query = query.where("livemode", "=", q.livemode === "true");
  if (q["created[gte]"] !== undefined) query = query.where("created_at", ">=", new Date(q["created[gte]"] * 1000));
  if (q["created[lte]"] !== undefined) query = query.where("created_at", "<", new Date((q["created[lte]"] + 1) * 1000));
  let reverse = false;
  if (q.starting_after) {
    const c = await cursorRow(s, q.starting_after, "starting_after");
    query = query.where(sql<boolean>`(created_at, id) < (${c.created_at}, ${c.id}::uuid)`);
  } else if (q.ending_before) {
    const c = await cursorRow(s, q.ending_before, "ending_before");
    query = query.where(sql<boolean>`(created_at, id) > (${c.created_at}, ${c.id}::uuid)`);
    reverse = true;
  }
  const dir = reverse ? "asc" : "desc";
  const rows = await query
    .orderBy("created_at", dir)
    .orderBy("id", dir)
    .limit(limit + 1)
    .execute();
  const page = rows.slice(0, limit);
  if (reverse) page.reverse();
  return { object: "list" as const, data: page.map(findingView), has_more: rows.length > limit, url: "/ops/findings" };
}

async function findingRow(s: Pick<Sentinel, "db">, ref: string): Promise<Row> {
  const row = await s.db
    .selectFrom("audit_findings")
    .select(COLUMNS)
    .where("id", "=", toUuid(ref, "fnd"))
    .executeTakeFirst();
  if (!row) throw ApiError.missing("audit_finding", ref, "id");
  return row;
}

/** `GET /ops/findings/{id}`. */
export async function getFinding(s: Pick<Sentinel, "db">, ref: string): Promise<FindingView> {
  return findingView(await findingRow(s, ref));
}

/**
 * `POST /ops/findings/{id}/acknowledge`: a `pass` finding or an acknowledged one is `409 state_conflict`
 * (the same operator repeating the same acknowledgement gets the finding back: an idempotent retry).
 */
export async function acknowledgeFinding(
  s: Pick<Sentinel, "db" | "log" | "now">,
  op: OpsActor,
  ref: string,
  note: string,
): Promise<FindingView> {
  const at = new Date(s.now());
  const out = await s.db.transaction().execute(async (t) => {
    const row = await t
      .selectFrom("audit_findings")
      .select(COLUMNS)
      .where("id", "=", toUuid(ref, "fnd"))
      .forUpdate()
      .executeTakeFirst();
    if (!row) throw ApiError.missing("audit_finding", ref, "id");
    if (row.acknowledged_at) {
      if (row.acknowledged_by === op.id && row.acknowledgement_note === note) return row;
      return "acknowledged" as const;
    }
    if (row.result === "pass") return "pass" as const;
    const updated = await t
      .updateTable("audit_findings")
      .set({ acknowledged_at: at, acknowledged_by: op.id, acknowledgement_note: note.slice(0, 2000) })
      .where("id", "=", row.id)
      .returning(COLUMNS)
      .executeTakeFirstOrThrow();
    await recordOpsAction(t, {
      actor: op,
      action: "finding.acknowledged",
      target: { type: "audit_finding", id: ref },
      accountId: fromUuid("acct", row.account_id),
      livemode: row.livemode,
    });
    return updated;
  });
  if (out === "acknowledged") throw new ApiError("state_conflict", { message: "The finding is already acknowledged." });
  if (out === "pass") throw new ApiError("state_conflict", { message: "A passing finding needs no acknowledgement." });
  s.log.warn({ finding: ref, operator: op.id }, "audit finding acknowledged");
  return findingView(out);
}
