/**
 * Quarantine log rows and bulk clearing of sentinel's own quarantines (SENTINEL-2, ADR-0028 amendment
 * 2026-11-12). Bulk clearing only ever removes holds sentinel created and nobody touched since: a quarantine an
 * operator created (`created_by` ≠ `sentinel`) or extended (its latest `quarantine_log` row has another actor)
 * is kept. Every cleared row gets a `cleared` transition with the actor and note, in the caller's transaction.
 *
 * These are the only cross-account quarantine writes (like the corroboration window, by design): each row is
 * still addressed by its own `account_id` and `livemode`.
 */
import { uuidv7 } from "@nearpay-internal/ids";
import type { Tx } from "../app/context.js";

export const SENTINEL_ACTOR = "sentinel";

export async function quarantineLog(
  t: Tx,
  accountUuid: string,
  livemode: boolean,
  action: "quarantined" | "extended" | "cleared",
  reason: string,
  actor: string,
  expires: Date | null,
  version: number,
): Promise<void> {
  await t
    .insertInto("quarantine_log")
    .values({
      id: uuidv7(),
      account_id: accountUuid,
      livemode,
      action,
      reason: reason.slice(0, 500),
      actor: actor.slice(0, 200),
      expires_at: expires,
      version,
    })
    .execute();
}

export interface BulkClear {
  /** Only quarantines created at or after this instant. */
  readonly since?: Date;
  /** Only quarantines created by one of these breaches. */
  readonly breachIds?: readonly string[];
  /** Only this mode (both when absent). */
  readonly livemode?: boolean;
  readonly actor: string;
  readonly note: string;
  readonly nowMs: number;
}

export interface BulkClearResult {
  readonly cleared: readonly { account_id: string; livemode: boolean }[];
  /** In force and matching, but created or changed by an operator: kept. */
  readonly kept: readonly { account_id: string; livemode: boolean; by: string }[];
}

/** Clears sentinel's own quarantines in force that match (module doc). */
export async function clearSentinelQuarantines(t: Tx, o: BulkClear): Promise<BulkClearResult> {
  if (o.breachIds && o.breachIds.length === 0) return { cleared: [], kept: [] };
  const now = new Date(o.nowMs);
  let q = t
    .selectFrom("quarantines")
    .selectAll()
    .where("status", "=", "active")
    .where("expires_at", ">", now)
    .orderBy("account_id")
    .forUpdate();
  if (o.since) q = q.where("created_at", ">=", o.since);
  if (o.breachIds) q = q.where("breach_id", "in", [...o.breachIds]);
  if (o.livemode !== undefined) q = q.where("livemode", "=", o.livemode);
  const rows = await q.execute();
  const cleared: { account_id: string; livemode: boolean }[] = [];
  const kept: { account_id: string; livemode: boolean; by: string }[] = [];
  for (const r of rows) {
    const last = await t
      .selectFrom("quarantine_log")
      .select("actor")
      .where("account_id", "=", r.account_id)
      .where("livemode", "=", r.livemode)
      .orderBy("version", "desc")
      .orderBy("created_at", "desc")
      .limit(1)
      .executeTakeFirst();
    const by = r.created_by !== SENTINEL_ACTOR ? r.created_by : (last?.actor ?? SENTINEL_ACTOR);
    if (by !== SENTINEL_ACTOR) {
      kept.push({ account_id: r.account_id, livemode: r.livemode, by });
      continue;
    }
    const version = r.version + 1;
    await t
      .updateTable("quarantines")
      .set({
        status: "cleared",
        cleared_at: now,
        cleared_by: o.actor.slice(0, 200),
        clear_note: o.note.slice(0, 500),
        version,
        updated_at: now,
      })
      .where("account_id", "=", r.account_id)
      .where("livemode", "=", r.livemode)
      .execute();
    await quarantineLog(t, r.account_id, r.livemode, "cleared", o.note, o.actor, null, version);
    cleared.push({ account_id: r.account_id, livemode: r.livemode });
  }
  return { cleared, kept };
}
