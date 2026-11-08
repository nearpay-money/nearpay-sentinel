/**
 * Domain-event consumers (lld/sentinel.md §7), run by `sentinel-auditor`:
 *
 * | Subject                                        | Effect                                                   |
 * |------------------------------------------------|----------------------------------------------------------|
 * | evt.rails.execution.settled                    | enqueue the `audit.execution` job (sampling and checks run there) |
 * | evt.identity.settlement_destination.disabled   | evict cached attestations signed for that destination    |
 * | evt.identity.account.created / .updated        | remember the display name for console findings (0.2.1)   |
 *
 * Each handler records the event in the inbox in the same transaction (exactly-once effect). The
 * eviction is idempotent; the display-name map ignores events with an `aggregate.version` not above the
 * stored one (stale-version guard); the co-signer also re-checks the destination on every cache hit, so an api
 * replica that kept an in-process entry while Valkey was down never re-serves it.
 */
import type { Envelope, EventHandler } from "@nearpay-internal/bus";
import { deadLetterSink, enqueueJob, inboxHandler, type Kysely } from "@nearpay-internal/db";
import { isId, toUuid } from "@nearpay-internal/ids";
import type { Execution, Subject } from "@nearpay-internal/spec";
import type { AttestationCache, Tx } from "../app/context.js";
import { AUDIT_JOB, AUDIT_MAX_ATTEMPTS } from "../independent-reconciliation/auditor.js";
import type { DB } from "../infra/db/schema.js";

async function settled(tx: Tx, e: Envelope): Promise<void> {
  const x = e.data.object as unknown as Execution;
  if (!isId("ex", x.id)) throw new Error(`settled event without an execution id (${e.id})`);
  await enqueueJob(tx, {
    kind: AUDIT_JOB,
    payload: { execution: x },
    dedupeKey: `${AUDIT_JOB}:${x.id}`,
    maxAttempts: AUDIT_MAX_ATTEMPTS,
  });
}

/** Deposit keys of unexpired attestations signed for a destination. */
export async function signedKeys(db: Kysely<DB> | Tx, destinationUuid: string): Promise<string[]> {
  const rows = await db
    .selectFrom("attestations")
    .select("deposit_key")
    .distinct()
    .where("destination_id", "=", destinationUuid)
    .where("result", "=", "signed")
    .where("expires_at", ">", new Date())
    .execute();
  return rows.map((r) => r.deposit_key);
}

/**
 * Applies an account event to the display-name map (spec 0.2.1): upsert, only when the event's aggregate
 * version is newer than the stored one. Display only; an event without a usable name is ignored.
 */
export async function accountName(tx: Tx, e: Envelope): Promise<void> {
  const a = e.data.object as unknown as { id?: unknown; display_name?: unknown };
  if (typeof a.id !== "string" || !isId("acct", a.id)) throw new Error(`account event without an account id (${e.id})`);
  if (typeof a.display_name !== "string" || a.display_name.length === 0) return;
  const version = e.aggregate.version;
  await tx
    .insertInto("account_names")
    .values({ account_id: toUuid(a.id, "acct"), display_name: a.display_name.slice(0, 100), version })
    .onConflict((oc) =>
      oc
        .column("account_id")
        .doUpdateSet({ display_name: (eb) => eb.ref("excluded.display_name"), version, updated_at: new Date() })
        .where("account_names.version", "<", version),
    )
    .execute();
}

export function sentinelHandlers(db: Kysely<DB>, cache: AttestationCache): Partial<Record<Subject, EventHandler>> {
  const h = (fn: (tx: Tx, e: Envelope) => Promise<void>) => inboxHandler(db, fn);
  return {
    "evt.rails.execution.settled": h(settled),
    "evt.identity.account.created": h(accountName),
    "evt.identity.account.updated": h(accountName),
    "evt.identity.settlement_destination.disabled": h(async (tx, e) => {
      const d = e.data.object as unknown as { id: string };
      const keys = await signedKeys(tx, toUuid(d.id, "sd"));
      await cache.del(keys);
    }),
  };
}

export const deadLetters = (db: Kysely<DB>) => deadLetterSink(db, "consumer:sentinel");
