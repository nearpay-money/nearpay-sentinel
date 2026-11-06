/**
 * The global quoting kill switch (lld/sentinel.md §8): one row, versioned; every change appends to
 * `kill_switch_log` and emits `evt.sentinel.kill_switch.engaged|released` in the same transaction.
 * Rails stops live quotes when it consumes `engaged`. Stage 1 releases through the ops CLI (the
 * two-person release arrives with the Stage 2 console).
 */
import { emit } from "@nearpay-internal/db";
import { fromUuid, uuidv7 } from "@nearpay-internal/ids";
import type { Sentinel, Tx } from "../app/context.js";

/** The kill switch aggregate (a singleton). */
export const KILL_SWITCH_ID = fromUuid("ks", "01900000-0000-7000-8000-00000000c0de");

export interface KillSwitchState {
  engaged: boolean;
  reason: string;
  actor: string;
  version: number;
  updated_at: Date;
}

export async function killSwitchState(s: Pick<Sentinel, "db">): Promise<KillSwitchState> {
  return s.db.selectFrom("kill_switch").selectAll().where("id", "=", 1).executeTakeFirstOrThrow();
}

/** Engages or releases. No-op (returns the state) when already in the requested position. */
export async function setKillSwitch(
  s: Pick<Sentinel, "db" | "log" | "metrics">,
  engaged: boolean,
  reason: string,
  actor: string,
  tx?: Tx,
): Promise<KillSwitchState> {
  const run = async (t: Tx) => {
    const cur = await t.selectFrom("kill_switch").selectAll().where("id", "=", 1).forUpdate().executeTakeFirstOrThrow();
    if (cur.engaged === engaged) return cur;
    const version = cur.version + 1;
    const next = await t
      .updateTable("kill_switch")
      .set({ engaged, reason: reason.slice(0, 500), actor: actor.slice(0, 200), version, updated_at: new Date() })
      .where("id", "=", 1)
      .returningAll()
      .executeTakeFirstOrThrow();
    await t
      .insertInto("kill_switch_log")
      .values({ id: uuidv7(), engaged, reason: next.reason, actor: next.actor, version })
      .execute();
    await emit(t, {
      subject: engaged ? "evt.sentinel.kill_switch.engaged" : "evt.sentinel.kill_switch.released",
      aggregate: { type: "kill_switch", id: KILL_SWITCH_ID, version },
      accountId: null,
      livemode: null,
      data: { object: { engaged, reason: next.reason, actor: next.actor }, previous: { engaged: cur.engaged } },
    });
    return next;
  };
  const state = tx ? await run(tx) : await s.db.transaction().execute(run);
  s.metrics.killSwitch(state.engaged);
  if (engaged) s.log.error({ reason, actor }, "ALERT kill switch engaged: live quoting stopped");
  else s.log.warn({ reason, actor }, "kill switch released");
  return state;
}
