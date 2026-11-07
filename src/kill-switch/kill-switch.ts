/**
 * The global quoting kill switch (lld/sentinel.md §8): one row, versioned; every change appends to
 * `kill_switch_log` and emits `evt.sentinel.kill_switch.engaged|released` in the same transaction.
 * Rails stops live quotes when it consumes `engaged`. From Stage 2 the console's two-person release
 * (./release.ts) is the only release on the server stage; the single-person release of the ops CLI and
 * `POST /internal/kill-switch` answers `409 two_person_required` there and stays on local/test stacks.
 * Every change also expires a pending release request (it was for the previous version).
 */
import { emit } from "@nearpay-internal/db";
import { fromUuid, uuidv7 } from "@nearpay-internal/ids";
import { ApiError } from "@nearpay-internal/service";
import type { Sentinel, Tx } from "../app/context.js";
import { singlePersonAllowed } from "./two-person.js";

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
    await expirePending(t, "the kill switch changed");
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

/** Marks every pending release request `expired` (inside the caller's transaction). */
export async function expirePending(t: Tx, note: string): Promise<number> {
  const r = await t
    .updateTable("release_requests")
    .set({ status: "expired", decision_note: note.slice(0, 500) })
    .where("status", "=", "pending")
    .executeTakeFirst();
  return Number(r.numUpdatedRows);
}

/**
 * The single-person path (`POST /internal/kill-switch`, ops CLI): engaging always works; releasing is
 * allowed only when `NP_ENV` is `local` or `test` (testbed T7); on any other value — `server`, an unknown
 * stage, a mistyped one — it is refused with `409 two_person_required` (the console's request + approval is
 * the only release there).
 */
export async function setKillSwitchSinglePerson(
  s: Pick<Sentinel, "db" | "log" | "metrics" | "env">,
  engaged: boolean,
  reason: string,
  actor: string,
): Promise<KillSwitchState> {
  if (!engaged && !singlePersonAllowed(s.env)) {
    s.log.warn({ actor, env: s.env }, "single-person kill-switch release refused outside local/test");
    throw new ApiError("two_person_required");
  }
  return setKillSwitch(s, engaged, reason, actor);
}
