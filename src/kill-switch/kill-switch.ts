/**
 * The global quoting kill switch (lld/sentinel.md §8): one row, versioned; every change appends to
 * `kill_switch_log` and emits `evt.sentinel.kill_switch.engaged|released` in the same transaction.
 * Rails stops live quotes when it consumes `engaged`. From Stage 2 the console's two-person release
 * (./release.ts) is the only release on the server stage; the single-person release of the ops CLI and
 * `POST /internal/kill-switch` answers `409 two_person_required` there and stays on local/test stacks.
 * Every change also expires a pending release request (it was for the previous version).
 *
 * Releasing (by any path) also clears, in the same transaction, the quarantines sentinel created during the
 * engagement (SENTINEL-2): the cause has been dealt with, so the merchants it paused resume with everyone
 * else. Holds an operator created or changed are kept (./quarantine-clear.ts).
 */
import { emit } from "@nearpay-internal/db";
import { fromUuid, uuidv7 } from "@nearpay-internal/ids";
import { ApiError } from "@nearpay-internal/service";
import { DEFAULT_CONTAINMENT, engagementQuarantineSince } from "../address-integrity/containment.js";
import type { Sentinel, Tx } from "../app/context.js";
import { clearSentinelQuarantines } from "./quarantine-clear.js";
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

/** The reason in plain words for the alert's first line (the recorded reason keeps every detail). */
export function plainReason(reason: string, actor: string): string {
  if (actor === "sentinel" && reason.startsWith("systemic integrity breach"))
    return "an automatic check found the same kind of problem on several merchants' payments within minutes";
  if (actor === "sentinel") return "an automatic check refused a payment";
  return reason;
}

/** Plain-language hint for whoever reads the paused-payments alert. */
export const RESUME_HINT =
  "To resume: release the kill switch in the console (scripts/beta.sh ops sentinel kill-switch-release-status shows where the release stands)";

export async function killSwitchState(s: Pick<Sentinel, "db">): Promise<KillSwitchState> {
  return s.db.selectFrom("kill_switch").selectAll().where("id", "=", 1).executeTakeFirstOrThrow();
}

/**
 * `KillSwitchState` on the wire (`getKillSwitch`, `setKillSwitch`): `version` is the row version, which
 * equals the envelope `aggregate.version` of the latest `evt.sentinel.kill_switch.*` (spec 0.2.1), so a
 * reader that seeds from it applies only later events.
 */
export function killSwitchView(st: KillSwitchState) {
  return {
    engaged: st.engaged,
    reason: st.reason,
    actor: st.actor,
    updated_at: st.updated_at.toISOString(),
    version: st.version,
  };
}

/** Engages or releases. No-op (returns the state) when already in the requested position. */
export async function setKillSwitch(
  s: Pick<Sentinel, "db" | "log" | "metrics"> & Partial<Pick<Sentinel, "containment" | "now">>,
  engaged: boolean,
  reason: string,
  actor: string,
  tx?: Tx,
): Promise<KillSwitchState & { quarantines_cleared?: number }> {
  let cleared = 0;
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
    if (!engaged) {
      const since = engagementQuarantineSince(
        { actor: cur.actor, atMs: cur.updated_at.getTime() },
        s.containment ?? DEFAULT_CONTAINMENT,
      );
      const r = await clearSentinelQuarantines(t, {
        since: new Date(since),
        actor,
        note: `kill switch released: ${next.reason}`,
        nowMs: s.now ? s.now() : Date.now(),
      });
      cleared = r.cleared.length;
    }
    return next;
  };
  const state = tx ? await run(tx) : await s.db.transaction().execute(run);
  s.metrics.killSwitch(state.engaged);
  if (engaged)
    s.log.error(
      { alert: "kill_switch_engaged", reason, actor },
      `ALERT Payments are paused: ${plainReason(reason, actor)}. ${RESUME_HINT}`,
    );
  else {
    if (cleared) s.metrics.quarantinesCleared("release", cleared);
    s.log.warn(
      { alert: "kill_switch_released", reason, actor, quarantines_cleared: cleared },
      cleared
        ? `Payments are back on; ${cleared} merchant(s) paused during the stop were switched back on too`
        : "Payments are back on",
    );
  }
  return cleared ? { ...state, quarantines_cleared: cleared } : state;
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
