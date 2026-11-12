/**
 * Automatic release of stale automatic stops (owner decision 2026-11-13; ADR-0028 amendment 2026-11-13;
 * lld/sentinel.md §6 and §18).
 *
 * On boot and every `NP_KILL_SWITCH_AUTO_RELEASE_TICK_S` (60 s) sentinel-auditor looks at the global kill switch.
 * When sentinel engaged it (actor `sentinel`) and its recorded reason and evidence would not engage it under the
 * current rules (`autoReleaseDecision`), sentinel releases it through the normal release path: version + 1,
 * `kill_switch_log` row (actor `sentinel`, reason "auto-released: <old reason> — no longer platform evidence
 * under ADR-0028"), outbox `evt.sentinel.kill_switch.released`, and the quarantine cleanup every release does.
 *
 * Never released here: an operator's stop, a systemic stop that is still corroborated, a stop with corroborated
 * evidence that arrived during it, a stop whose evidence cannot be loaded or judged (an error leaves the switch
 * engaged and pages), and any stop once the flap guard tripped. Operator stops and corroborated systemic stops
 * keep the console's two-person / single-operator release, wait unchanged.
 *
 * The decision and the release run in one transaction under the corroboration advisory lock and with the switch
 * row locked (the same order as `containBreach`), so a concurrent engagement is never released by a decision
 * taken before it.
 */
import { sql } from "@nearpay-internal/db";
import {
  type AutoReleaseDecision,
  autoReleaseDecision,
  autoReleaseReason,
  DEFAULT_AUTO_RELEASE,
  type Reclassified,
  type StaleClass,
  type SwitchLogEntry,
  stillPipelineBreach,
} from "../address-integrity/containment.js";
import type { Sentinel, Tx } from "../app/context.js";
import { SYSTEMIC_LOCK, windowBreaches } from "./containment.js";
import { type KillSwitchState, setKillSwitch } from "./kill-switch.js";

type Ctx = Pick<Sentinel, "db" | "log" | "metrics" | "containment" | "now"> & Partial<Pick<Sentinel, "autoRelease">>;

/** Plain words for the Telegram-visible line. */
export const AUTO_RELEASED_MESSAGE =
  "Payments were paused by an automatic check that turned out to be a false alarm. They have been switched back on automatically.";

const SLACK_MS = 1_000;

/**
 * Loads what the decision needs (inside the caller's transaction or on the pool) and decides. Read-only. Throws
 * when the evidence cannot be read: callers keep the switch engaged.
 */
export async function assessAutoRelease(
  db: Sentinel["db"] | Tx,
  s: Pick<Sentinel, "containment" | "now"> & Partial<Pick<Sentinel, "autoRelease">>,
  st: Pick<KillSwitchState, "engaged" | "actor" | "reason" | "updated_at">,
): Promise<AutoReleaseDecision> {
  const policy = s.autoRelease ?? DEFAULT_AUTO_RELEASE;
  const nowMs = s.now();
  const atMs = st.updated_at.getTime();
  const engagement = { actor: st.actor, reason: st.reason, atMs };
  if (st.actor !== "sentinel")
    return autoReleaseDecision({
      engagement,
      breaches: [],
      log: [],
      containment: s.containment,
      policy,
      nowMs,
    });
  const from = atMs - s.containment.systemicWindowMs - SLACK_MS;
  const [breaches, reclassified, log] = await Promise.all([
    windowBreaches(db, from, Math.max(nowMs, atMs + SLACK_MS)),
    reclassifiedRows(db, from, atMs + SLACK_MS),
    switchLog(db, nowMs - policy.flapWindowMs),
  ]);
  return autoReleaseDecision({ engagement, breaches, reclassified, log, containment: s.containment, policy, nowMs });
}

/** Recorded live rows of the window that the current rules no longer read as pipeline breaches. */
async function reclassifiedRows(db: Sentinel["db"] | Tx, sinceMs: number, untilMs: number): Promise<Reclassified> {
  const rows = await db
    .selectFrom("integrity_breaches")
    .select(["evidence", "reasons", "destination_account_id"])
    .where("livemode", "=", true)
    .where("created_at", ">=", new Date(sinceMs))
    .where("created_at", "<=", new Date(untilMs))
    .execute();
  let r2Only = 0;
  let request = 0;
  for (const r of rows) {
    if (r.evidence === "request") request++;
    else if (!stillPipelineBreach({ reasons: r.reasons, destinationMatched: r.destination_account_id !== null }))
      r2Only++;
  }
  return { r2Only, request };
}

/** `kill_switch_log` rows from `sinceMs`, plus the row before the first (a re-engagement needs its predecessor). */
async function switchLog(db: Sentinel["db"] | Tx, sinceMs: number): Promise<SwitchLogEntry[]> {
  const recent = await db
    .selectFrom("kill_switch_log")
    .select(["version", "engaged", "actor", "reason", "created_at"])
    .where("created_at", ">=", new Date(sinceMs))
    .orderBy("version")
    .execute();
  const first = recent[0]?.version;
  const before =
    first === undefined
      ? []
      : await db
          .selectFrom("kill_switch_log")
          .select(["version", "engaged", "actor", "reason", "created_at"])
          .where("version", "<", first)
          .orderBy("version", "desc")
          .limit(1)
          .execute();
  return [...before, ...recent].map((r) => ({
    version: r.version,
    engaged: r.engaged,
    actor: r.actor,
    reason: r.reason,
    atMs: r.created_at.getTime(),
  }));
}

export type AutoReleaseOutcome =
  | { readonly action: "none" }
  | { readonly action: "kept"; readonly version: number; readonly decision: AutoReleaseDecision & { release: false } }
  | {
      readonly action: "released";
      readonly version: number;
      readonly class: StaleClass;
      readonly why: string;
      readonly previousReason: string;
      readonly quarantinesCleared: number;
    };

/** One check: releases the switch when the decision says so (module doc). Throws when the evidence is unreadable. */
export async function autoReleaseStaleStop(s: Ctx): Promise<AutoReleaseOutcome> {
  const peek = await s.db
    .selectFrom("kill_switch")
    .select(["engaged", "actor", "reason", "updated_at", "version"])
    .where("id", "=", 1)
    .executeTakeFirstOrThrow();
  if (!peek.engaged) return { action: "none" };
  // an operator's stop needs no transaction: it is never released here
  if (peek.actor !== "sentinel") {
    const decision = await assessAutoRelease(s.db, s, peek);
    return decision.release ? { action: "none" } : { action: "kept", version: peek.version, decision };
  }

  const out = await s.db.transaction().execute(async (t): Promise<AutoReleaseOutcome> => {
    await sql`select pg_advisory_xact_lock(hashtext(${SYSTEMIC_LOCK}))`.execute(t);
    const cur = await t.selectFrom("kill_switch").selectAll().where("id", "=", 1).forUpdate().executeTakeFirstOrThrow();
    if (!cur.engaged) return { action: "none" };
    const decision = await assessAutoRelease(t, s, cur);
    if (!decision.release) return { action: "kept", version: cur.version, decision };
    const next = await setKillSwitch(s, false, autoReleaseReason(cur.reason), "sentinel", t);
    if (next.engaged || next.version !== cur.version + 1) throw new Error("automatic release did not apply"); // rolls back
    return {
      action: "released",
      version: next.version,
      class: decision.class,
      why: decision.why,
      previousReason: cur.reason,
      quarantinesCleared: next.quarantines_cleared ?? 0,
    };
  });

  if (out.action === "released") {
    s.metrics.killSwitchAutoReleased(out.class);
    s.log.info(
      {
        reason_class: out.class,
        why: out.why,
        previous_reason: out.previousReason,
        version: out.version,
        quarantines_cleared: out.quarantinesCleared,
      },
      `kill switch auto-released: the automatic stop is no longer platform evidence under ADR-0028 (${out.why})`,
    );
    s.log.warn(
      {
        alert: "kill_switch_auto_released",
        reason_class: out.class,
        previous_reason: out.previousReason,
        version: out.version,
        quarantines_cleared: out.quarantinesCleared,
      },
      `ALERT ${AUTO_RELEASED_MESSAGE}`,
    );
  }
  return out;
}

/** Holds that page (once per switch version and reason per process); operator and corroborated stops are expected. */
const PAGED: ReadonlySet<string> = new Set(["unjudgeable", "new_evidence", "flapping"]);

/** Liveness handle (structural twin of the kit's `Heartbeat`). */
interface Heartbeat {
  beat(): void;
  idle(): void;
}

/**
 * The background task (`sentinel:kill-switch-auto-release`, sentinel-auditor): one check at boot, then one every
 * `tickMs`; beats once per check, failed ones included (a database outage is readiness, not liveness). A check
 * that fails leaves the switch as it is and logs an ALERT line.
 */
export function autoReleaseTask(s: Ctx, o: { tickMs?: number } = {}) {
  const tickMs = o.tickMs ?? (s.autoRelease ?? DEFAULT_AUTO_RELEASE).tickMs;
  const noted = new Set<string>();
  const check = async () => {
    try {
      const r = await autoReleaseStaleStop(s);
      if (r.action !== "kept") return;
      const key = `${r.version}:${r.decision.keep}`;
      if (noted.has(key)) return;
      noted.add(key);
      if (PAGED.has(r.decision.keep))
        s.log.error(
          { alert: "kill_switch_auto_release_held", keep: r.decision.keep, why: r.decision.why, version: r.version },
          `ALERT Payments stay paused: the automatic stop was not switched back on automatically because ${r.decision.why}. An operator must release it in the console`,
        );
      else
        s.log.info(
          { keep: r.decision.keep, why: r.decision.why, version: r.version },
          `kill switch stays engaged until an operator releases it (${r.decision.why})`,
        );
    } catch (e) {
      s.log.error(
        { alert: "kill_switch_auto_release_failed", err: e instanceof Error ? e.message : String(e) },
        "ALERT sentinel could not check whether an automatic stop is a false alarm; payments stay as they are until the next check",
      );
    }
  };
  return {
    name: "sentinel:kill-switch-auto-release",
    maxSilenceMs: Math.max(3 * tickMs, 60_000),
    start(heartbeat?: Heartbeat) {
      let stopped = false;
      let timer: NodeJS.Timeout | null = null;
      let wake: (() => void) | null = null;
      const loop = (async () => {
        while (!stopped) {
          await check();
          heartbeat?.beat();
          if (stopped) break;
          await new Promise<void>((r) => {
            wake = r;
            timer = setTimeout(r, tickMs);
          });
        }
      })();
      return {
        async stop() {
          stopped = true;
          if (timer) clearTimeout(timer);
          wake?.();
          await loop;
        },
      };
    },
  };
}
