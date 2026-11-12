/**
 * Integrity containment (ADR-0028, lld/sentinel.md §5 "Containment"; owner directive 2026-11-12: "the
 * service should never stop"). Replaces the automatic global stop on a single payment's check (L-SN-01 as
 * first fixed):
 *
 * - every `security` refusal on a deposit address rails confirms NearPay issued is recorded in
 *   `integrity_breaches` with full detail;
 * - `pipeline` evidence also records an audit finding (`check_kind: attestation`, emitted as
 *   `evt.sentinel.audit_finding.created`: compliance opens a case, notify pages) and, in live mode,
 *   quarantines the account(s) involved for `quarantineTtlMs` (sentinel signs nothing for them meanwhile;
 *   every other merchant keeps working) — one transaction: breach, finding + outbox, quarantine row +
 *   `quarantine_log` transition;
 * - the global kill switch is engaged by sentinel (actor `sentinel`) only when the corroboration rule holds
 *   (`systemicVerdict`: ≥ N refusals across ≥ M accounts within the window). It then stays engaged until ops
 *   release it (the two-person / single-operator release): a corroborated breach is a security event.
 *
 * Quarantines expire on their own; ops list, extend and clear them with the CLI (src/ops/cli.ts).
 *
 * Amended 2026-11-12 (SENTINEL-1/2/7):
 * - a quarantine in force is not extended by further breaches (payers retrying the same broken quote);
 * - a breach that is provider-wide drift (`driftSignatures`: the same format/semantics refusal on ≥ 2 merchants)
 *   is recorded with `drift = true`, quarantines nobody, raises no per-merchant audit finding, never counts
 *   toward the systemic rule, and lifts the quarantines the earlier refusals of the same drift created
 *   (`ALERT`-level log + `integrity_drift_total{source="pattern"}`);
 * - when the systemic rule engages on refusals that all share one rule set, the engagement also reports
 *   `integrity_drift_total{source="engaged"}` (likely a provider change or config skew; the switch still engages);
 * - a breach with no known account counts as a refusal, never as an account.
 */
import { emit, sql } from "@nearpay-internal/db";
import { fromUuid, isId, toUuid, uuidv7 } from "@nearpay-internal/ids";
import type { Evidence } from "../address-integrity/checks.js";
import {
  type Breach,
  driftSignature,
  isDrift,
  quarantineExpiry,
  quarantineState,
  rulesOf,
  type SystemicVerdict,
  stillPipelineBreach,
  systemicVerdict,
} from "../address-integrity/containment.js";
import type { Sentinel, Tx } from "../app/context.js";
import { setKillSwitch } from "./kill-switch.js";
import { clearSentinelQuarantines, quarantineLog as log } from "./quarantine-clear.js";

/** What rails answered about the deposit address (scoping only, never a verdict). */
export interface DepositLookup {
  readonly exists: boolean;
  readonly livemode: boolean | null;
  readonly execution_id?: string | null;
  readonly account_id?: string | null;
}

export interface BreachInput {
  readonly livemode: boolean;
  readonly evidence: Evidence;
  readonly reasons: readonly string[];
  readonly attemptId: string;
  readonly depositAddress: string | null;
  readonly depositMemo: string | null;
  readonly lookup: DepositLookup;
  /** identity's registry: the account the quote pays (uuid), when R5 matched. */
  readonly destinationAccount: string | null;
  readonly ip: string;
}

export interface Containment {
  readonly breachId: string;
  /** Accounts (uuid) quarantined or kept in quarantine by this breach. */
  readonly quarantined: readonly string[];
  readonly until: Date | null;
  readonly verdict: SystemicVerdict | null;
  readonly engaged: boolean;
  /** The breach is provider-wide drift (SENTINEL-1): not contained, not counted. */
  readonly drift: boolean;
}

const SYSTEMIC_LOCK = "sentinel.integrity.systemic";
const RUNBOOK =
  "scripts/beta.sh ops sentinel integrity-breaches; ops sentinel quarantines; runbook RB-03 (sentinel mismatch)";
const DRIFT_HINT =
  "same rule on every merchant: likely provider format change or rails/sentinel config skew (compare nearpay_sentinel_fee_config_info with rails); compare `ops sentinel integrity-breaches` reasons with the 1Click changelog; release after the fix";

const acctUuid = (id: string | null | undefined): string | null => (id && isId("acct", id) ? toUuid(id, "acct") : null);

/**
 * The pipeline breaches on genuine live addresses inside the corroboration window (`[sinceMs, untilMs]`), as the
 * current rules read them (an R2-only refusal recorded before SENTINEL-1 is not a breach any more).
 */
export async function windowBreaches(
  db: Sentinel["db"] | Tx,
  sinceMs: number,
  untilMs = Number.POSITIVE_INFINITY,
): Promise<Breach[]> {
  let q = db
    .selectFrom("integrity_breaches")
    .select(["id", "account_id", "destination_account_id", "created_at", "reasons"])
    .where("livemode", "=", true)
    .where("evidence", "=", "pipeline")
    .where("created_at", ">=", new Date(sinceMs));
  if (Number.isFinite(untilMs)) q = q.where("created_at", "<=", new Date(untilMs));
  const rows = await q.execute();
  return rows
    .filter((r) => stillPipelineBreach({ reasons: r.reasons, destinationMatched: r.destination_account_id !== null }))
    .map((r) => ({
      id: r.id,
      account: r.account_id ?? r.destination_account_id,
      atMs: r.created_at.getTime(),
      reasons: r.reasons,
    }));
}

/** Scrape-time gauge: the corroboration window right now. */
export async function systemicWindow(s: Pick<Sentinel, "db" | "containment" | "now">) {
  const now = s.now();
  const v = systemicVerdict(await windowBreaches(s.db, now - s.containment.systemicWindowMs), s.containment, now);
  return { refusals: v.refusals, accounts: v.accounts, drift: v.drift.length };
}

/** Scrape-time gauge: quarantines in force. */
export async function quarantinesActive(s: Pick<Sentinel, "db" | "now">): Promise<number> {
  const r = await s.db
    .selectFrom("quarantines")
    .select((eb) => eb.fn.countAll<string>().as("n"))
    .where("status", "=", "active")
    .where("expires_at", ">", new Date(s.now()))
    .executeTakeFirstOrThrow();
  return Number(r.n);
}

/** The quarantine in force for an account in a mode, if any. */
export async function activeQuarantine(
  s: Pick<Sentinel, "db" | "now">,
  accountUuid: string,
  livemode: boolean,
): Promise<{ reason: string; expires_at: Date } | null> {
  const q = await s.db
    .selectFrom("quarantines")
    .select(["reason", "expires_at", "status"])
    .where("account_id", "=", accountUuid)
    .where("livemode", "=", livemode)
    .executeTakeFirst();
  return q && quarantineState(q, s.now()) === "active" ? q : null;
}

async function quarantine(
  t: Tx,
  o: { accountUuid: string; livemode: boolean; reason: string; breachId: string; ttlMs: number; nowMs: number },
): Promise<Date> {
  const cur = await t
    .selectFrom("quarantines")
    .selectAll()
    .where("account_id", "=", o.accountUuid)
    .where("livemode", "=", o.livemode)
    .forUpdate()
    .executeTakeFirst();
  const reason = o.reason.slice(0, 500);
  const now = new Date(o.nowMs);
  if (!cur) {
    const expires = quarantineExpiry(null, o.ttlMs, o.nowMs);
    await t
      .insertInto("quarantines")
      .values({
        account_id: o.accountUuid,
        livemode: o.livemode,
        status: "active",
        reason,
        breach_id: o.breachId,
        created_by: "sentinel",
        created_at: now,
        expires_at: expires,
        updated_at: now,
      })
      .execute();
    await log(t, o.accountUuid, o.livemode, "quarantined", reason, "sentinel", expires, 1);
    return expires;
  }
  // in force: a further breach (typically the payer retrying the same quote) never extends it (SENTINEL-2)
  if (quarantineState(cur, o.nowMs) === "active") return cur.expires_at;
  const expires = quarantineExpiry(null, o.ttlMs, o.nowMs);
  const version = cur.version + 1;
  await t
    .updateTable("quarantines")
    .set({
      status: "active",
      reason,
      breach_id: o.breachId,
      created_by: "sentinel",
      created_at: now,
      expires_at: expires,
      cleared_at: null,
      cleared_by: null,
      clear_note: null,
      version,
      updated_at: now,
    })
    .where("account_id", "=", o.accountUuid)
    .where("livemode", "=", o.livemode)
    .execute();
  await log(t, o.accountUuid, o.livemode, "quarantined", reason, "sentinel", expires, version);
  return expires;
}

/**
 * Records a `security` refusal on a genuine NearPay deposit address and contains it (module doc). Request
 * evidence is only recorded. Logs the ALERT lines; the caller counts the metric.
 */
export async function containBreach(s: Sentinel, i: BreachInput): Promise<Containment> {
  const nowMs = s.now();
  const p = s.containment;
  const rules = rulesOf(i.reasons);
  const execAccount = acctUuid(i.lookup.account_id);
  const pipeline = i.evidence === "pipeline";
  const live = i.livemode && i.lookup.livemode === true;
  const accounts = [...new Set([execAccount, i.destinationAccount].filter((a): a is string => a !== null))];
  const id = uuidv7();
  const reasonText = `integrity breach on ${i.depositAddress ?? "?"} (${rules.join(", ")}): ${i.reasons.join("; ")}`;

  const result = await s.db.transaction().execute(async (t) => {
    let verdict: SystemicVerdict | null = null;
    let drift = false;
    let lifted: readonly string[] = [];
    if (pipeline && live) {
      // one corroboration decision at a time, so concurrent breaches cannot each miss the threshold
      await sql`select pg_advisory_xact_lock(hashtext(${SYSTEMIC_LOCK}))`.execute(t);
      const prior = await windowBreaches(t, nowMs - p.systemicWindowMs);
      const me: Breach = { id, account: execAccount ?? i.destinationAccount, atMs: nowMs, reasons: i.reasons };
      verdict = systemicVerdict([...prior, me], p, nowMs);
      drift = isDrift(me, new Set(verdict.drift));
      if (drift) {
        // the earlier refusals of the same drift quarantined their merchants before the pattern showed: lift them
        const sig = driftSignature(i.reasons);
        const same = prior.filter((b) => b.reasons && driftSignature(b.reasons) === sig).map((b) => b.id);
        const r = await clearSentinelQuarantines(t, {
          breachIds: same,
          livemode: true,
          actor: "sentinel",
          note: `provider-wide drift suspected (${sig}): the same refusal on several merchants is not tampering`,
          nowMs,
        });
        lifted = r.cleared.map((c) => c.account_id);
      }
    }
    const quarantineIt = pipeline && live && accounts.length > 0 && !drift;
    await t
      .insertInto("integrity_breaches")
      .values({
        id,
        livemode: live,
        evidence: i.evidence,
        rules,
        reasons: i.reasons.map((r) => r.slice(0, 500)),
        attempt_id: i.attemptId,
        deposit_address: i.depositAddress,
        deposit_memo: i.depositMemo,
        execution_id: i.lookup.execution_id ?? null,
        account_id: execAccount,
        destination_account_id: i.destinationAccount,
        client_ip: i.ip.slice(0, 64),
        quarantined: quarantineIt,
        systemic: verdict?.engage ?? false,
        drift,
        created_at: new Date(nowMs),
      })
      .execute();

    // the audit finding (compliance case, ops page) — pipeline evidence on an execution rails named; provider-wide
    // drift pages once (below) instead of opening a case per merchant
    if (pipeline && !drift && i.lookup.execution_id && execAccount) {
      const details = {
        breach_id: id,
        evidence: i.evidence,
        rules,
        reasons: i.reasons,
        attempt_id: i.attemptId,
        deposit_address: i.depositAddress,
        deposit_memo: i.depositMemo,
        destination_account: i.destinationAccount ? fromUuid("acct", i.destinationAccount) : null,
        quarantined: quarantineIt,
      };
      const finding = await t
        .insertInto("audit_findings")
        .values({
          id: uuidv7(),
          execution_id: i.lookup.execution_id,
          account_id: execAccount,
          livemode: live,
          check_kind: "attestation",
          result: "mismatch",
          details: JSON.stringify(details),
        })
        .onConflict((oc) => oc.columns(["execution_id", "check_kind"]).doNothing())
        .returning("id")
        .executeTakeFirst();
      if (finding)
        await emit(t, {
          subject: "evt.sentinel.audit_finding.created",
          aggregate: { type: "audit_finding", id: fromUuid("fnd", finding.id), version: 1 },
          accountId: execAccount,
          livemode: live,
          data: {
            object: {
              id: fromUuid("fnd", finding.id),
              execution_id: i.lookup.execution_id,
              account_id: fromUuid("acct", execAccount),
              livemode: live,
              check_kind: "attestation",
              result: "mismatch",
              details,
            },
          },
        });
    }

    let until: Date | null = null;
    if (quarantineIt)
      for (const a of accounts)
        until = await quarantine(t, {
          accountUuid: a,
          livemode: true,
          reason: reasonText,
          breachId: id,
          ttlMs: p.quarantineTtlMs,
          nowMs,
        });

    let engaged = false;
    if (verdict?.engage) {
      const before = await t.selectFrom("kill_switch").select("engaged").where("id", "=", 1).executeTakeFirstOrThrow();
      await setKillSwitch(
        s,
        true,
        `systemic integrity breach: ${verdict.refusals} refusals on NearPay deposit addresses across ${verdict.accounts} accounts within ${Math.round(p.systemicWindowMs / 60_000)} min (latest ${i.depositAddress}: ${i.reasons.join("; ")}). Stays engaged until ops release it. ${RUNBOOK}`,
        "sentinel",
        t,
      );
      engaged = !before.engaged;
    }
    return { quarantined: quarantineIt ? accounts : [], until, verdict, engaged, drift, lifted };
  });

  const ctx = {
    breach: id,
    evidence: i.evidence,
    rules,
    reasons: i.reasons,
    deposit: i.depositAddress,
    attempt: i.attemptId,
    execution: i.lookup.execution_id ?? null,
    account: execAccount ? fromUuid("acct", execAccount) : null,
    livemode: live,
  };
  if (!pipeline) {
    s.log.warn(
      ctx,
      "attestation request differs from the provider's quote on a NearPay deposit address (caller-supplied fields: refused and recorded, nothing stopped)",
    );
  } else if (result.drift) {
    s.metrics.integrityDrift("pattern", rules.join("+"));
    if (result.lifted.length) s.metrics.quarantinesCleared("drift", result.lifted.length);
    s.log.error(
      {
        ...ctx,
        alert: "integrity_drift_suspected",
        signature: driftSignature(i.reasons),
        drift: result.verdict?.drift ?? [],
        lifted: result.lifted.map((a) => fromUuid("acct", a)),
        hint: DRIFT_HINT,
      },
      "ALERT integrity_drift_suspected: every merchant's payments are refused for the same reason, which looks like a provider format change, not tampering. Payments for them are refused until it is fixed; nobody is quarantined and the kill switch is not engaged",
    );
  } else {
    s.log.error(
      {
        ...ctx,
        alert: "integrity_breach",
        quarantined: result.quarantined.map((a) => fromUuid("acct", a)),
        until: result.until?.toISOString() ?? null,
        window: result.verdict,
        runbook: RUNBOOK,
      },
      "ALERT quote integrity breach on a NearPay deposit address: the payment was refused and the merchant is paused for a while",
    );
    if (result.engaged) {
      s.metrics.systemicEngaged();
      const uniform = result.verdict?.uniformRules ?? null;
      if (uniform) {
        s.metrics.integrityDrift("engaged", uniform);
        s.log.error(
          { alert: "integrity_drift_suspected", rules: uniform, window: result.verdict, hint: DRIFT_HINT },
          "ALERT integrity_drift_suspected: the payments that paused the platform all failed the same check on several merchants; this may be a provider change or a configuration mismatch between rails and sentinel",
        );
      }
      s.log.error(
        { alert: "systemic_integrity_breach", ...result.verdict, runbook: RUNBOOK },
        "ALERT Payments are paused: the same kind of problem was found on several merchants' payments within minutes. They stay paused until an operator releases the kill switch in the console",
      );
    }
  }
  return { breachId: id, ...result };
}

// ------------------------------------------------------------------------------------- ops

export interface QuarantineView {
  account_id: string;
  account_display_name: string | null;
  livemode: boolean;
  state: "active" | "expired" | "cleared";
  reason: string;
  breach_id: string | null;
  created_by: string;
  created_at: Date;
  expires_at: Date;
  cleared_at: Date | null;
  cleared_by: string | null;
  clear_note: string | null;
  version: number;
}

/** Quarantines in force (or every quarantine with `all`), newest first. */
export async function listQuarantines(s: Pick<Sentinel, "db" | "now">, all: boolean): Promise<QuarantineView[]> {
  let q = s.db
    .selectFrom("quarantines")
    .leftJoin("account_names", "account_names.account_id", "quarantines.account_id")
    .selectAll("quarantines")
    .select("account_names.display_name")
    .orderBy("quarantines.created_at", "desc");
  if (!all) q = q.where("quarantines.status", "=", "active").where("quarantines.expires_at", ">", new Date(s.now()));
  return (await q.execute()).map((r) => ({
    account_id: fromUuid("acct", r.account_id),
    account_display_name: r.display_name ?? null,
    livemode: r.livemode,
    state: quarantineState(r, s.now()),
    reason: r.reason,
    breach_id: r.breach_id,
    created_by: r.created_by,
    created_at: r.created_at,
    expires_at: r.expires_at,
    cleared_at: r.cleared_at,
    cleared_by: r.cleared_by,
    clear_note: r.clear_note,
    version: r.version,
  }));
}

export class QuarantineNotFound extends Error {
  override readonly name = "QuarantineNotFound";
}

/**
 * Ops: clear (`minutes` null) or extend by `minutes` from now the quarantine of an account in a mode. Clearing
 * a quarantine that is not in force fails; extending re-activates an expired or cleared one (an operator
 * quarantine, actor recorded).
 */
export async function changeQuarantine(
  s: Pick<Sentinel, "db" | "log" | "now">,
  o: { account: string; livemode: boolean; minutes: number | null; note: string; actor: string },
): Promise<QuarantineView> {
  const accountUuid = toUuid(o.account, "acct");
  const nowMs = s.now();
  await s.db.transaction().execute(async (t) => {
    const cur = await t
      .selectFrom("quarantines")
      .selectAll()
      .where("account_id", "=", accountUuid)
      .where("livemode", "=", o.livemode)
      .forUpdate()
      .executeTakeFirst();
    const now = new Date(nowMs);
    if (o.minutes === null) {
      if (!cur || quarantineState(cur, nowMs) !== "active") throw new QuarantineNotFound("no quarantine in force");
      const version = cur.version + 1;
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
        .where("account_id", "=", accountUuid)
        .where("livemode", "=", o.livemode)
        .execute();
      await log(t, accountUuid, o.livemode, "cleared", o.note, o.actor, null, version);
      return;
    }
    const expires = new Date(nowMs + o.minutes * 60_000);
    if (!cur) {
      await t
        .insertInto("quarantines")
        .values({
          account_id: accountUuid,
          livemode: o.livemode,
          status: "active",
          reason: o.note.slice(0, 500),
          created_by: o.actor.slice(0, 200),
          created_at: now,
          expires_at: expires,
          updated_at: now,
        })
        .execute();
      await log(t, accountUuid, o.livemode, "quarantined", o.note, o.actor, expires, 1);
      return;
    }
    const inForce = quarantineState(cur, nowMs) === "active";
    const version = cur.version + 1;
    await t
      .updateTable("quarantines")
      .set({
        status: "active",
        expires_at: expires,
        cleared_at: null,
        cleared_by: null,
        clear_note: null,
        ...(inForce ? {} : { reason: o.note.slice(0, 500), created_by: o.actor.slice(0, 200), created_at: now }),
        version,
        updated_at: now,
      })
      .where("account_id", "=", accountUuid)
      .where("livemode", "=", o.livemode)
      .execute();
    await log(t, accountUuid, o.livemode, inForce ? "extended" : "quarantined", o.note, o.actor, expires, version);
  });
  s.log.warn(
    { account: o.account, livemode: o.livemode, minutes: o.minutes, actor: o.actor },
    o.minutes === null ? "quarantine cleared" : "quarantine set or extended",
  );
  const all = await listQuarantines(s, true);
  return all.find((q) => q.account_id === o.account && q.livemode === o.livemode) as QuarantineView;
}

/**
 * Ops `quarantine-clear-all <reason>` (SENTINEL-2): clears every quarantine in force in a mode that sentinel
 * created and no operator changed since; operator holds are kept and listed. Audit-logged per account.
 */
export async function clearAllQuarantines(
  s: Pick<Sentinel, "db" | "log" | "metrics" | "now">,
  o: { livemode: boolean; note: string; actor: string },
) {
  const r = await s.db
    .transaction()
    .execute((t) =>
      clearSentinelQuarantines(t, { livemode: o.livemode, actor: o.actor, note: o.note, nowMs: s.now() }),
    );
  if (r.cleared.length) s.metrics.quarantinesCleared("ops_all", r.cleared.length);
  s.log.warn(
    { livemode: o.livemode, cleared: r.cleared.length, kept: r.kept.length, actor: o.actor },
    "Merchants paused by sentinel were switched back on by an operator",
  );
  return {
    livemode: o.livemode,
    cleared: r.cleared.map((c) => fromUuid("acct", c.account_id)),
    kept: r.kept.map((k) => ({ account_id: fromUuid("acct", k.account_id), by: k.by })),
  };
}

/** Recorded integrity breaches, newest first. */
export async function listBreaches(s: Pick<Sentinel, "db">, limit: number) {
  const rows = await s.db
    .selectFrom("integrity_breaches")
    .selectAll()
    .orderBy("created_at", "desc")
    .limit(limit)
    .execute();
  return rows.map((r) => ({
    ...r,
    account_id: r.account_id ? fromUuid("acct", r.account_id) : null,
    destination_account_id: r.destination_account_id ? fromUuid("acct", r.destination_account_id) : null,
  }));
}
