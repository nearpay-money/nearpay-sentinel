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
 */
import { emit, sql } from "@nearpay-internal/db";
import { fromUuid, isId, toUuid, uuidv7 } from "@nearpay-internal/ids";
import type { Evidence } from "../address-integrity/checks.js";
import {
  type Breach,
  quarantineExpiry,
  quarantineState,
  rulesOf,
  type SystemicVerdict,
  systemicVerdict,
} from "../address-integrity/containment.js";
import type { Sentinel, Tx } from "../app/context.js";
import { setKillSwitch } from "./kill-switch.js";

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
}

const SYSTEMIC_LOCK = "sentinel.integrity.systemic";
const RUNBOOK =
  "scripts/beta.sh ops sentinel integrity-breaches; ops sentinel quarantines; runbook RB-03 (sentinel mismatch)";

const acctUuid = (id: string | null | undefined): string | null => (id && isId("acct", id) ? toUuid(id, "acct") : null);

/** The pipeline breaches on genuine live addresses inside the corroboration window. */
async function windowBreaches(db: Sentinel["db"] | Tx, sinceMs: number): Promise<Breach[]> {
  const rows = await db
    .selectFrom("integrity_breaches")
    .select(["id", "account_id", "destination_account_id", "created_at"])
    .where("livemode", "=", true)
    .where("evidence", "=", "pipeline")
    .where("created_at", ">=", new Date(sinceMs))
    .execute();
  return rows.map((r) => ({
    id: r.id,
    account: r.account_id ?? r.destination_account_id,
    atMs: r.created_at.getTime(),
  }));
}

/** Scrape-time gauge: the corroboration window right now. */
export async function systemicWindow(s: Pick<Sentinel, "db" | "containment" | "now">) {
  const now = s.now();
  const v = systemicVerdict(await windowBreaches(s.db, now - s.containment.systemicWindowMs), s.containment, now);
  return { refusals: v.refusals, accounts: v.accounts };
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
  const inForce = quarantineState(cur, o.nowMs) === "active";
  const expires = quarantineExpiry(inForce ? cur.expires_at : null, o.ttlMs, o.nowMs);
  const version = cur.version + 1;
  await t
    .updateTable("quarantines")
    .set(
      inForce
        ? { expires_at: expires, version, updated_at: now }
        : {
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
          },
    )
    .where("account_id", "=", o.accountUuid)
    .where("livemode", "=", o.livemode)
    .execute();
  await log(t, o.accountUuid, o.livemode, inForce ? "extended" : "quarantined", reason, "sentinel", expires, version);
  return expires;
}

async function log(
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
    if (pipeline && live) {
      // one corroboration decision at a time, so concurrent breaches cannot each miss the threshold
      await sql`select pg_advisory_xact_lock(hashtext(${SYSTEMIC_LOCK}))`.execute(t);
      const prior = await windowBreaches(t, nowMs - p.systemicWindowMs);
      verdict = systemicVerdict(
        [...prior, { id, account: execAccount ?? i.destinationAccount, atMs: nowMs }],
        p,
        nowMs,
      );
    }
    const quarantineIt = pipeline && live && accounts.length > 0;
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
        created_at: new Date(nowMs),
      })
      .execute();

    // the audit finding (compliance case, ops page) — pipeline evidence on an execution rails named
    if (pipeline && i.lookup.execution_id && execAccount) {
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
    return { quarantined: quarantineIt ? accounts : [], until, verdict, engaged };
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
  } else {
    s.log.error(
      {
        ...ctx,
        quarantined: result.quarantined.map((a) => fromUuid("acct", a)),
        until: result.until?.toISOString() ?? null,
        window: result.verdict,
        runbook: RUNBOOK,
      },
      "ALERT quote integrity breach on a NearPay deposit address",
    );
    if (result.engaged) {
      s.metrics.systemicEngaged();
      s.log.error(
        { ...result.verdict, runbook: RUNBOOK },
        "ALERT systemic integrity breach: sentinel engaged the kill switch (corroborated across accounts); it stays engaged until ops release it",
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
