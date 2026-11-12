/**
 * Stage 1 ops CLI (platform §3, lld/sentinel.md §15): `docker compose exec sentinel-api /nodejs/bin/node
 * dist/ops.js <command>`. Every command prints one JSON document; errors print `{"error": …}` and exit 1
 * (2: usage). Kill-switch changes are recorded in `kill_switch_log` with the operator (`cli@<host>`) and
 * emitted like any other change. From Stage 2 the single-person release works only when `NP_ENV` is `local`
 * or `test`; any other value is refused (`two_person_required`: the console's two-person release is the only one).
 */
import { parseArgs } from "node:util";
import { DEAD_LETTER_USAGE, DeadLetterError, KitOpsUsageError, runKitOps, sql } from "@nearpay-internal/db";
import { fromUuid, isId, toUuid } from "@nearpay-internal/ids";
import { ApiError } from "@nearpay-internal/service";
import type { Subject } from "@nearpay-internal/spec";
import type { Sentinel } from "../app/context.js";
import { sentinelHandlers } from "../consumers/handlers.js";
import {
  changeQuarantine,
  clearAllQuarantines,
  listBreaches,
  listQuarantines,
  QuarantineNotFound,
} from "../kill-switch/containment.js";
import { killSwitchState, setKillSwitch, setKillSwitchSinglePerson } from "../kill-switch/kill-switch.js";
import { releaseStatus } from "./release-status.js";

async function quarantineChange(s: Sentinel, o: Parameters<typeof changeQuarantine>[1]) {
  try {
    return await changeQuarantine(s, o);
  } catch (e) {
    if (e instanceof QuarantineNotFound)
      throw new ApiError("state_conflict", { message: "The account has no quarantine in force in that mode." });
    throw e;
  }
}

export const USAGE = `usage: ops.js <command> [arguments]

  kill-switch                               the kill switch and its last 20 changes
  kill-switch-engage <reason…>              stop live quoting now
  kill-switch-release <reason…>             resume live quoting (one operator; local/test stacks only)
  kill-switch-release-status                where a release stands: why payments are paused, whether that stop would
                                            happen under the current rules, whether sentinel releases it by itself
                                            (and when) or why not, the pending request and when it can be
                                            completed, and how many paused merchants the release switches back on
  findings [--all] [--limit N]              open (unacknowledged, non-pass) audit findings; --all: every finding
  finding-ack <fnd_…> <note…>               acknowledge a finding
  attestations <pa_… | deposit key | deposit address> [--limit N]   co-signing records, newest first
  integrity-breaches [--limit N]            security refusals on NearPay deposit addresses, newest first
  quarantines [--all]                       accounts sentinel does not sign for right now; --all: every quarantine
  quarantine-clear <acct_…> <note…> [--test]          sign for the account again now
  quarantine-extend <acct_…> <minutes> <note…> [--test]  hold (or re-hold) the account for <minutes> from now
  quarantine-clear-all <reason…> [--test]   sign again for every account sentinel paused (holds an operator set or
                                            changed are kept and listed)

  A breach on one payment quarantines that account only (ADR-0028); quarantines expire on their own
  (NP_QUARANTINE_TTL_S); retries never extend one. Releasing the kill switch also lifts the quarantines sentinel
  set during the stop. The kill switch is engaged by sentinel only on corroborated breaches across accounts
  and is released in the console (two-person / single-operator release). A stop sentinel engaged that the
  current rules would not engage (a false alarm) is released by sentinel itself within a minute.

dead letters and the outbox (kit 0.6.0):
${DEAD_LETTER_USAGE}`;

class UsageError extends Error {}

export interface OpsDeps {
  actor: string;
  out?: (line: string) => void;
  err?: (line: string) => void;
}

const KIT_COMMANDS = new Set(["dead-letters", "outbox"]);

/** `dead-letters …` / `outbox …` (kit `runKitOps`): consumer dead letters replay through the worker's handlers (inbox-deduped). */
function kitOps(s: Sentinel, argv: readonly string[], actor: string): Promise<unknown> {
  const handlers = sentinelHandlers(s.db, s.cache);
  return runKitOps(s.db, argv[0] as string, argv.slice(1), {
    actor,
    handlers: {
      consumer: async (e) => {
        const h = handlers[e.subject as Subject];
        if (!h) throw new DeadLetterError("no_handler", `sentinel does not consume ${e.subject}`);
        await h(e);
      },
    },
  });
}

export async function runOps(argv: readonly string[], s: Sentinel, deps: OpsDeps): Promise<number> {
  const out = deps.out ?? ((l: string) => process.stdout.write(`${l}\n`));
  const err = deps.err ?? ((l: string) => process.stderr.write(`${l}\n`));
  try {
    if (KIT_COMMANDS.has(argv[0] ?? "")) {
      const result = await kitOps(s, argv, deps.actor);
      out(JSON.stringify(result, (_k, v) => (typeof v === "bigint" ? v.toString() : v), 2));
      return 0;
    }
    const { values, positionals } = parseArgs({
      args: [...argv],
      allowPositionals: true,
      strict: true,
      options: { all: { type: "boolean" }, limit: { type: "string" }, test: { type: "boolean" } },
    });
    const [cmd, ...args] = positionals;
    const result = await run(
      s,
      cmd,
      args,
      { all: values.all ?? false, limit: values.limit, test: values.test ?? false },
      deps.actor,
    );
    out(JSON.stringify(result, (_k, v) => (typeof v === "bigint" ? v.toString() : v), 2));
    return 0;
  } catch (e) {
    const code = (e as { code?: string }).code;
    if (
      e instanceof UsageError ||
      e instanceof KitOpsUsageError ||
      code === "ERR_PARSE_ARGS_UNKNOWN_OPTION" ||
      code === "ERR_PARSE_ARGS_INVALID_OPTION_VALUE"
    ) {
      err(`${e instanceof Error ? e.message : String(e)}\n\n${USAGE}`);
      return 2;
    }
    err(
      JSON.stringify({
        error: e instanceof ApiError || e instanceof DeadLetterError ? { code: e.code, message: e.message } : String(e),
      }),
    );
    return 1;
  }
}

function reasonOf(args: readonly string[]): string {
  const reason = args.join(" ").trim();
  if (!reason) throw new UsageError("a reason is required");
  if (reason.length > 500) throw new UsageError("the reason is limited to 500 characters");
  return reason;
}

function limitOf(v: string | undefined): number {
  if (v === undefined) return 50;
  const n = Number(v);
  if (!Number.isInteger(n) || n < 1 || n > 1000) throw new UsageError("--limit must be an integer from 1 to 1000");
  return n;
}

const findingView = (f: {
  id: string;
  execution_id: string;
  account_id: string;
  livemode: boolean;
  check_kind: string;
  result: string;
  details: unknown;
  created_at: Date;
  acknowledged_at: Date | null;
  acknowledged_by: string | null;
  acknowledgement_note: string | null;
}) => ({
  id: fromUuid("fnd", f.id),
  execution_id: f.execution_id,
  account_id: fromUuid("acct", f.account_id),
  livemode: f.livemode,
  check_kind: f.check_kind,
  result: f.result,
  details: f.details,
  created_at: f.created_at,
  acknowledged_at: f.acknowledged_at,
  acknowledged_by: f.acknowledged_by,
  acknowledgement_note: f.acknowledgement_note,
});

async function run(
  s: Sentinel,
  cmd: string | undefined,
  args: string[],
  o: { all: boolean; limit: string | undefined; test: boolean },
  actor: string,
): Promise<unknown> {
  switch (cmd) {
    case "kill-switch": {
      const [state, log] = await Promise.all([
        killSwitchState(s),
        s.db.selectFrom("kill_switch_log").selectAll().orderBy("created_at", "desc").limit(20).execute(),
      ]);
      return { ...state, log };
    }
    case "kill-switch-engage":
      return setKillSwitch(s, true, reasonOf(args), actor);
    case "kill-switch-release":
      return setKillSwitchSinglePerson(s, false, reasonOf(args), actor);
    case "kill-switch-release-status":
      return releaseStatus(s);
    case "findings": {
      let q = s.db.selectFrom("audit_findings").selectAll().orderBy("created_at", "desc").limit(limitOf(o.limit));
      if (!o.all) q = q.where("result", "<>", "pass").where("acknowledged_at", "is", null);
      return (await q.execute()).map(findingView);
    }
    case "finding-ack": {
      const [ref, ...note] = args;
      if (!ref || !isId("fnd", ref)) throw new UsageError("finding-ack needs a fnd_… id");
      const row = await s.db
        .updateTable("audit_findings")
        .set({
          acknowledged_at: new Date(),
          acknowledged_by: actor.slice(0, 200),
          acknowledgement_note: reasonOf(note),
        })
        .where("id", "=", toUuid(ref, "fnd"))
        .where("acknowledged_at", "is", null)
        .where("result", "<>", "pass")
        .returningAll()
        .executeTakeFirst();
      if (!row) {
        const exists = await s.db
          .selectFrom("audit_findings")
          .select("id")
          .where("id", "=", toUuid(ref, "fnd"))
          .executeTakeFirst();
        if (!exists) throw ApiError.missing("audit_finding", ref);
        throw new ApiError("state_conflict", { message: "The finding is already acknowledged or passed." });
      }
      s.log.warn({ finding: ref, actor }, "audit finding acknowledged");
      return findingView(row);
    }
    case "attestations": {
      const ref = args[0];
      if (!ref) throw new UsageError("attestations needs an attempt id, deposit key or deposit address");
      let q = s.db
        .selectFrom("attestations")
        .select([
          "id",
          "livemode",
          "kind",
          "deposit_key",
          "attempt_id",
          "result",
          "class",
          "reasons",
          "client_ip",
          "expires_at",
          "created_at",
        ])
        .orderBy("created_at", "desc")
        .limit(limitOf(o.limit));
      if (isId("pa", ref)) q = q.where("attempt_id", "=", ref);
      else if (ref.includes("|") || ref.startsWith("np1:")) q = q.where("deposit_key", "=", ref);
      else q = q.where(sql<string>`split_part(deposit_key, '|', 2)`, "=", ref);
      return q.execute();
    }
    case "integrity-breaches":
      return listBreaches(s, limitOf(o.limit));
    case "quarantines":
      return listQuarantines(s, o.all);
    case "quarantine-clear": {
      const [ref, ...note] = args;
      if (!ref || !isId("acct", ref)) throw new UsageError("quarantine-clear needs an acct_… id");
      return quarantineChange(s, { account: ref, livemode: !o.test, minutes: null, note: reasonOf(note), actor });
    }
    case "quarantine-extend": {
      const [ref, minutes, ...note] = args;
      if (!ref || !isId("acct", ref)) throw new UsageError("quarantine-extend needs an acct_… id");
      const m = Number(minutes);
      if (!Number.isInteger(m) || m < 1 || m > 10_080)
        throw new UsageError("minutes must be an integer from 1 to 10080");
      return quarantineChange(s, { account: ref, livemode: !o.test, minutes: m, note: reasonOf(note), actor });
    }
    case "quarantine-clear-all":
      return clearAllQuarantines(s, { livemode: !o.test, note: reasonOf(args), actor });
    default:
      throw new UsageError(cmd ? `unknown command ${cmd}` : "missing command");
  }
}
