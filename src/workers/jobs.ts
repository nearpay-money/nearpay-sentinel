/**
 * Jobs (lld/sentinel.md §7), run by `sentinel-auditor` (leases, backoff, dead letters):
 *
 * | kind            | when                        | what                                             |
 * |-----------------|-----------------------------|--------------------------------------------------|
 * | audit.execution | per `execution.settled`     | sampling, then the destination and settlement checks |
 * | kit.purge       | hourly                      | published outbox, old inbox, expired idempotency keys |
 */
import { type JobHandler, purgeKitTables, type RecurringJob } from "@nearpay-internal/db";
import { Execution } from "@nearpay-internal/spec";
import type { Sentinel } from "../app/context.js";
import { AUDIT_JOB, auditExecution, sampled } from "../independent-reconciliation/auditor.js";

const HOUR = 3_600_000;

export const RECURRING: readonly RecurringJob[] = [{ kind: "kit.purge", everyMs: HOUR }];

export function jobHandlers(s: Sentinel): Record<string, JobHandler> {
  return {
    [AUDIT_JOB]: async (payload, ctx) => {
      const parsed = Execution.safeParse((payload as { execution?: unknown } | null)?.execution);
      if (!parsed.success) throw new Error(`audit.execution payload is not an execution: ${parsed.error.message}`);
      const x = parsed.data;
      if (ctx.attempt === 1 && !(await sampled(s, x))) {
        s.metrics.finding("not_sampled");
        return;
      }
      await auditExecution(s, x, ctx.attempt);
    },
    "kit.purge": async () => {
      s.log.info(await purgeKitTables(s.db), "kit tables purged");
    },
  };
}
