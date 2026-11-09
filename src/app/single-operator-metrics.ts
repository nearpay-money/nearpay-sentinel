/**
 * Single-operator monitoring (lld/sentinel.md §6 "Single-operator platforms"): the counter
 * `nearpay_ops_single_operator_actions_total{action}` — two-person actions completed by their requester on a
 * single-operator platform — under one name across services (outside the `nearpay_sentinel_` prefix), so
 * the deploy stack alerts on any increase (Telegram). Plus one boot log line with the configured wait.
 */
import type { Logger, ServiceMetrics } from "@nearpay-internal/service";
import { Counter } from "prom-client";

export const SINGLE_OPERATOR_METRIC = "nearpay_ops_single_operator_actions_total";

export function registerSingleOperatorCounter(m: ServiceMetrics): (action: string) => void {
  const counter = new Counter({
    name: SINGLE_OPERATOR_METRIC,
    help: "Two-person ops actions completed by their requester alone (single-operator platform).",
    labelNames: ["action"],
    registers: [m.registry],
  });
  return (action) => counter.inc({ action });
}

export function logSingleOperatorPolicy(log: Logger, delayS: number): void {
  log.info(
    { two_person: "adaptive", single_operator_delay_s: delayS },
    "two-person rule: adaptive (a second operator is required while 2+ operators can approve)",
  );
}
