/**
 * Ops CLI `kill-switch-release-status` (2026-11-12 audit): where a kill-switch release stands, in plain words,
 * for the operator who has to do it — the switch, whether its engagement would still engage under the current
 * rules (a diagnostic only: the release stays the operator's decision, in the console), the pending release
 * request and when its requester may complete it on a single-operator platform, and how many paused merchants
 * the release will switch back on. Read-only.
 *
 * Since the owner decision of 2026-11-13 sentinel-auditor releases a stale automatic stop by itself
 * (kill-switch/auto-release.ts): `automatic_release` says when that is expected, or why it will not happen
 * (an operator's stop, still corroborated, new corroborated evidence, evidence that cannot be judged, the flap
 * guard).
 */
import { fromUuid } from "@nearpay-internal/ids";
import {
  type AutoReleaseDecision,
  DEFAULT_AUTO_RELEASE,
  engagementQuarantineSince,
} from "../address-integrity/containment.js";
import type { Sentinel } from "../app/context.js";
import { assessAutoRelease } from "../kill-switch/auto-release.js";
import { killSwitchState, plainReason } from "../kill-switch/kill-switch.js";
import { bulkClearPlan } from "../kill-switch/quarantine-clear.js";
import {
  DEFAULT_SINGLE_OPERATOR_POLICY,
  RELEASE_TTL_MS,
  SINGLE_OPERATOR_REASON_MIN,
} from "../kill-switch/two-person.js";

const minutes = (ms: number) => Math.max(0, Math.ceil(ms / 60_000));

export async function releaseStatus(
  s: Pick<Sentinel, "db" | "now" | "containment" | "singleOperator"> & Partial<Pick<Sentinel, "autoRelease">>,
) {
  const now = s.now();
  const st = await killSwitchState(s);
  if (!st.engaged)
    return {
      engaged: false,
      summary: "Payments are on: the kill switch is not engaged.",
      kill_switch: { reason: st.reason, actor: st.actor, since: st.updated_at, version: st.version },
    };

  const delayMs = (s.singleOperator ?? DEFAULT_SINGLE_OPERATOR_POLICY).delayMs;
  const engagedAt = st.updated_at.getTime();
  // would this engagement still engage under the current rules, and will sentinel release it by itself?
  const tickMs = (s.autoRelease ?? DEFAULT_AUTO_RELEASE).tickMs;
  let decision: AutoReleaseDecision;
  try {
    decision = await assessAutoRelease(s.db, s, st);
  } catch (e) {
    decision = {
      release: false,
      keep: "unjudgeable",
      why: `its evidence could not be read (${e instanceof Error ? e.message : String(e)})`,
    };
  }
  // the stop itself is a false alarm (released automatically, or held only by the flap guard)
  const stale = decision.release || decision.keep === "flapping";
  const expectedBy = decision.release ? new Date(now + tickMs) : null;

  const since = new Date(engagementQuarantineSince({ actor: st.actor, atMs: engagedAt }, s.containment));
  const plan = await bulkClearPlan(s.db, { since, nowMs: now });

  const p = await s.db.selectFrom("release_requests").selectAll().where("status", "=", "pending").executeTakeFirst();
  const pendingValid = p && p.switch_version === st.version && p.expires_at.getTime() > now ? p : null;
  const single = pendingValid ? pendingValid.requested_admins !== null && pendingValid.requested_admins <= 1 : null;
  const availableAt = pendingValid && single ? pendingValid.requested_at.getTime() + delayMs : null;

  const steps: string[] = [];
  if (expectedBy)
    steps.push(
      `Nothing to do: sentinel switches payments back on by itself at its next check (by ${expectedBy.toISOString()}). If they are still paused a few minutes after that, check that sentinel-auditor is running, or release in the console as below.`,
    );
  if (!pendingValid) {
    steps.push("Open the console, Sentinel > Kill switch, choose Request release and confirm with your passkey.");
    steps.push(
      `If you are the only ops admin: wait ${minutes(delayMs)} min, then choose Approve release on your own request, confirm with your passkey again and write a reason of at least ${SINGLE_OPERATOR_REASON_MIN} characters.`,
    );
    steps.push("If there are two or more ops admins: a different ops admin approves the request in the console.");
  } else if (single && availableAt !== null) {
    steps.push(
      now >= availableAt
        ? "The wait is over: in the console choose Approve release on your request, confirm with your passkey and write the reason."
        : `Wait ${minutes(availableAt - now)} more min (until ${new Date(availableAt).toISOString()}), then complete it in the console with a fresh passkey confirmation and a reason of at least ${SINGLE_OPERATOR_REASON_MIN} characters.`,
    );
  } else {
    steps.push("A different ops admin approves the pending request in the console (Sentinel > Kill switch).");
  }
  steps.push(
    "Then check: scripts/beta.sh ops rails flags (quoting_enabled = true) and scripts/beta.sh routing (no reasons for live).",
  );

  return {
    engaged: true,
    summary: `Payments are paused: ${plainReason(st.reason, st.actor)}.`,
    kill_switch: { reason: st.reason, actor: st.actor, since: st.updated_at, version: st.version },
    would_engage_under_current_rules: !stale,
    assessment: decision.release
      ? `This stop would not happen under the current rules: ${decision.why}. Sentinel switches payments back on by itself within ${Math.ceil(tickMs / 1000)} s.`
      : stale
        ? `This stop would not happen under the current rules, but ${decision.why}. Release it in the console once you have read the reason.`
        : `Keep it in mind: ${decision.why}.`,
    automatic_release: decision.release
      ? { expected: true, expected_by: expectedBy, why: decision.why }
      : {
          expected: false,
          expected_by: null,
          why: `Sentinel will not switch payments back on by itself: ${decision.why}.`,
        },
    pending_release: pendingValid
      ? {
          id: fromUuid("opa", pendingValid.id),
          requested_by: fromUuid("usr", pendingValid.requested_by),
          requested_at: pendingValid.requested_at,
          expires_at: pendingValid.expires_at,
          single_operator: single,
          can_complete_from: availableAt === null ? null : new Date(availableAt),
        }
      : null,
    request_lifetime_min: RELEASE_TTL_MS / 60_000,
    merchants_switched_back_on_by_release: plan.clear.length,
    merchants_kept_paused_by_operators: plan.kept.length,
    steps,
  };
}
