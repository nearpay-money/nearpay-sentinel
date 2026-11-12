/**
 * Ops CLI `kill-switch-release-status` (2026-11-12 audit): where a kill-switch release stands, in plain words,
 * for the operator who has to do it — the switch, whether its engagement would still engage under the current
 * rules (a diagnostic only: the release stays the operator's decision, in the console), the pending release
 * request and when its requester may complete it on a single-operator platform, and how many paused merchants
 * the release will switch back on. Read-only.
 */
import { fromUuid } from "@nearpay-internal/ids";
import {
  engagementQuarantineSince,
  SYSTEMIC_REASON_PREFIX,
  staleAutomaticStop,
} from "../address-integrity/containment.js";
import type { Sentinel } from "../app/context.js";
import { windowBreaches } from "../kill-switch/containment.js";
import { killSwitchState, plainReason } from "../kill-switch/kill-switch.js";
import {
  DEFAULT_SINGLE_OPERATOR_POLICY,
  RELEASE_TTL_MS,
  SINGLE_OPERATOR_REASON_MIN,
} from "../kill-switch/two-person.js";

const minutes = (ms: number) => Math.max(0, Math.ceil(ms / 60_000));

export async function releaseStatus(s: Pick<Sentinel, "db" | "now" | "containment" | "singleOperator">) {
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
  // the diagnostic: would this engagement still engage under the current rules?
  const breaches = st.reason.startsWith(SYSTEMIC_REASON_PREFIX)
    ? await windowBreaches(s.db, engagedAt - s.containment.systemicWindowMs - 1_000, engagedAt + 1_000)
    : [];
  const verdict = staleAutomaticStop({ actor: st.actor, reason: st.reason, atMs: engagedAt }, breaches, s.containment);

  const since = new Date(engagementQuarantineSince({ actor: st.actor, atMs: engagedAt }, s.containment));
  const paused = await s.db
    .selectFrom("quarantines")
    .select((eb) => eb.fn.countAll<string>().as("n"))
    .where("status", "=", "active")
    .where("expires_at", ">", new Date(now))
    .where("created_by", "=", "sentinel")
    .where("created_at", ">=", since)
    .executeTakeFirstOrThrow();

  const p = await s.db.selectFrom("release_requests").selectAll().where("status", "=", "pending").executeTakeFirst();
  const pendingValid = p && p.switch_version === st.version && p.expires_at.getTime() > now ? p : null;
  const single = pendingValid ? pendingValid.requested_admins !== null && pendingValid.requested_admins <= 1 : null;
  const availableAt = pendingValid && single ? pendingValid.requested_at.getTime() + delayMs : null;

  const steps: string[] = [];
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
    would_engage_under_current_rules: !verdict.stale,
    assessment: verdict.stale
      ? `This stop would not happen under the current rules: ${verdict.why}. Releasing it is safe once you have read the reason.`
      : `Keep it in mind: ${verdict.why}.`,
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
    merchants_switched_back_on_by_release: Number(paused.n),
    steps,
  };
}
