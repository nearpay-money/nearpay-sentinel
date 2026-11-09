/**
 * Spec route bindings (lld/sentinel.md §6). Auth and scopes are enforced from the spec by the bootstrap;
 * console routes additionally pass {@link opsOperator}, which re-checks the ops principal, `opsRoles` and
 * step-up here (fail closed: the two-person rule must hold even where the service package does not
 * enforce `opsRoles` / ops step-up yet).
 */

import { type AnyRoute, createDepositInstructionsAttestation, listAttestationKeys } from "@nearpay/spec";
import { isId } from "@nearpay-internal/ids";
import { ApiError, implement, type RequestContext, type RouteBinding } from "@nearpay-internal/service";
import {
  acknowledgeOpsFinding,
  approveOpsKillSwitchRelease,
  engageOpsKillSwitch,
  getKillSwitch,
  getOpsFinding,
  getOpsKillSwitch,
  listOpsFindings,
  listOpsKillSwitchLog,
  rejectOpsKillSwitchRelease,
  requestOpsKillSwitchRelease,
  setKillSwitch as setKillSwitchRoute,
} from "@nearpay-internal/spec";
import type { Sentinel } from "../app/context.js";
import { attest } from "../co-signer/attest.js";
import { acknowledgeFinding, getFinding, listFindings } from "../independent-reconciliation/findings.js";
import { killSwitchState, killSwitchView, setKillSwitchSinglePerson } from "../kill-switch/kill-switch.js";
import {
  approveRelease,
  engageByOperator,
  killSwitchLog,
  opsKillSwitch,
  rejectRelease,
  requestRelease,
} from "../kill-switch/release.js";
import { type Operator, stepUpFresh } from "../kill-switch/two-person.js";
import { type ClientIpRule, clientIpRule, resolveClientIp } from "./client-ip.js";

/**
 * The payer's IP by identity's rule (L-ID-07): `CF-Connecting-IP` on the server stage, the rightmost untrusted
 * `X-Forwarded-For` hop locally; forwarding headers only from a trusted proxy peer (`NP_TRUSTED_PROXIES`), else the
 * socket peer. Only the spoof counter uses it. Never the leftmost X-Forwarded-For hop: the client writes it.
 */
export function clientIp(
  req: { headers: RequestContext["request"]["headers"]; socket?: { remoteAddress?: string | undefined } | undefined },
  rule: ClientIpRule,
): string {
  const one = (v: string | string[] | undefined) => (Array.isArray(v) ? v[0] : v);
  return (
    resolveClientIp(rule, {
      peer: req.socket?.remoteAddress,
      cfConnectingIp: one(req.headers["cf-connecting-ip"]),
      xForwardedFor: one(req.headers["x-forwarded-for"]),
    }) ?? "unknown"
  ).slice(0, 64);
}

/**
 * The verified console operator of an ops route: an `ops` principal whose `sub` is an operator user id,
 * whose `ops_role` the route admits, and — on step-up routes — with a fresh step-up. Never anything the
 * client sends in the body.
 */
export function opsOperator(route: AnyRoute, principal: RequestContext["principal"], nowMs: number): Operator {
  const p = principal as (RequestContext["principal"] & { ops_role?: string }) | null;
  if (p?.ptype !== "ops" || !isId("usr", p.sub))
    throw new ApiError("permission_denied", { message: "This route needs a console operator." });
  const role = p.ops_role;
  if ((role !== "ops" && role !== "ops_admin") || !(route.opsRoles ?? []).includes(role))
    throw new ApiError("permission_denied", { message: `Role ${role ?? "none"} may not call ${route.id}.` });
  const op: Operator = { id: p.sub, role, stepUpUntil: p.step_up_until };
  if (route.stepUp && !stepUpFresh(op, nowMs)) throw new ApiError("step_up_required");
  return op;
}

export interface KeyInfo {
  readonly notAfter: string;
  readonly announced: readonly { kid: string; public_key: string; not_after: string }[];
}

export function sentinelRoutes(s: Sentinel, keys: KeyInfo): RouteBinding[] {
  const operator = (ctx: RequestContext) => opsOperator(ctx.route, ctx.principal, s.now());
  return [
    implement(createDepositInstructionsAttestation, async (ctx) =>
      attest(s, ctx.body, clientIp(ctx.request, s.clientIp ?? clientIpRule(s.env))),
    ),
    implement(listAttestationKeys, async () => ({
      object: "list" as const,
      keys: [
        { kid: s.signingKey.kid, public_key: s.signingKey.publicRaw, not_after: keys.notAfter },
        ...keys.announced.filter((k) => k.kid !== s.signingKey.kid),
      ],
    })),
    implement(setKillSwitchRoute, async (ctx) => {
      const actor = ctx.principal ? `ops:${ctx.principal.sub}` : "ops";
      return killSwitchView(await setKillSwitchSinglePerson(s, ctx.body.engaged, ctx.body.reason, actor));
    }),
    // spec 0.2.1: services (payments, rails, agentpay) read the switch at boot; never cached, straight from the row
    implement(getKillSwitch, async () => killSwitchView(await killSwitchState(s))),

    // console (stage 2)
    implement(getOpsKillSwitch, async (ctx) => {
      operator(ctx);
      return opsKillSwitch(s);
    }),
    implement(engageOpsKillSwitch, async (ctx) => engageByOperator(s, operator(ctx), ctx.body.reason)),
    implement(requestOpsKillSwitchRelease, async (ctx) => {
      // a replay (same operator, same reason, still pending) answers like the original request
      return (await requestRelease(s, operator(ctx), ctx.body.reason)).approval;
    }),
    implement(approveOpsKillSwitchRelease, async (ctx) =>
      approveRelease(s, operator(ctx), ctx.params.id, ctx.body.note),
    ),
    implement(rejectOpsKillSwitchRelease, async (ctx) => rejectRelease(s, operator(ctx), ctx.params.id, ctx.body.note)),
    implement(listOpsKillSwitchLog, async (ctx) => {
      operator(ctx);
      return killSwitchLog(s, ctx.query);
    }),
    implement(listOpsFindings, async (ctx) => {
      operator(ctx);
      return listFindings(s, ctx.query);
    }),
    implement(getOpsFinding, async (ctx) => {
      operator(ctx);
      return getFinding(s, ctx.params.id);
    }),
    implement(acknowledgeOpsFinding, async (ctx) => acknowledgeFinding(s, operator(ctx), ctx.params.id, ctx.body.note)),
  ];
}
