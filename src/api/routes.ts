/** Spec route bindings (lld/sentinel.md §6). Auth and scopes are enforced from the spec by the bootstrap. */
import { createDepositInstructionsAttestation, listAttestationKeys } from "@nearpay/spec";
import { implement, type RequestContext, type RouteBinding } from "@nearpay-internal/service";
import { setKillSwitch as setKillSwitchRoute } from "@nearpay-internal/spec";
import type { Sentinel } from "../app/context.js";
import { attest } from "../co-signer/attest.js";
import { setKillSwitch } from "../kill-switch/kill-switch.js";

/**
 * The payer's IP: the first `X-Forwarded-For` hop, which the gateway sets (Traefik replaces the
 * header of untrusted clients), else the socket peer. Only the spoof counter uses it.
 */
export function clientIp(req: Pick<RequestContext["request"], "headers" | "ip">): string {
  const xff = req.headers["x-forwarded-for"];
  const first = (Array.isArray(xff) ? xff[0] : xff)?.split(",")[0]?.trim();
  return (first || req.ip || "unknown").slice(0, 64);
}

export interface KeyInfo {
  readonly notAfter: string;
  readonly announced: readonly { kid: string; public_key: string; not_after: string }[];
}

export function sentinelRoutes(s: Sentinel, keys: KeyInfo): RouteBinding[] {
  return [
    implement(createDepositInstructionsAttestation, async (ctx) => attest(s, ctx.body, clientIp(ctx.request))),
    implement(listAttestationKeys, async () => ({
      object: "list" as const,
      keys: [
        { kid: s.signingKey.kid, public_key: s.signingKey.publicRaw, not_after: keys.notAfter },
        ...keys.announced.filter((k) => k.kid !== s.signingKey.kid),
      ],
    })),
    implement(setKillSwitchRoute, async (ctx) => {
      const actor = ctx.principal ? `ops:${ctx.principal.sub}` : "ops";
      const st = await setKillSwitch(s, ctx.body.engaged, ctx.body.reason, actor);
      return { engaged: st.engaged, reason: st.reason, actor: st.actor, updated_at: st.updated_at.toISOString() };
    }),
  ];
}
