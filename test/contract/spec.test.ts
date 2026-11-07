/**
 * Contract (foundations §16): every Stage-1 and Stage-2 sentinel route (console `/ops/…` routes included) is bound (and nothing else); every subject
 * the catalogue routes to sentinel is handled; every subject sentinel produces is emitted; the payloads
 * sentinel emits parse with the catalogue schemas; the provider wire schemas parse recorded responses.
 */
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";
import { PUBLIC_ROUTES } from "@nearpay/spec";
import { unhandledSubjects } from "@nearpay-internal/bus";
import { unimplementedRoutes } from "@nearpay-internal/service";
import { INTERNAL_ROUTES, OneClickQuoteResponse, SUBJECTS, type Subject } from "@nearpay-internal/spec";
import { describe, expect, it } from "vitest";
import { sentinelRoutes } from "../../src/api/routes.js";
import { sentinelHandlers } from "../../src/consumers/handlers.js";
import { fixture } from "../support/keys.js";

const ALL = [...PUBLIC_ROUTES, ...INTERNAL_ROUTES];

describe("routes and events", () => {
  it("binds every Stage-1/2 sentinel route, and nothing else", () => {
    const bindings = sentinelRoutes({} as never, { notAfter: "9999-12-31T23:59:59.000Z", announced: [] });
    expect(unimplementedRoutes("sentinel", ALL, bindings, 2).map((r) => r.id)).toEqual([]);
    expect(bindings.map((b) => b.route.id).sort()).toEqual(
      ALL.filter((r) => r.service === "sentinel" && r.stage <= 2)
        .map((r) => r.id)
        .sort(),
    );
  });

  it("handles every subject the catalogue routes to sentinel", () => {
    const handlers = sentinelHandlers({} as never, {} as never);
    expect(unhandledSubjects("sentinel", handlers)).toEqual([]);
    for (const subject of Object.keys(handlers) as Subject[]) expect(SUBJECTS[subject].consumers).toContain("sentinel");
  });

  it("emits every subject sentinel produces", () => {
    const produced = (Object.keys(SUBJECTS) as Subject[]).filter(
      (k) => SUBJECTS[k].producer === "sentinel" && SUBJECTS[k].stage <= 2,
    );
    expect(produced.length).toBeGreaterThan(0);
    const files = (dir: string): string[] =>
      readdirSync(dir).flatMap((f) => (statSync(join(dir, f)).isDirectory() ? files(join(dir, f)) : [join(dir, f)]));
    const src = files(new URL("../../src", import.meta.url).pathname)
      .map((f) => readFileSync(f, "utf8"))
      .join("\n");
    for (const s of produced) expect(src).toContain(s);
  });

  it("console routes are ops routes with the roles of the two-person rule", () => {
    const ops = ALL.filter((r) => r.service === "sentinel" && r.visibility === "ops");
    expect(ops.length).toBe(9);
    const byId = Object.fromEntries(ops.map((r) => [r.id, r]));
    expect(byId.approveOpsKillSwitchRelease?.opsRoles).toEqual(["ops_admin"]);
    expect(byId.approveOpsKillSwitchRelease?.stepUp).toBe(true);
    expect(byId.requestOpsKillSwitchRelease?.stepUp).toBe(true);
    expect(byId.engageOpsKillSwitch?.stepUp).toBeFalsy();
    expect(byId.rejectOpsKillSwitchRelease?.opsRoles).toEqual(["ops_admin"]);
  });
});

describe("provider wire schemas", () => {
  it("parse the recorded 1Click quote", () => {
    expect(OneClickQuoteResponse.safeParse(fixture("oneclick/dry-quote.json")).success).toBe(true);
  });
});
