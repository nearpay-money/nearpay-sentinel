/**
 * Automatic release of stale automatic stops (owner decision 2026-11-13; ADR-0028 amendment 2026-11-13): the
 * decision cases. Only a stop sentinel engaged whose reason and evidence would not engage the switch under the
 * current rules is released; an operator's stop, a corroborated systemic stop and an unjudgeable stop never are;
 * new corroborated evidence during the stop and the flap guard keep it engaged.
 */

import { createService } from "@nearpay-internal/service";
import { describe, expect, it } from "vitest";
import {
  AUTO_RELEASE_PREFIX,
  AUTO_RELEASE_SUFFIX,
  autoReleaseDecision,
  autoReleaseReason,
  type Breach,
  DEFAULT_AUTO_RELEASE,
  DEFAULT_CONTAINMENT,
  type Engagement,
  reengagementsAfterAutoRelease,
  STALE_CLASSES,
  type SwitchLogEntry,
  staleAutomaticStop,
} from "../../src/address-integrity/containment.js";
import { sentinelMetrics } from "../../src/app/context.js";
import { autoReleasePolicy } from "../../src/config.js";

const NOW = Date.parse("2026-11-13T00:00:00Z");
const MIN = 60_000;
const p = DEFAULT_CONTAINMENT;
const policy = DEFAULT_AUTO_RELEASE;
const R5 = ["R5 recipient is not an active NearPay destination"];
const LIFETIME = ["R4 deposit address goes inactive before the deadline"];
const b = (id: string, account: string | null, atMs: number, reasons: string[] = R5): Breach => ({
  id,
  account,
  atMs,
  reasons,
});

/** The live incident (2026-11-11T18:58:29Z), judged two days later. */
const INCIDENT: Engagement = {
  actor: "sentinel",
  reason: "integrity breach on 0x11D278921A31AB448c7e27F33c2313C130B05036: R4 deposit chain differs",
  atMs: Date.parse("2026-11-11T18:58:29Z"),
};
const SYSTEMIC_AT = NOW - 30 * MIN;
const systemic: Engagement = {
  actor: "sentinel",
  reason:
    "systemic integrity breach: 3 refusals on NearPay deposit addresses across 2 accounts within 15 min (latest x). Stays engaged until ops release it.",
  atMs: SYSTEMIC_AT,
};

const decide = (
  engagement: Engagement,
  o: { breaches?: Breach[]; log?: SwitchLogEntry[]; reclassified?: { r2Only?: number; request?: number } } = {},
) =>
  autoReleaseDecision({
    engagement,
    breaches: o.breaches ?? [],
    ...(o.reclassified ? { reclassified: o.reclassified } : {}),
    log: o.log ?? [],
    containment: p,
    policy,
    nowMs: NOW,
  });

describe("which stops are released automatically", () => {
  it("the live incident (single payment's R4 deposit chain differs, actor sentinel) is released: omdep misparse", () => {
    expect(decide(INCIDENT)).toEqual({
      release: true,
      class: "omdep_misparse",
      why: expect.stringMatching(/single payment's check/),
    });
  });

  it("other single-payment stops are released, classified by their reasons", () => {
    const single = (reasons: string) => ({ ...INCIDENT, reason: `integrity breach on addr.near: ${reasons}` });
    expect(decide(single("R4 amount differs; R4 deadline differs"))).toMatchObject({
      release: true,
      class: "request_evidence",
    });
    expect(decide(single("R4 deposit chain differs; R4 origin asset differs"))).toMatchObject({
      class: "request_evidence",
    });
    expect(decide(single("R6 appFees has 3 entries"))).toMatchObject({ release: true, class: "drift" });
    expect(decide(single("R2 provider signature does not verify; R3 referral is not NearPay's"))).toMatchObject({
      release: true,
      class: "single_breach",
    });
  });

  it("a systemic stop that is no longer corroborated is released: drift, null accounts, uncorroborated", () => {
    const at = (min: number) => SYSTEMIC_AT - min * MIN;
    expect(
      decide(systemic, {
        breaches: [b("1", "a", at(3), LIFETIME), b("2", "c", at(2), LIFETIME), b("3", "a", at(0), LIFETIME)],
      }),
    ).toMatchObject({ release: true, class: "drift" });
    expect(
      decide(systemic, { breaches: [b("1", "a", at(3)), b("2", null, at(2)), b("3", null, at(0))] }),
    ).toMatchObject({
      release: true,
      class: "null_account",
    });
    expect(decide(systemic, { breaches: [b("1", "a", at(3)), b("2", "c", at(0))] })).toMatchObject({
      release: true,
      class: "uncorroborated",
    });
    // a null account with too few refusals is just uncorroborated
    expect(decide(systemic, { breaches: [b("1", "a", at(3)), b("2", null, at(0))] })).toMatchObject({
      class: "uncorroborated",
    });
  });

  it("a systemic stop whose window rows are all reclassified (R2-only echo drift, request evidence) is released", () => {
    expect(decide(systemic, { reclassified: { r2Only: 3 } })).toMatchObject({ release: true, class: "drift" });
    expect(decide(systemic, { reclassified: { request: 4 } })).toMatchObject({
      release: true,
      class: "request_evidence",
    });
    expect(decide(systemic, { reclassified: { r2Only: 1, request: 2 } })).toMatchObject({ class: "drift" });
  });
});

describe("which stops are never released automatically", () => {
  it("an operator's stop (any actor other than sentinel)", () => {
    for (const actor of ["usr_01m6vree6ye928jvj2vxkyyz08", "cli@host", "system", "Sentinel"])
      expect(decide({ ...INCIDENT, actor })).toEqual({
        release: false,
        keep: "operator",
        why: "an operator engaged it",
      });
  });

  it("a systemic stop that still meets the corroborated-systemic rule", () => {
    const at = (min: number) => SYSTEMIC_AT - min * MIN;
    expect(decide(systemic, { breaches: [b("1", "a", at(3)), b("2", "c", at(2)), b("3", "a", at(0))] })).toMatchObject({
      release: false,
      keep: "corroborated",
      why: "still corroborated: 3 refusals across 2 merchants",
    });
  });

  it("a single-payment stop whose window on record is corroborated", () => {
    const e = { ...INCIDENT, atMs: SYSTEMIC_AT };
    const at = (min: number) => SYSTEMIC_AT - min * MIN;
    expect(decide(e, { breaches: [b("1", "a", at(3)), b("2", "c", at(2)), b("3", "a", at(0))] })).toMatchObject({
      release: false,
      keep: "corroborated",
    });
  });

  it("evidence that cannot be judged: an unknown sentinel reason, or a systemic stop with nothing on record", () => {
    for (const reason of ["integrity breach", "something else", "integrity breach on : R4", ""])
      expect(decide({ ...INCIDENT, reason })).toMatchObject({ release: false, keep: "unjudgeable" });
    expect(decide(systemic)).toMatchObject({
      release: false,
      keep: "unjudgeable",
      why: expect.stringMatching(/not on record/),
    });
    expect(decide(systemic, { reclassified: { r2Only: 0, request: 0 } })).toMatchObject({ keep: "unjudgeable" });
    // breaches after the engagement are not its evidence
    expect(decide(systemic, { breaches: [b("1", "a", SYSTEMIC_AT + 5 * MIN)] })).toMatchObject({ keep: "unjudgeable" });
  });

  it("new corroborated evidence during a stale stop keeps it engaged (the systemic rule cannot engage it again)", () => {
    const e = { ...INCIDENT, atMs: NOW - 60 * MIN };
    const later = [b("1", "a", NOW - 20 * MIN), b("2", "c", NOW - 15 * MIN), b("3", "a", NOW - 10 * MIN)];
    expect(decide(e, { breaches: later })).toMatchObject({
      release: false,
      keep: "new_evidence",
      why: expect.stringMatching(/3 refusals across 2 merchants/),
    });
    // uncorroborated later breaches, drift-classified ones, or ones after now do not hold it
    expect(decide(e, { breaches: later.slice(0, 2) })).toMatchObject({ release: true });
    const drift = later.map((x) => ({ ...x, reasons: LIFETIME }));
    expect(decide(e, { breaches: drift })).toMatchObject({ release: true });
    expect(decide(e, { breaches: later.map((x) => ({ ...x, atMs: x.atMs + 60 * MIN })) })).toMatchObject({
      release: true,
    });
  });
});

describe("flap guard", () => {
  let v = 0;
  const row = (engaged: boolean, actor: string, reason: string, agoMin: number): SwitchLogEntry => ({
    version: ++v,
    engaged,
    actor,
    reason,
    atMs: NOW - agoMin * MIN,
  });
  const auto = (ago: number) =>
    row(false, "sentinel", autoReleaseReason("integrity breach on x: R4 amount differs"), ago);
  const engage = (ago: number, actor = "sentinel") => row(true, actor, "systemic integrity breach: …", ago);
  const cycles = (n: number, startAgo: number) => {
    const out: SwitchLogEntry[] = [];
    for (let i = 0; i < n; i++) out.push(auto(startAgo - i * 10), engage(startAgo - i * 10 - 1));
    return out;
  };

  it("more than N (default 3) re-engagements after automatic releases within 1 h stop automatic release", () => {
    v = 0;
    const three = cycles(3, 50);
    expect(reengagementsAfterAutoRelease(three, NOW, policy.flapWindowMs)).toBe(3);
    expect(decide(INCIDENT, { log: three })).toMatchObject({ release: true });
    v = 0;
    const four = cycles(4, 50);
    expect(reengagementsAfterAutoRelease(four, NOW, policy.flapWindowMs)).toBe(4);
    expect(decide(INCIDENT, { log: four })).toMatchObject({
      release: false,
      keep: "flapping",
      why: expect.stringMatching(/engaged again 4 times within 60 min/),
    });
    // the order of the rows does not matter
    expect(reengagementsAfterAutoRelease([...four].reverse(), NOW, policy.flapWindowMs)).toBe(4);
  });

  it("only re-engagements within the hour, by sentinel, right after an automatic release count", () => {
    v = 0;
    const old = cycles(4, 200); // all more than an hour ago
    expect(reengagementsAfterAutoRelease(old, NOW, policy.flapWindowMs)).toBe(0);
    v = 0;
    const mixed = [
      auto(50),
      engage(49, "usr_01m6vree6ye928jvj2vxkyyz08"), // an operator engaged after it
      row(false, "usr_x+usr_y", "fixed", 40), // an operator release, then sentinel engaged
      engage(39),
      row(false, "sentinel", "some other release", 30),
      engage(29),
    ];
    expect(reengagementsAfterAutoRelease(mixed, NOW, policy.flapWindowMs)).toBe(0);
    // a future row (clock skew) is not counted
    v = 0;
    expect(reengagementsAfterAutoRelease([auto(1), engage(-5)], NOW, policy.flapWindowMs)).toBe(0);
  });

  it("maxReengagements 0: the first re-engagement after an automatic release stops automatic release", () => {
    v = 0;
    const log = cycles(1, 10);
    expect(
      autoReleaseDecision({
        engagement: INCIDENT,
        breaches: [],
        log,
        containment: p,
        policy: { ...policy, maxReengagements: 0 },
        nowMs: NOW,
      }),
    ).toMatchObject({ release: false, keep: "flapping" });
  });
});

describe("release record, configuration, metric", () => {
  it("the kill_switch_log reason names the old reason and ADR-0028, within 500 characters", () => {
    expect(autoReleaseReason(INCIDENT.reason)).toBe(
      "auto-released: integrity breach on 0x11D278921A31AB448c7e27F33c2313C130B05036: R4 deposit chain differs — no longer platform evidence under ADR-0028",
    );
    const long = autoReleaseReason(`integrity breach on x: ${"R4 amount differs; ".repeat(40)}`);
    expect(long).toHaveLength(500);
    expect(long.startsWith(AUTO_RELEASE_PREFIX)).toBe(true);
    expect(long.endsWith(`…${AUTO_RELEASE_SUFFIX}`)).toBe(true);
  });

  it("staleAutomaticStop keeps its diagnostic shape for the ops CLI", () => {
    expect(staleAutomaticStop(INCIDENT, [], p)).toMatchObject({ stale: true, class: "omdep_misparse" });
    expect(staleAutomaticStop({ ...INCIDENT, actor: "usr_x" }, [], p)).toMatchObject({
      stale: false,
      keep: "operator",
    });
  });

  it("autoReleasePolicy: defaults (60 s, 3 re-engagements, 1 h) and overrides", () => {
    expect(autoReleasePolicy({})).toEqual({ tickMs: 60_000, maxReengagements: 3, flapWindowMs: 3_600_000 });
    expect(autoReleasePolicy({ killSwitchAutoReleaseTickS: 30, killSwitchAutoReleaseMaxReengagements: 1 })).toEqual({
      tickMs: 30_000,
      maxReengagements: 1,
      flapWindowMs: 3_600_000,
    });
  });

  it("nearpay_sentinel_kill_switch_auto_released_total{reason_class} is pre-created at 0 and counts", async () => {
    const service = createService({
      name: "sentinel",
      config: { env: "test", logLevel: "silent", host: "127.0.0.1", port: 0, metricsPort: 0 } as never,
    });
    const metrics = sentinelMetrics(service.metrics);
    metrics.killSwitchAutoReleased("omdep_misparse");
    const text = await service.metrics.registry.metrics();
    for (const c of STALE_CLASSES)
      expect(text).toContain(
        `nearpay_sentinel_kill_switch_auto_released_total{reason_class="${c}"} ${c === "omdep_misparse" ? 1 : 0}`,
      );
  });
});
