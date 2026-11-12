/**
 * Containment rules (ADR-0028): the corroboration (systemic) rule, rule ids, quarantine state and TTL.
 * One payment or one account never stops the platform; breaches across accounts within the window do.
 */
import { createHash } from "node:crypto";
import fc from "fast-check";
import { describe, expect, it } from "vitest";
import { feeConfigHash } from "../../src/address-integrity/config-hash.js";
import {
  type Breach,
  DEFAULT_CONTAINMENT,
  driftSignature,
  driftSignatures,
  engagementQuarantineSince,
  isDrift,
  quarantineExpiry,
  quarantineState,
  rulesOf,
  staleAutomaticStop,
  stillPipelineBreach,
  systemicVerdict,
} from "../../src/address-integrity/containment.js";
import { containmentPolicy } from "../../src/config.js";

const NOW = Date.parse("2026-11-12T10:00:00Z");
const MIN = 60_000;
const b = (id: string, account: string | null, agoMin: number, reasons?: string[]): Breach => ({
  id,
  account,
  atMs: NOW - agoMin * MIN,
  ...(reasons ? { reasons } : {}),
});
const none = { drift: [], uniformRules: null };

describe("systemic rule (defaults: 3 refusals, 2 accounts, 15 min)", () => {
  const p = DEFAULT_CONTAINMENT;

  it("a single breach never engages", () => {
    expect(systemicVerdict([b("1", "a", 0)], p, NOW)).toEqual({ engage: false, refusals: 1, accounts: 1, ...none });
  });

  it("any number of breaches on one account never engages (a local signal)", () => {
    const one = Array.from({ length: 50 }, (_, i) => b(String(i), "a", i % 10));
    expect(systemicVerdict(one, p, NOW)).toMatchObject({ engage: false, refusals: 50, accounts: 1 });
  });

  it("3 breaches across 2 accounts within the window engage", () => {
    expect(systemicVerdict([b("1", "a", 14), b("2", "a", 5), b("3", "c", 0)], p, NOW)).toEqual({
      engage: true,
      refusals: 3,
      accounts: 2,
      ...none,
    });
  });

  it("2 breaches across 2 accounts are not enough", () => {
    expect(systemicVerdict([b("1", "a", 1), b("2", "c", 0)], p, NOW).engage).toBe(false);
  });

  it("breaches outside the window (or in the future) do not count", () => {
    expect(systemicVerdict([b("1", "a", 16), b("2", "a", 1), b("3", "c", 0), b("4", "d", -1)], p, NOW)).toEqual({
      engage: false,
      refusals: 2,
      accounts: 2,
      ...none,
    });
  });

  it("SENTINEL-7: breaches with no known account count as refusals, never as accounts (3 null-account breaches do not engage)", () => {
    expect(systemicVerdict([b("1", null, 1), b("2", null, 1), b("3", null, 0)], p, NOW)).toMatchObject({
      engage: false,
      refusals: 3,
      accounts: 0,
    });
    // they still add to the refusals of known accounts
    expect(systemicVerdict([b("1", null, 1), b("2", "a", 1), b("3", "c", 0)], p, NOW)).toMatchObject({
      engage: true,
      refusals: 3,
      accounts: 2,
    });
    expect(systemicVerdict([b("1", null, 1), b("2", null, 1), b("3", "c", 0)], p, NOW).engage).toBe(false);
  });

  it("thresholds below 2 are raised to 2: one payment / one account is never global", () => {
    const loose = { ...p, systemicRefusals: 1, systemicAccounts: 1 };
    expect(systemicVerdict([b("1", "a", 0)], loose, NOW).engage).toBe(false);
    expect(systemicVerdict([b("1", "a", 0), b("2", "a", 0)], loose, NOW).engage).toBe(false);
    expect(systemicVerdict([b("1", "a", 0), b("2", "c", 0)], loose, NOW).engage).toBe(true);
  });

  it("configurable", () => {
    const strict = { ...p, systemicRefusals: 5, systemicAccounts: 3, systemicWindowMs: 5 * MIN };
    const five = [b("1", "a", 4), b("2", "c", 3), b("3", "d", 2), b("4", "a", 1), b("5", "c", 0)];
    expect(systemicVerdict(five, strict, NOW).engage).toBe(true);
    expect(systemicVerdict([b("0", "a", 6), ...five.slice(1)], strict, NOW).engage).toBe(false);
  });
});

describe("SENTINEL-1: provider-wide drift never engages the switch", () => {
  const p = DEFAULT_CONTAINMENT;
  const LIFETIME = "R4 deposit address goes inactive before the deadline";
  const ENTRIES = "R6 appFees has 3 entries";
  const SHARE = (x: number, y: number) => `R6 treasury appFee ${x} bps of ${y} is below its share`;

  it("drift signature: only format/semantics reasons that cannot redirect a payment; numbers blanked", () => {
    expect(driftSignature([LIFETIME])).toBe(LIFETIME);
    expect(driftSignature([ENTRIES])).toBe("R6 appFees has # entries");
    expect(driftSignature(["R6 appFees has a non-integer or negative fee"])).not.toBeNull();
    expect(driftSignature([SHARE(10, 50)])).toBe(driftSignature([SHARE(12, 60)]));
    expect(driftSignature([SHARE(10, 50), ENTRIES])).toBe(driftSignature([ENTRIES, SHARE(1, 2)]));
    for (const r of [
      "R2 provider signature does not verify",
      "R3 referral is not NearPay's",
      "R4 deposit address differs",
      "R4 deposit memo differs",
      "R4 deposit address is not a valid sol address (x)",
      "R5 recipient is not an active NearPay destination",
      "R6 appFees pay the treasury 0 times",
      "R6 appFees total 600 bps > 500",
      "R4 amount differs",
    ])
      expect(driftSignature([r])).toBeNull();
    // any non-eligible reason disqualifies the refusal
    expect(driftSignature([ENTRIES, "R2 provider signature does not verify"])).toBeNull();
    expect(driftSignature([ENTRIES, "R4 amount differs"])).toBeNull();
    expect(driftSignature([])).toBeNull();
  });

  it("the same drift-eligible refusal on 2 merchants is drift: not counted, never engages", () => {
    const set = [
      b("1", "a", 3, [ENTRIES]),
      b("2", "c", 2, [ENTRIES]),
      b("3", "a", 1, [ENTRIES]),
      b("4", "d", 0, [ENTRIES]),
    ];
    expect(systemicVerdict(set, p, NOW)).toEqual({
      engage: false,
      refusals: 0,
      accounts: 0,
      drift: ["R6 appFees has # entries"],
      uniformRules: null,
    });
    expect([...driftSignatures(set, p, NOW)]).toEqual(["R6 appFees has # entries"]);
    expect(isDrift({ reasons: [ENTRIES] }, new Set(["R6 appFees has # entries"]))).toBe(true);
    expect(isDrift({}, new Set(["R6 appFees has # entries"]))).toBe(false);
  });

  it("one merchant's repeated drift-eligible refusal is not drift (it counts, but one account never engages)", () => {
    const set = [b("1", "a", 2, [LIFETIME]), b("2", "a", 1, [LIFETIME]), b("3", "a", 0, [LIFETIME])];
    expect(systemicVerdict(set, p, NOW)).toMatchObject({ engage: false, refusals: 3, accounts: 1, drift: [] });
    // unknown accounts never make a drift pattern either
    expect(driftSignatures([b("1", null, 1, [LIFETIME]), b("2", null, 0, [LIFETIME])], p, NOW).size).toBe(0);
  });

  it("drift is excluded but a real breach next to it still counts", () => {
    const R5 = ["R5 recipient is not an active NearPay destination"];
    const set = [
      b("1", "a", 4, [LIFETIME]),
      b("2", "c", 3, [LIFETIME]),
      b("3", "d", 2, R5),
      b("4", "e", 1, R5),
      b("5", "d", 0, R5),
    ];
    expect(systemicVerdict(set, p, NOW)).toMatchObject({ engage: true, refusals: 3, accounts: 2, drift: [LIFETIME] });
  });

  it("non-eligible refusals keep their full weight however uniform; the uniform rule set is reported (drift flag)", () => {
    const sig = ["R2 provider signature does not verify", "R3 referral is not NearPay's"];
    const set = [b("1", "a", 2, sig), b("2", "c", 1, sig), b("3", "a", 0, sig)];
    expect(systemicVerdict(set, p, NOW)).toEqual({
      engage: true,
      refusals: 3,
      accounts: 2,
      drift: [],
      uniformRules: "R2+R3",
    });
    // mixed rule sets: no uniform flag
    expect(
      systemicVerdict([...set, b("4", "d", 0, ["R5 recipient is not an active NearPay destination"])], p, NOW)
        .uniformRules,
    ).toBeNull();
    // one account only: no uniform flag
    expect(systemicVerdict([b("1", "a", 1, sig), b("2", "a", 0, sig)], p, NOW).uniformRules).toBeNull();
  });

  it("property: no set of drift-classified refusals ever engages", () => {
    const eligible = [LIFETIME, ENTRIES, "R6 appFees has a non-integer or negative fee", SHARE(10, 50)];
    fc.assert(
      fc.property(
        fc.array(
          fc.record({
            account: fc.constantFrom("a", "b", "c", "d", null),
            ago: fc.integer({ min: 0, max: 20 }),
            reasons: fc.subarray(eligible, { minLength: 1 }),
          }),
          { maxLength: 40 },
        ),
        (rows) => {
          const set = rows.map((r, i) => b(String(i), r.account, r.ago, r.reasons));
          const v = systemicVerdict(set, p, NOW);
          const drift = new Set(v.drift);
          const counted = set.filter((x) => x.atMs <= NOW && NOW - x.atMs <= p.systemicWindowMs && !isDrift(x, drift));
          // whatever engages is engaged by counted (non-drift) refusals only
          expect(v.refusals).toBe(counted.length);
          if (v.engage) expect(new Set(counted.map((x) => x.account).filter(Boolean)).size).toBeGreaterThanOrEqual(2);
        },
      ),
    );
  });
});

describe("re-reading recorded breaches and engagements under the current rules", () => {
  const p = DEFAULT_CONTAINMENT;
  it("an R2-only breach recorded before SENTINEL-1 on a matched recipient is not a breach any more", () => {
    expect(stillPipelineBreach({ reasons: ["R2 provider signature does not verify"], destinationMatched: true })).toBe(
      false,
    );
    expect(stillPipelineBreach({ reasons: ["R2 provider signature does not verify"], destinationMatched: false })).toBe(
      true,
    );
    expect(
      stillPipelineBreach({
        reasons: ["R2 provider signature does not verify", "R3 referral is not NearPay's"],
        destinationMatched: true,
      }),
    ).toBe(true);
  });

  it("staleAutomaticStop: operator stops are never stale; a single-breach sentinel stop is (the 2026-11-11 incident)", () => {
    expect(staleAutomaticStop({ actor: "usr_x", reason: "investigating", atMs: NOW }, [], p)).toMatchObject({
      stale: false,
    });
    expect(
      staleAutomaticStop(
        {
          actor: "sentinel",
          reason: "integrity breach on 0x11D2…5036: R4 deposit chain differs",
          atMs: NOW,
        },
        [],
        p,
      ),
    ).toMatchObject({ stale: true });
  });

  it("staleAutomaticStop: a systemic stop is re-checked on its window (corroborated → kept, drift → stale, no record → kept)", () => {
    const e = { actor: "sentinel", reason: "systemic integrity breach: 3 refusals …", atMs: NOW };
    const R5 = ["R5 recipient is not an active NearPay destination"];
    expect(staleAutomaticStop(e, [b("1", "a", 3, R5), b("2", "c", 2, R5), b("3", "a", 0, R5)], p)).toMatchObject({
      stale: false,
    });
    const L = ["R4 deposit address goes inactive before the deadline"];
    expect(staleAutomaticStop(e, [b("1", "a", 3, L), b("2", "c", 2, L), b("3", "a", 0, L)], p)).toMatchObject({
      stale: true,
      why: expect.stringMatching(/provider-format/),
    });
    expect(staleAutomaticStop(e, [b("1", "a", 3, R5), b("2", "a", 0, R5)], p)).toMatchObject({
      stale: true,
      why: expect.stringMatching(/no longer corroborated/),
    });
    expect(staleAutomaticStop(e, [], p)).toMatchObject({ stale: false });
    // breaches after the engagement do not count for it
    expect(staleAutomaticStop(e, [b("1", "a", -3, R5), b("2", "c", -2, R5), b("3", "a", -1, R5)], p)).toMatchObject({
      stale: false,
      why: expect.stringMatching(/not on record/),
    });
  });

  it("engagementQuarantineSince: a sentinel stop covers its corroboration window; an operator stop starts when engaged", () => {
    expect(engagementQuarantineSince({ actor: "sentinel", atMs: NOW }, p)).toBe(NOW - p.systemicWindowMs);
    expect(engagementQuarantineSince({ actor: "usr_x", atMs: NOW }, p)).toBe(NOW);
  });
});

describe("configuration", () => {
  it("defaults and seconds → ms", () => {
    expect(containmentPolicy({})).toEqual(DEFAULT_CONTAINMENT);
    expect(
      containmentPolicy({
        integritySystemicRefusals: 4,
        integritySystemicAccounts: 3,
        integritySystemicWindowS: 600,
        quarantineTtlS: 120,
        registryRereadMs: 0,
        registryMaxLagS: 2,
        registryRecentChangeS: 60,
      }),
    ).toEqual({
      systemicRefusals: 4,
      systemicAccounts: 3,
      systemicWindowMs: 600_000,
      quarantineTtlMs: 120_000,
      rereadMs: 0,
      registryMaxLagMs: 2_000,
      registryRecentMs: 60_000,
    });
  });
});

describe("rule ids", () => {
  it("R2 … R6 from reasons, intents otherwise; unique and sorted", () => {
    expect(rulesOf(["R6 appFees …", "R2 provider signature does not verify", "R6 x", "R4 amount differs"])).toEqual([
      "R2",
      "R4",
      "R6",
    ]);
    expect(rulesOf(["fee recipient is not the treasury"])).toEqual(["intents"]);
    expect(rulesOf([])).toEqual([]);
  });
});

describe("quarantine TTL", () => {
  it("state: active until expiry, then expired; cleared wins", () => {
    const q = { status: "active", expires_at: new Date(NOW + MIN) };
    expect(quarantineState(q, NOW)).toBe("active");
    expect(quarantineState(q, NOW + MIN)).toBe("expired");
    expect(quarantineState({ ...q, status: "cleared" }, NOW)).toBe("cleared");
  });

  it("a breach on an account without a quarantine in force sets now + ttl and never shortens an ops expiry", () => {
    const ttl = 30 * MIN;
    expect(quarantineExpiry(null, ttl, NOW).getTime()).toBe(NOW + ttl);
    expect(quarantineExpiry(new Date(NOW + MIN), ttl, NOW).getTime()).toBe(NOW + ttl);
    expect(quarantineExpiry(new Date(NOW + 2 * ttl), ttl, NOW).getTime()).toBe(NOW + 2 * ttl);
  });
});

describe("fee configuration fingerprint (deploy-skew guard)", () => {
  const base = {
    treasury: "intents.near",
    testTreasury: "treasury.nearpay.near",
    referral: "nearpay",
    split: { shareBps: 5000, floorBps: 20, stableFloorBps: 1 },
  };
  it("is 16 hex chars, stable, and changes with any of the four settings", () => {
    const h = feeConfigHash(base);
    expect(h).toMatch(/^[0-9a-f]{16}$/);
    expect(feeConfigHash({ ...base })).toBe(h);
    for (const other of [
      { ...base, treasury: null },
      { ...base, treasury: "other.near" },
      { ...base, testTreasury: "t.near" },
      { ...base, referral: "x" },
      { ...base, split: { ...base.split, shareBps: 4000 } },
      { ...base, split: { ...base.split, floorBps: 21 } },
      { ...base, split: { ...base.split, stableFloorBps: 2 } },
    ])
      expect(feeConfigHash(other)).not.toBe(h);
  });
  it("is defined over RFC 8785 JSON (the vector rails must reproduce)", () => {
    const doc =
      '{"provider_split":{"floor_bps":20,"share_bps":5000,"stable_floor_bps":1},"referral":"nearpay","treasury_live":"intents.near","treasury_test":"treasury.nearpay.near","v":1}';
    expect(feeConfigHash(base)).toBe(createHash("sha256").update(doc).digest("hex").slice(0, 16));
  });
});
