/**
 * Containment rules (ADR-0028): the corroboration (systemic) rule, rule ids, quarantine state and TTL.
 * One payment or one account never stops the platform; breaches across accounts within the window do.
 */
import { describe, expect, it } from "vitest";
import {
  type Breach,
  DEFAULT_CONTAINMENT,
  quarantineExpiry,
  quarantineState,
  rulesOf,
  systemicVerdict,
} from "../../src/address-integrity/containment.js";
import { containmentPolicy } from "../../src/config.js";

const NOW = Date.parse("2026-11-12T10:00:00Z");
const MIN = 60_000;
const b = (id: string, account: string | null, agoMin: number): Breach => ({ id, account, atMs: NOW - agoMin * MIN });

describe("systemic rule (defaults: 3 refusals, 2 accounts, 15 min)", () => {
  const p = DEFAULT_CONTAINMENT;

  it("a single breach never engages", () => {
    expect(systemicVerdict([b("1", "a", 0)], p, NOW)).toEqual({ engage: false, refusals: 1, accounts: 1 });
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
    });
  });

  it("an unknown account counts as its own (fail towards detection)", () => {
    expect(systemicVerdict([b("1", null, 1), b("2", null, 1), b("3", null, 0)], p, NOW)).toMatchObject({
      engage: true,
      accounts: 3,
    });
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

  it("a breach sets now + ttl and never shortens an expiry further out", () => {
    const ttl = 30 * MIN;
    expect(quarantineExpiry(null, ttl, NOW).getTime()).toBe(NOW + ttl);
    expect(quarantineExpiry(new Date(NOW + MIN), ttl, NOW).getTime()).toBe(NOW + ttl);
    expect(quarantineExpiry(new Date(NOW + 2 * ttl), ttl, NOW).getTime()).toBe(NOW + 2 * ttl);
  });
});
