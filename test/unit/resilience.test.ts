/**
 * 2026-11-12 audit, sentinel side: the 1Click key expiry read from a JWT key (SENTINEL-3), which registry errors
 * get their one retry (SENTINEL-5), the attestation outcomes pre-created for alerting, and the static gauges.
 */
import { createService, type ServiceMetrics } from "@nearpay-internal/service";
import { describe, expect, it } from "vitest";
import { ATTESTATION_OUTCOMES, sentinelMetrics } from "../../src/app/context.js";
import { transientRegistryError } from "../../src/co-signer/attest.js";
import { jwtExpiry, oneClickAuthHeaders } from "../../src/infra/clients/oneclick-auth.js";

const b64 = (o: unknown) => Buffer.from(JSON.stringify(o)).toString("base64url");
const jwt = (payload: unknown) => `${b64({ alg: "RS256", typ: "JWT" })}.${b64(payload)}.c2ln`;

describe("1Click key expiry (SENTINEL-3)", () => {
  it("reads exp from a JWT key; non-JWT keys and keys without a numeric exp give no gauge", () => {
    expect(jwtExpiry(jwt({ sub: "nearpay", exp: 1_800_000_000 }))).toBe(1_800_000_000);
    expect(jwtExpiry(jwt({ exp: 1_800_000_000.7 }))).toBe(1_800_000_000);
    expect(jwtExpiry(jwt({ sub: "nearpay" }))).toBeNull();
    expect(jwtExpiry(jwt({ exp: "tomorrow" }))).toBeNull();
    expect(jwtExpiry(jwt({ exp: -1 }))).toBeNull();
    expect(jwtExpiry("plain-api-key")).toBeNull();
    expect(jwtExpiry(undefined)).toBeNull();
    expect(jwtExpiry("a.b.c")).toBeNull(); // shaped like a JWT, does not decode
    // the auth header rule is unchanged
    expect(oneClickAuthHeaders(jwt({ exp: 1 }))).toHaveProperty("authorization");
    expect(oneClickAuthHeaders("plain-api-key")).toEqual({ "x-api-key": "plain-api-key" });
  });
});

describe("registry retry (SENTINEL-5)", () => {
  it("retries statement and connection timeouts only", () => {
    expect(
      transientRegistryError(
        Object.assign(new Error("canceling statement due to statement timeout"), { code: "57014" }),
      ),
    ).toBe(true);
    expect(transientRegistryError(new Error("timeout exceeded when trying to connect"))).toBe(true);
    expect(transientRegistryError(new Error("Connection terminated due to connection timeout"))).toBe(true);
    expect(transientRegistryError(new Error("permission denied for view sentinel_destination_registry"))).toBe(false);
    expect(transientRegistryError(Object.assign(new Error("relation does not exist"), { code: "42P01" }))).toBe(false);
    expect(transientRegistryError("boom")).toBe(false);
  });
});

describe("metrics", () => {
  async function scrape(f: (m: ServiceMetrics) => void): Promise<string> {
    const service = createService({
      name: "sentinel",
      config: { env: "test", logLevel: "silent", host: "127.0.0.1", port: 0, metricsPort: 0 } as never,
    });
    f(service.metrics);
    return service.metrics.registry.metrics();
  }

  it("pre-creates every attestation outcome at 0 (so the first failure shows in increase()) and exports the statics", async () => {
    const text = await scrape((m) =>
      sentinelMetrics(m, undefined, undefined, undefined, {
        feeConfigHash: "0123456789abcdef",
        oneClickKeyExpiry: { live: 1_800_000_000, test: null },
      }),
    );
    for (const [result, reason] of ATTESTATION_OUTCOMES)
      expect(text).toContain(
        `nearpay_sentinel_attestations_total{kind="route_quote",result="${result}",reason="${reason}"} 0`,
      );
    expect(text).toContain('nearpay_sentinel_fee_config_info{hash="0123456789abcdef"} 1');
    expect(text).toContain('nearpay_sentinel_oneclick_key_expiry_seconds{mode="live"} 1800000000');
    expect(text).not.toContain('oneclick_key_expiry_seconds{mode="test"}');
    expect(text).toContain('nearpay_sentinel_integrity_drift_total{source="r2_only",rules="R2"} 0');
  });

  it("counts drift and bulk clears", async () => {
    const service = createService({
      name: "sentinel",
      config: { env: "test", logLevel: "silent", host: "127.0.0.1", port: 0, metricsPort: 0 } as never,
    });
    const metrics = sentinelMetrics(service.metrics);
    metrics.integrityDrift("pattern", "R6");
    metrics.quarantinesCleared("release", 3);
    const text = await service.metrics.registry.metrics();
    expect(text).toContain('nearpay_sentinel_integrity_drift_total{source="pattern",rules="R6"} 1');
    expect(text).toContain('nearpay_sentinel_quarantines_cleared_total{by="release"} 3');
  });
});
