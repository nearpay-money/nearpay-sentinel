/** Attested asset (CR-15-07): display rules (src/address-integrity/assets.ts) and the token-registry cache. */
import { describe, expect, it } from "vitest";
import {
  attestedAsset,
  formattedMatches,
  reconcileToken,
  registryTokenContract,
} from "../../src/address-integrity/assets.js";
import {
  cachedTokenRegistry,
  TOKENS_FRESH_MS,
  TOKENS_MAX_AGE_MS,
  TOKENS_MISS_REFRESH_MS,
  TOKENS_RETRY_MS,
  type TokenListStore,
  TokensUnavailable,
  tokenMap,
} from "../../src/infra/clients/tokens.js";

const USDC = "nep141:base-0x833589fcd6edb6e08f4c7c32d4f71b54bda02913.omft.near";

describe("formattedMatches", () => {
  it("accepts exact, trailing-zero-stripped, truncated and rounded renderings", () => {
    expect(formattedMatches("2014321", "2.014321", 6)).toBe(true);
    expect(formattedMatches("2000000", "2", 6)).toBe(true);
    expect(formattedMatches("2100000", "2.1", 6)).toBe(true);
    expect(formattedMatches("1234567890123456789", "1.234567", 18)).toBe(true); // truncated
    expect(formattedMatches("1234567890123456789", "1.234568", 18)).toBe(true); // rounded up
    expect(formattedMatches("5", "5", 0)).toBe(true);
  });

  it("refuses other decimals and malformed values", () => {
    expect(formattedMatches("2014321", "2.014321", 18)).toBe(false);
    expect(formattedMatches("2014321", "2.014321", 5)).toBe(false);
    expect(formattedMatches("2014321", "2.014321", 7)).toBe(false);
    expect(formattedMatches("2014321", "2.014323", 6)).toBe(false);
    expect(formattedMatches("2014321", "2,014321", 6)).toBe(false);
    expect(formattedMatches("-1", "1", 0)).toBe(false);
    expect(formattedMatches("1", "", 0)).toBe(false);
  });
});

describe("attestedAsset", () => {
  const signed = { amountIn: "2014321", amountInFormatted: "2.014321" };
  it("attests registry data consistent with the signed quote", () => {
    expect(attestedAsset(USDC, { symbol: "USDC", decimals: 6 }, signed)).toEqual({
      ok: true,
      asset: { asset_id: USDC, symbol: "USDC", decimals: 6, token: null },
    });
    expect(attestedAsset(USDC, { symbol: "USDC", decimals: 6 })).toMatchObject({ ok: true });
  });

  it("refuses unknown assets, out-of-contract data and data the signed quote contradicts", () => {
    expect(attestedAsset(USDC, null)).toMatchObject({ ok: false, reason: expect.stringMatching(/not in/) });
    expect(attestedAsset(USDC, { symbol: "USDC", decimals: 256 })).toMatchObject({ ok: false });
    expect(attestedAsset(USDC, { symbol: "USDC", decimals: -1 })).toMatchObject({ ok: false });
    expect(attestedAsset(USDC, { symbol: "USDC", decimals: 1.5 })).toMatchObject({ ok: false });
    expect(attestedAsset(USDC, { symbol: "", decimals: 6 })).toMatchObject({ ok: false });
    expect(attestedAsset(USDC, { symbol: "X".repeat(33), decimals: 6 })).toMatchObject({ ok: false });
    expect(attestedAsset(USDC, { symbol: "USDC", decimals: 18 }, signed)).toMatchObject({
      ok: false,
      reason: expect.stringMatching(/do not explain/),
    });
  });
});

describe("token registry", () => {
  const entry = (assetId: string, decimals = 6) => ({
    assetId,
    decimals,
    blockchain: "base",
    symbol: "USDC",
    price: 1,
    priceUpdatedAt: "2026-11-07T00:00:00Z",
  });

  it("keeps only entries that parse; a non-array body is unavailable", () => {
    const m = tokenMap([entry(USDC), { assetId: "x" }, null, entry("nep141:a.near", 24)]);
    expect([...m.keys()]).toEqual([USDC, "nep141:a.near"]);
    expect(() => tokenMap({})).toThrow(TokensUnavailable);
  });

  it("caches 10 min, serves a list younger than 6 h when a refresh fails, then fails closed", async () => {
    let now = 0;
    let fail = false;
    let calls = 0;
    const r = cachedTokenRegistry(
      async () => {
        calls++;
        if (fail) throw new Error("down");
        return [entry(USDC)];
      },
      () => now,
    );
    expect(await r.asset(USDC)).toMatchObject({
      symbol: "USDC",
      decimals: 6,
      token: { standard: "native", address: null },
    });
    now = TOKENS_FRESH_MS - 1;
    await r.asset(USDC);
    expect(calls).toBe(1);
    fail = true;
    now = TOKENS_FRESH_MS;
    expect(await r.asset(USDC)).toMatchObject({
      symbol: "USDC",
      decimals: 6,
      token: { standard: "native", address: null },
    });
    expect(calls).toBe(2);
    now = TOKENS_MAX_AGE_MS;
    await expect(r.asset(USDC)).rejects.toThrow(TokensUnavailable);
  });

  it("an unknown asset refreshes at most once per 30 s", async () => {
    let now = 0;
    let list = [entry(USDC)];
    let calls = 0;
    const r = cachedTokenRegistry(
      async () => {
        calls++;
        return list;
      },
      () => now,
    );
    expect(await r.asset("nep141:new.near")).toBeNull();
    expect(calls).toBe(2);
    list = [entry(USDC), entry("nep141:new.near", 18)];
    now = TOKENS_MISS_REFRESH_MS - 1;
    expect(await r.asset("nep141:new.near")).toBeNull();
    expect(calls).toBe(2);
    now = TOKENS_MISS_REFRESH_MS + 1;
    expect(await r.asset("nep141:new.near")).toMatchObject({ symbol: "USDC", decimals: 18 });
  });

  it("SENTINEL-4: a failed refresh is not retried for 30 s (negative cache), with or without a list", async () => {
    let now = 0;
    let calls = 0;
    let fail = true;
    const r = cachedTokenRegistry(
      async () => {
        calls++;
        if (fail) throw new Error("down");
        return [entry(USDC)];
      },
      () => now,
    );
    await expect(r.asset(USDC)).rejects.toThrow(TokensUnavailable);
    expect(calls).toBe(1);
    now = TOKENS_RETRY_MS - 1;
    await expect(r.asset(USDC)).rejects.toThrow(/next attempt within 30 s/);
    expect(calls).toBe(1); // the second call within 30 s does not fetch
    now = TOKENS_RETRY_MS;
    fail = false;
    expect(await r.asset(USDC)).toMatchObject({ symbol: "USDC" });
    expect(calls).toBe(2);
    // stale list + failing provider: served at once, one attempt per 30 s
    fail = true;
    now += TOKENS_FRESH_MS;
    expect(await r.asset(USDC)).toMatchObject({ symbol: "USDC" });
    await new Promise((res) => setTimeout(res, 0));
    expect(calls).toBe(3);
    now += TOKENS_RETRY_MS - 1;
    expect(await r.asset(USDC)).toMatchObject({ symbol: "USDC" });
    expect(calls).toBe(3);
  });

  it("SENTINEL-4: a stale list is served immediately and refreshed in the background", async () => {
    let now = 0;
    let release: (v: unknown) => void = () => {};
    let calls = 0;
    const r = cachedTokenRegistry(
      async () => {
        calls++;
        if (calls === 1) return [entry(USDC)];
        return new Promise((res) => {
          release = res;
        });
      },
      () => now,
    );
    await r.asset(USDC);
    now = TOKENS_FRESH_MS + 1;
    // the refresh hangs (1Click slow): the attestation does not wait for it
    expect(await r.asset(USDC)).toMatchObject({ decimals: 6 });
    expect(calls).toBe(2);
    // a second stale read joins the same refresh instead of starting another
    expect(await r.asset(USDC)).toMatchObject({ decimals: 6 });
    expect(calls).toBe(2);
    release([entry(USDC, 18)]);
    await new Promise((res) => setTimeout(res, 0));
    expect(await r.asset(USDC)).toMatchObject({ decimals: 18 });
  });

  it("SENTINEL-4: boot with a persisted list and a failing fetch serves it (within 6 h); a good fetch is saved", async () => {
    let now = 10 * TOKENS_MAX_AGE_MS;
    const saved: { body: unknown; atMs: number }[] = [];
    const store = (atMs: number): TokenListStore => ({
      load: async () => ({ body: [entry(USDC)], atMs }),
      save: async (body, at) => {
        saved.push({ body, atMs: at });
      },
    });
    let fail = true;
    const fetchList = async () => {
      if (fail) throw new Error("down");
      return [entry(USDC, 18)];
    };
    const r = cachedTokenRegistry(fetchList, () => now, store(now - TOKENS_MAX_AGE_MS + 60_000));
    expect(await r.asset(USDC)).toMatchObject({ symbol: "USDC", decimals: 6 });
    // too old to trust: fail closed
    const old = cachedTokenRegistry(fetchList, () => now, store(now - TOKENS_MAX_AGE_MS));
    await expect(old.asset(USDC)).rejects.toThrow(TokensUnavailable);
    // an unreadable store is ignored
    const broken = cachedTokenRegistry(fetchList, () => now, {
      load: async () => {
        throw new Error("db down");
      },
      save: async () => {},
    });
    await expect(broken.asset(USDC)).rejects.toThrow(TokensUnavailable);
    // a successful fetch persists the list
    fail = false;
    now += TOKENS_RETRY_MS;
    const fresh = cachedTokenRegistry(fetchList, () => now, {
      load: async () => null,
      save: async (body, at) => {
        saved.push({ body, atMs: at });
      },
    });
    expect(await fresh.asset(USDC)).toMatchObject({ decimals: 18 });
    expect(saved).toEqual([{ body: [entry(USDC, 18)], atMs: now }]);
  });

  it("no list at all is unavailable", async () => {
    const r = cachedTokenRegistry(async () => {
      throw new Error("down");
    });
    await expect(r.asset(USDC)).rejects.toThrow(TokensUnavailable);
  });
});

describe("attested token contract (spec 0.2.1)", () => {
  const USDC_CONTRACT = "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913";

  it("maps the registry's blockchain family and contract address", () => {
    expect(registryTokenContract("base", USDC_CONTRACT.toUpperCase().replace("0X", "0x"))).toEqual({
      standard: "erc20",
      address: USDC_CONTRACT,
    });
    expect(registryTokenContract("base", null)).toEqual({ standard: "native", address: null });
    expect(registryTokenContract("near", "usdt.tether-token.near")).toEqual({
      standard: "nep141",
      address: "usdt.tether-token.near",
    });
    expect(registryTokenContract("near", "")).toEqual({ standard: "native", address: null });
    expect(registryTokenContract("sol", "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v")).toEqual({
      standard: "spl",
      address: "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",
    });
    expect(registryTokenContract("btc", "ignored")).toEqual({ standard: "native", address: null });
    expect(registryTokenContract(undefined, USDC_CONTRACT)).toBeNull();
    expect(registryTokenContract("no-such-chain", USDC_CONTRACT)).toBeNull();
    expect(registryTokenContract("base", "x".repeat(257))).toBeNull();
  });

  it("must agree with the contract the asset id names", () => {
    const erc20 = { standard: "erc20", address: USDC_CONTRACT } as const;
    expect(reconcileToken(USDC, erc20)).toEqual({ ok: true, token: erc20 });
    expect(reconcileToken(USDC, { standard: "erc20", address: "0x0000000000000000000000000000000000000001" })).toEqual({
      ok: false,
    });
    expect(reconcileToken(USDC, { standard: "spl", address: USDC_CONTRACT })).toEqual({ ok: false });
    // a registry entry without a contract for an id that names one: no token (manual path), never "native"
    expect(reconcileToken(USDC, { standard: "native", address: null })).toEqual({ ok: true, token: null });
    expect(reconcileToken("nep141:wrap.near", { standard: "native", address: null })).toEqual({
      ok: true,
      token: null,
    });
    expect(reconcileToken("nep141:wrap.near", { standard: "nep141", address: "wrap.near" })).toMatchObject({
      ok: true,
    });
    expect(reconcileToken("nep141:wrap.near", { standard: "nep141", address: "evil.near" })).toEqual({ ok: false });
    expect(reconcileToken("nep141:base.omft.near", { standard: "native", address: null })).toMatchObject({
      ok: true,
      token: { standard: "native" },
    });
    expect(reconcileToken("nep141:base.omft.near", erc20)).toEqual({ ok: false });
    expect(reconcileToken("nep245:v2_1.omni.hot.tg:56_11", { standard: "other", address: "x" })).toMatchObject({
      ok: true,
    });
    expect(reconcileToken(USDC, null)).toEqual({ ok: true, token: null });
  });

  it("attestedAsset carries the token, and refuses one that contradicts the asset id", () => {
    expect(
      attestedAsset(USDC, { symbol: "USDC", decimals: 6, token: { standard: "erc20", address: USDC_CONTRACT } }),
    ).toEqual({
      ok: true,
      asset: { asset_id: USDC, symbol: "USDC", decimals: 6, token: { standard: "erc20", address: USDC_CONTRACT } },
    });
    expect(attestedAsset(USDC, { symbol: "USDC", decimals: 6 })).toMatchObject({ ok: true, asset: { token: null } });
    expect(
      attestedAsset(USDC, { symbol: "USDC", decimals: 6, token: { standard: "erc20", address: "0xdeadbeef" } }),
    ).toMatchObject({ ok: false, reason: expect.stringMatching(/does not match/) });
  });

  it("tokenMap reads blockchain and contractAddress; an entry without blockchain keeps display data, token null", () => {
    const m = tokenMap([
      {
        assetId: USDC,
        decimals: 6,
        blockchain: "base",
        symbol: "USDC",
        price: 1,
        priceUpdatedAt: "x",
        contractAddress: USDC_CONTRACT,
      },
      { assetId: "nep141:wrap.near", decimals: 24, symbol: "wNEAR", price: 4, priceUpdatedAt: "x" },
    ]);
    expect(m.get(USDC)?.token).toEqual({ standard: "erc20", address: USDC_CONTRACT });
    expect(m.get("nep141:wrap.near")).toEqual({ symbol: "wNEAR", decimals: 24, token: null, priceUsd: "4" });
  });
});
