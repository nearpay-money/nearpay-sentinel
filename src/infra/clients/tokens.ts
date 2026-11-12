/**
 * The provider's token registry read with sentinel's own credentials (CR-15-07, lld/sentinel.md §5
 * "Attested asset"): live 1Click `GET /v0/tokens` (5 s), test mode the sandbox's `GET /v0/tokens`
 * (service token). Only `assetId`, `symbol`, `decimals` and — for the attested token contract (spec 0.2.1) —
 * `blockchain` and `contractAddress` are used (an entry without them still serves symbol/decimals, token null). The list is cached per process for
 * 10 minutes; when a refresh fails, a list younger than 6 hours is still used (an asset id's decimals do
 * not change); an asset missing from the list triggers at most one refresh per 30 s. No list at all is
 * {@link TokensUnavailable}: the co-signer refuses (fail closed).
 *
 * SENTINEL-4: once a list exists a stale one is served at once and refreshed in the background (an
 * attestation never waits 2 × 5 s on a 1Click outage); a failed refresh is not retried for 30 s (negative
 * cache), also when there is no list; the last good list is persisted ({@link TokenListStore}, sentinel's own
 * database) and loaded on first use after a restart, within the same 6-hour age limit.
 */
import { httpClient } from "@nearpay-internal/http";
import { OneClickToken, sandboxTokens } from "@nearpay-internal/spec";
import { z } from "zod";
import { type AssetDisplay, registryTokenContract } from "../../address-integrity/assets.js";
import { oneClickAuthHeaders } from "./oneclick-auth.js";

export class TokensUnavailable extends Error {
  override readonly name = "TokensUnavailable";
}

export interface TokenRegistry {
  /** Display data of an asset id; null when the registry does not list it. Throws {@link TokensUnavailable}. */
  asset(assetId: string): Promise<AssetDisplay | null>;
}

export const TOKENS_FRESH_MS = 10 * 60_000;
export const TOKENS_MAX_AGE_MS = 6 * 60 * 60_000;
export const TOKENS_MISS_REFRESH_MS = 30_000;
/** After a failed refresh, no new attempt for this long (negative cache). */
export const TOKENS_RETRY_MS = 30_000;

/** The last good token list, persisted (a DB row per registry). */
export interface TokenListStore {
  load(): Promise<{ body: unknown; atMs: number } | null>;
  save(body: unknown, atMs: number): Promise<void>;
}

const Entry = OneClickToken.pick({ assetId: true, symbol: true, decimals: true }).extend({
  blockchain: z.string().nullish(),
  contractAddress: z.string().nullish(),
  price: z.unknown().optional(),
});

/**
 * The registry's USD price as an exact decimal string (Stage 4: only the Bitcoin confirmation tier of an
 * audit uses it, §16). A price that is not a plain positive decimal (absent, zero, negative, exponent
 * notation) is null: the auditor then requires the stricter tier.
 */
export function priceString(price: unknown): string | null {
  if (typeof price !== "number" || !Number.isFinite(price) || price <= 0) return null;
  const s = String(price);
  return /^\d+(\.\d+)?$/.test(s) ? s : null;
}

/** Builds the asset map from a token list body; entries that do not parse are left out (and so refused). */
export function tokenMap(body: unknown): Map<string, AssetDisplay> {
  if (!Array.isArray(body)) throw new TokensUnavailable("token list is not an array");
  const map = new Map<string, AssetDisplay>();
  for (const item of body) {
    const e = Entry.safeParse(item);
    if (e.success)
      map.set(e.data.assetId, {
        symbol: e.data.symbol,
        decimals: e.data.decimals,
        token: registryTokenContract(e.data.blockchain, e.data.contractAddress),
        priceUsd: priceString(e.data.price),
      });
  }
  return map;
}

/** Caching registry over a list fetcher (module doc). */
export function cachedTokenRegistry(
  fetchList: () => Promise<unknown>,
  now: () => number = Date.now,
  store?: TokenListStore,
): TokenRegistry {
  let list: { map: Map<string, AssetDisplay>; at: number } | null = null;
  let lastMissRefresh = Number.NEGATIVE_INFINITY;
  let retryAt = Number.NEGATIVE_INFINITY;
  let inflight: Promise<void> | null = null;
  let loaded: Promise<void> | null = null;
  const refresh = () => {
    inflight ??= (async () => {
      try {
        const body = await fetchList();
        const map = tokenMap(body);
        list = { map, at: now() };
        retryAt = Number.NEGATIVE_INFINITY;
        await store?.save(body, list.at).catch(() => {});
      } catch (e) {
        retryAt = now() + TOKENS_RETRY_MS;
        throw e;
      } finally {
        inflight = null;
      }
    })();
    return inflight;
  };
  // the persisted last good list, once per process (before the first fetch)
  const load = () => {
    loaded ??= (async () => {
      try {
        const p = await store?.load();
        if (p && !list && now() - p.atMs < TOKENS_MAX_AGE_MS) list = { map: tokenMap(p.body), at: p.atMs };
      } catch {}
    })();
    return loaded;
  };
  async function current(force: boolean): Promise<Map<string, AssetDisplay>> {
    if (store) await load();
    const have = list as { map: Map<string, AssetDisplay>; at: number } | null;
    const usable = have !== null && now() - have.at < TOKENS_MAX_AGE_MS;
    if (have && usable && !force && now() - have.at < TOKENS_FRESH_MS) return have.map;
    const mayTry = now() >= retryAt;
    if (have && usable) {
      if (mayTry) {
        // a miss waits for the refresh (the asset may be new); staleness alone refreshes in the background
        if (force) await refresh().catch(() => {});
        else refresh().catch(() => {});
      }
      return (list as unknown as { map: Map<string, AssetDisplay> }).map;
    }
    if (!mayTry) throw new TokensUnavailable("token registry unreachable (next attempt within 30 s)");
    try {
      await refresh();
    } catch (e) {
      throw new TokensUnavailable(`token registry unreachable: ${e instanceof Error ? e.message : String(e)}`);
    }
    return (list as unknown as { map: Map<string, AssetDisplay> }).map;
  }
  return {
    async asset(assetId) {
      const hit = (await current(false)).get(assetId);
      if (hit) return hit;
      if (now() - lastMissRefresh < TOKENS_MISS_REFRESH_MS) return null;
      lastMissRefresh = now();
      return (await current(true)).get(assetId) ?? null;
    },
  };
}

export function oneClickTokens(o: {
  baseUrl: string;
  apiKey?: string | undefined;
  fetch?: typeof fetch;
  store?: TokenListStore;
  now?: () => number;
}): TokenRegistry {
  const client = httpClient({
    target: "oneclick",
    baseUrl: o.baseUrl,
    timeoutMs: 5_000,
    attempts: 2,
    breaker: false,
    ...(o.fetch ? { fetch: o.fetch } : {}),
  });
  return cachedTokenRegistry(
    async () =>
      (await client.request({ method: "GET", path: "/v0/tokens", headers: oneClickAuthHeaders(o.apiKey) })).body,
    o.now,
    o.store,
  );
}

export function sandboxTokenRegistry(o: {
  baseUrl: string;
  serviceToken: () => Promise<string>;
  fetch?: typeof fetch;
  store?: TokenListStore;
}): TokenRegistry {
  const client = httpClient({
    target: "sandbox",
    baseUrl: o.baseUrl,
    timeoutMs: 2_000,
    attempts: 2,
    breaker: false,
    serviceToken: o.serviceToken,
    ...(o.fetch ? { fetch: o.fetch } : {}),
  });
  return cachedTokenRegistry(
    async () => client.request({ method: "GET", path: sandboxTokens.path }).then((r) => r.body),
    Date.now,
    o.store,
  );
}
