/**
 * The provider's token registry read with sentinel's own credentials (CR-15-07, lld/sentinel.md §5
 * "Attested asset"): live 1Click `GET /v0/tokens` (5 s), test mode the sandbox's `GET /v0/tokens`
 * (service token). Only `assetId`, `symbol` and `decimals` are used. The list is cached per process for
 * 10 minutes; when a refresh fails, a list younger than 6 hours is still used (an asset id's decimals do
 * not change); an asset missing from the list triggers at most one refresh per 30 s. No list at all is
 * {@link TokensUnavailable}: the co-signer refuses (fail closed).
 */
import { httpClient } from "@nearpay-internal/http";
import { OneClickToken, sandboxTokens } from "@nearpay-internal/spec";
import type { AssetDisplay } from "../../address-integrity/assets.js";
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

const Entry = OneClickToken.pick({ assetId: true, symbol: true, decimals: true });

/** Builds the asset map from a token list body; entries that do not parse are left out (and so refused). */
export function tokenMap(body: unknown): Map<string, AssetDisplay> {
  if (!Array.isArray(body)) throw new TokensUnavailable("token list is not an array");
  const map = new Map<string, AssetDisplay>();
  for (const item of body) {
    const e = Entry.safeParse(item);
    if (e.success) map.set(e.data.assetId, { symbol: e.data.symbol, decimals: e.data.decimals });
  }
  return map;
}

/** Caching registry over a list fetcher. */
export function cachedTokenRegistry(fetchList: () => Promise<unknown>, now: () => number = Date.now): TokenRegistry {
  let list: { map: Map<string, AssetDisplay>; at: number } | null = null;
  let lastMissRefresh = Number.NEGATIVE_INFINITY;
  let inflight: Promise<void> | null = null;
  const refresh = () => {
    inflight ??= (async () => {
      try {
        list = { map: tokenMap(await fetchList()), at: now() };
      } finally {
        inflight = null;
      }
    })();
    return inflight;
  };
  async function current(force: boolean): Promise<Map<string, AssetDisplay>> {
    if (!list || force || now() - list.at >= TOKENS_FRESH_MS) {
      try {
        await refresh();
      } catch (e) {
        if (!list || now() - list.at >= TOKENS_MAX_AGE_MS)
          throw new TokensUnavailable(`token registry unreachable: ${e instanceof Error ? e.message : String(e)}`);
      }
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
  );
}

export function sandboxTokenRegistry(o: {
  baseUrl: string;
  serviceToken: () => Promise<string>;
  fetch?: typeof fetch;
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
  return cachedTokenRegistry(async () =>
    client.request({ method: "GET", path: sandboxTokens.path }).then((r) => r.body),
  );
}
