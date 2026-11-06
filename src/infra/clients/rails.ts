/**
 * Rails' internal API with sentinel's service credentials (scope `rails.read`). Used for two
 * non-verdict questions only (lld/sentinel.md §5, §7): did NearPay issue a deposit address (the kill
 * switch decision after a security refusal), and an asset's decimals and price (audit sampling).
 */
import { httpClient } from "@nearpay-internal/http";
import { getInternalAsset, lookupExecutionByDeposit } from "@nearpay-internal/spec";
import type { RailsClient } from "../../app/context.js";

export function railsClient(o: {
  baseUrl: string;
  serviceToken: () => Promise<string>;
  fetch?: typeof fetch;
}): RailsClient {
  const client = httpClient({
    target: "rails",
    baseUrl: o.baseUrl,
    timeoutMs: 1_000,
    attempts: 2,
    breaker: false,
    serviceToken: o.serviceToken,
    ...(o.fetch ? { fetch: o.fetch } : {}),
  });
  return {
    async exists(address, memo) {
      try {
        const r = await client.call(lookupExecutionByDeposit, {
          query: { deposit_address: address, ...(memo ? { memo } : {}) },
        });
        return { exists: r.exists, livemode: r.livemode };
      } catch {
        return null;
      }
    },
    async asset(assetId, livemode) {
      try {
        const a = await client.call(getInternalAsset, {
          params: { asset_id: assetId },
          query: { livemode: livemode ? "true" : "false" },
        });
        return { decimals: a.decimals, price_usd: a.price_usd };
      } catch {
        return null; // unknown asset or rails unreachable: the caller audits (conservative)
      }
    },
  };
}
