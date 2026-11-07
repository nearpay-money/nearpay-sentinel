/**
 * What an asset id says about its chain and token (shared by the co-signer and the auditor), derived
 * from the id alone — never from a registry another service controls.
 */
import { chainByBlockchain } from "@nearpay-internal/chains";

/** NEAR mainnet, where the Intents contract and NEP-141 tokens live. */
export const NEAR = "near:mainnet";

/**
 * What a NEAR Intents asset id says about its token, independently of any registry (PoA bridge,
 * `omft.near`): `nep141:<prefix>-0x<20 bytes>.omft.near` → an ERC-20 on that EVM chain;
 * `nep141:<prefix>.omft.near` → the chain's native asset; `nep141:<prefix>-<token>.omft.near` → another
 * bridged token of that chain; `nep141:<account>` → a NEP-141 token on NEAR; anything else (other
 * bridges, NEP-245 ids) → `other`. `chain` is null when the bridge prefix is not a known chain.
 */
export type AssetShape =
  | { readonly kind: "erc20"; readonly chain: string; readonly contract: string }
  | { readonly kind: "native"; readonly chain: string | null }
  | { readonly kind: "bridged"; readonly chain: string | null }
  | { readonly kind: "nep141"; readonly contract: string }
  | { readonly kind: "other" };

export function assetShape(assetId: string): AssetShape {
  const omft = /^nep141:([a-z0-9]+)(?:-([0-9a-z]+))?\.omft\.near$/.exec(assetId);
  if (omft) {
    const info = chainByBlockchain(omft[1] as string);
    const chain = info?.caip2 ?? null;
    const token = omft[2];
    if (token === undefined) return { kind: "native", chain };
    if (info?.family === "evm" && /^0x[0-9a-f]{40}$/.test(token))
      return { kind: "erc20", chain: info.caip2, contract: token };
    return { kind: "bridged", chain };
  }
  const nep141 = /^nep141:([a-z0-9][a-z0-9._-]*)$/.exec(assetId);
  if (nep141) return { kind: "nep141", contract: nep141[1] as string };
  return { kind: "other" };
}

/** The chain an asset id lives on, when its id says so (null: not derivable). */
export function assetChain(assetId: string): string | null {
  const shape = assetShape(assetId);
  if (shape.kind === "nep141") return NEAR;
  if (shape.kind === "other") return null;
  return shape.chain;
}

/**
 * Display data of the asset the payer sends (CR-15-07, `Attestation.asset`). Sentinel takes `symbol` and
 * `decimals` from its own read of the provider's token registry for the mode (live 1Click `/v0/tokens`
 * with sentinel's key, test: the sandbox's) — never from rails, checkout or the payer — and, for a route
 * quote, also requires them to explain the provider's **signed** `quote.amountInFormatted`: that string must
 * be `amountIn / 10^decimals` truncated or rounded to its own number of fraction digits. A registry that
 * disagrees with the signed quote, or a registry entry outside the contract's bounds, refuses the signature
 * (`unavailable`, never the kill switch): checkout must never render an amount with unattested decimals.
 */
export interface AssetDisplay {
  readonly symbol: string;
  readonly decimals: number;
}

export type AttestedAsset =
  | { readonly ok: true; readonly asset: { asset_id: string; symbol: string; decimals: number } }
  | { readonly ok: false; readonly reason: string };

const DECIMAL = /^(\d+)(?:\.(\d+))?$/;

/** Whether `formatted` is `amountIn / 10^decimals` cut (truncated or rounded) to its own fraction digits. */
export function formattedMatches(amountIn: string, formatted: string, decimals: number): boolean {
  if (!/^\d+$/.test(amountIn)) return false;
  const m = DECIMAL.exec(formatted.trim());
  if (!m) return false;
  const frac = m[2] ?? "";
  const scale = Math.max(frac.length, decimals);
  const a = BigInt(amountIn) * 10n ** BigInt(scale - decimals);
  const f = BigInt(`${m[1]}${frac}`) * 10n ** BigInt(scale - frac.length);
  const step = 10n ** BigInt(scale - frac.length); // one unit of the formatted string's last digit
  // truncated: f ≤ a < f + step; rounded (either way at the half): |a − f| ≤ step / 2
  const truncated = a >= f && a - f < step;
  const diff = a > f ? a - f : f - a;
  return truncated || 2n * diff <= step;
}

export function attestedAsset(
  assetId: string,
  display: AssetDisplay | null,
  signed?: { readonly amountIn: string; readonly amountInFormatted: string },
): AttestedAsset {
  if (!display) return { ok: false, reason: `asset ${assetId} is not in the provider's token registry` };
  const { symbol, decimals } = display;
  if (!Number.isInteger(decimals) || decimals < 0 || decimals > 255)
    return { ok: false, reason: `asset ${assetId} has invalid decimals ${decimals}` };
  if (typeof symbol !== "string" || symbol.length < 1 || symbol.length > 32)
    return { ok: false, reason: `asset ${assetId} has an invalid symbol` };
  if (signed && !formattedMatches(signed.amountIn, signed.amountInFormatted, decimals))
    return {
      ok: false,
      reason: `registry decimals ${decimals} do not explain the signed amountInFormatted ${signed.amountInFormatted.slice(0, 40)}`,
    };
  return { ok: true, asset: { asset_id: assetId, symbol, decimals } };
}
