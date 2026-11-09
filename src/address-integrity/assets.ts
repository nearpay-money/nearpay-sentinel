/**
 * What an asset id says about its chain and token (shared by the co-signer and the auditor), derived
 * from the id alone — never from a registry another service controls.
 */
import { chainByBlockchain } from "@nearpay-internal/chains";
import { keccak_256 } from "@noble/hashes/sha3.js";
import bs58 from "bs58";

/** NEAR mainnet, where the Intents contract and NEP-141 tokens live. */
export const NEAR = "near:mainnet";

/**
 * What a NEAR Intents asset id says about its token, independently of any registry (PoA bridge,
 * `omft.near`): `nep141:<prefix>-0x<20 bytes>.omft.near` → an ERC-20 on that EVM chain;
 * `nep141:<prefix>.omft.near` → the chain's native asset; `nep141:sol-<40 hex>.omft.near` → a Solana SPL
 * token whose mint hashes to that value (Stage 4, {@link splAssetHash}); `nep141:<prefix>-<token>.omft.near`
 * → another bridged token of that chain; `nep141:<account>` → a NEP-141 token on NEAR; anything else (other
 * bridges, NEP-245 ids) → `other`. `chain` is null when the bridge prefix is not a known chain.
 */
export type AssetShape =
  | { readonly kind: "erc20"; readonly chain: string; readonly contract: string }
  | { readonly kind: "spl"; readonly chain: string; readonly hash20: string }
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
    if (info?.family === "solana" && /^[0-9a-f]{40}$/.test(token))
      return { kind: "spl", chain: info.caip2, hash20: token };
    return { kind: "bridged", chain };
  }
  const nep141 = /^nep141:([a-z0-9][a-z0-9._-]*)$/.exec(assetId);
  if (nep141) return { kind: "nep141", contract: nep141[1] as string };
  return { kind: "other" };
}

/**
 * The omft token part of a Solana SPL mint (lld/sentinel.md §16, spec `chains-solana-bitcoin.json` `omft`):
 * `hex(keccak256(raw 32 mint bytes)[12..32])`; null when `mint` is not base58 of 32 bytes.
 */
export function splAssetHash(mint: string): string | null {
  if (!/^[1-9A-HJ-NP-Za-km-z]{32,44}$/.test(mint)) return null;
  let raw: Uint8Array;
  try {
    raw = bs58.decode(mint);
  } catch {
    return null;
  }
  if (raw.length !== 32) return null;
  return Buffer.from(keccak_256(raw).subarray(12)).toString("hex");
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
  /**
   * How to transfer the asset on its chain (spec 0.2.1 `Attestation.asset.token`), from the same registry
   * entry: its `blockchain` family and `contractAddress`. Null / absent when the entry does not say.
   */
  readonly token?: TokenContractView | null;
  /** USD price from the same registry entry (decimal string), for the Bitcoin audit tier only (§16). */
  readonly priceUsd?: string | null;
}

/** Spec `TokenContract` (wallet path). */
export interface TokenContractView {
  readonly standard: "erc20" | "native" | "nep141" | "spl" | "other";
  readonly address: string | null;
}

export type AttestedAsset =
  | {
      readonly ok: true;
      readonly asset: { asset_id: string; symbol: string; decimals: number; token: TokenContractView | null };
    }
  | { readonly ok: false; readonly reason: string };

/**
 * The token contract of a registry entry (spec 0.2.1): by the chain family of its 1Click `blockchain` code —
 * EVM `erc20`, NEAR `nep141`, Solana `spl` with a contract, `native` without one; Bitcoin `native`; any other
 * family `other`. An entry without a `blockchain` code (or with an unknown one) has no token (null: the
 * manual path). Addresses are kept as listed (EVM lowercased), at most 256 characters.
 */
export function registryTokenContract(
  blockchain: string | null | undefined,
  contractAddress: string | null | undefined,
): TokenContractView | null {
  if (!blockchain) return null;
  const info = chainByBlockchain(blockchain);
  if (!info) return null;
  const raw = contractAddress?.trim() ?? "";
  if (raw.length > 256) return null;
  const address = raw.length > 0 ? raw : null;
  switch (info.family) {
    case "evm":
      return address ? { standard: "erc20", address: address.toLowerCase() } : { standard: "native", address: null };
    case "near":
      return address ? { standard: "nep141", address } : { standard: "native", address: null };
    case "solana":
      return address ? { standard: "spl", address } : { standard: "native", address: null };
    case "bitcoin":
      return { standard: "native", address: null };
    default:
      return { standard: "other", address };
  }
}

/**
 * The registry's token contract checked against what the asset id itself says (defence in depth: a registry
 * entry must never make the wallet path transfer a contract other than the one the Intents asset id names).
 * An id naming an ERC-20 (`<chain>-0x….omft.near`) or a NEP-141 account (`nep141:<account>`) needs that
 * contract: a different contract (or another standard) is a contradiction (refused); an entry that lists no
 * contract for it (`native`) gives no token (null: the manual path — never "send the native coin"). An id
 * naming a Solana SPL token (`sol-<hash20>.omft.near`, Stage 4) is reconciled the same way: the registry's
 * `spl` mint must hash to `hash20` ({@link splAssetHash}), anything else refuses, and a listing without a
 * mint gives no token. An id naming the chain's native coin needs `native`. Ids that name no contract
 * accept what the registry says.
 */
export function reconcileToken(
  assetId: string,
  token: TokenContractView | null,
): { readonly ok: true; readonly token: TokenContractView | null } | { readonly ok: false } {
  if (token === null) return { ok: true, token: null };
  const shape = assetShape(assetId);
  if (shape.kind === "erc20" || shape.kind === "nep141") {
    if (token.standard === "native") return { ok: true, token: null };
    const standard = shape.kind;
    return token.standard === standard && token.address === shape.contract ? { ok: true, token } : { ok: false };
  }
  if (shape.kind === "spl") {
    if (token.standard === "native") return { ok: true, token: null };
    return token.standard === "spl" && token.address !== null && splAssetHash(token.address) === shape.hash20
      ? { ok: true, token }
      : { ok: false };
  }
  if (shape.kind === "native") return token.standard === "native" ? { ok: true, token } : { ok: false };
  return { ok: true, token };
}

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
  const listed = display.token ?? null;
  const token = reconcileToken(assetId, listed);
  if (!token.ok)
    return {
      ok: false,
      reason: `registry token contract ${listed?.standard}:${(listed?.address ?? "").slice(0, 80)} does not match ${assetId}`,
    };
  return { ok: true, asset: { asset_id: assetId, symbol, decimals, token: token.token } };
}
