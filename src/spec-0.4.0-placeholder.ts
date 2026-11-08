/**
 * PLACEHOLDER — delete in Phase B (step 4.2), when `@nearpay/spec` 0.4.0 is published.
 *
 * The only hand-copied Stage 4 contract pieces in this repo, mirrored exactly from `nearpay-spec`
 * `src/common/chains.ts` and `src/internal/sandbox.ts` on branch `stage-4/4.1-chains` (25ab1af).
 * Replace each import of this file with the spec export named below and delete the file.
 */

/** spec `SOLANA_MAINNET`. */
export const SOLANA_MAINNET = "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp" as const;
/** spec `BITCOIN_MAINNET`. */
export const BITCOIN_MAINNET = "bip122:000000000019d6689c085ae165831e93" as const;

/** spec `OmftAsset`. */
export interface OmftAsset {
  readonly blockchain: string;
  readonly kind: "native" | "evm" | "hash20";
  readonly token: string | null;
}

/** spec `parseOmftAssetId` (verbatim). */
export function parseOmftAssetId(assetId: string): OmftAsset | null {
  const m = /^nep141:([a-z0-9]+)(?:-(0x[0-9a-f]{40}|[0-9a-f]{40}))?\.omft\.near$/.exec(assetId);
  if (!m) return null;
  const blockchain = m[1] as string;
  const token = m[2] ?? null;
  if (token === null) return { blockchain, kind: "native", token: null };
  return { blockchain, kind: token.startsWith("0x") ? "evm" : "hash20", token };
}

/** spec `ConfirmationTier`. */
export interface ConfirmationTier {
  readonly below_usd_micros: number | null;
  readonly confirmations: number;
}

/** spec `requiredConfirmations` (verbatim). */
export function requiredConfirmations(tiers: readonly ConfirmationTier[], usdMicros: bigint): number {
  for (const t of tiers)
    if (t.below_usd_micros === null || usdMicros < BigInt(t.below_usd_micros)) return t.confirmations;
  throw new RangeError("confirmation tiers must end with an unbounded tier");
}

/** spec `BITCOIN_CONFIRMATION_TIERS`. */
export const BITCOIN_CONFIRMATION_TIERS: readonly ConfirmationTier[] = Object.freeze([
  { below_usd_micros: 1_000_000_000, confirmations: 1 },
  { below_usd_micros: null, confirmations: 2 },
]);

/** spec 0.4.0 `SimTx` additions (all optional; 0.3.1's loose object already passes them through). */
export interface SimTxStage4 {
  readonly block_ref?: string | null;
  readonly confirmations?: number | null;
  readonly failed?: boolean;
  readonly transfers: readonly {
    readonly token: string;
    readonly to: string;
    readonly amount: string;
    readonly vout?: number | null;
    readonly token_account?: string | null;
  }[];
}
