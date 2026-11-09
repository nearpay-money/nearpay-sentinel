/**
 * Chains sentinel attests independently (lld/sentinel.md §16 "Attested chains"): it co-signs deposits on
 * them (R4: the deposit chain is derivable from the origin asset id) and audits their settlements with its
 * own reads and credentials. Any other chain: co-sign when the omft prefix names the origin chain; audit
 * through the provider's signed status (Tier B).
 */
import { BITCOIN_MAINNET, SOLANA_MAINNET } from "@nearpay/spec";

/** How the `settlement` finding reads a chain (§8.1, §16). */
export type OwnRead = "near_final" | "evm_finalized" | "solana_finalized" | "bitcoin_confirmations";

export interface AttestedChain {
  readonly chain: string;
  readonly read: OwnRead;
  /** R4 also checks the deposit address's shape with kit `validateAddress` (Stage 4 chains). */
  readonly depositAddressShape: boolean;
  readonly stage: 1 | 4;
}

export const ATTESTED_CHAINS: ReadonlyMap<string, AttestedChain> = new Map(
  (
    [
      { chain: "near:mainnet", read: "near_final", depositAddressShape: false, stage: 1 },
      { chain: "eip155:1", read: "evm_finalized", depositAddressShape: false, stage: 1 },
      { chain: "eip155:8453", read: "evm_finalized", depositAddressShape: false, stage: 1 },
      { chain: "eip155:42161", read: "evm_finalized", depositAddressShape: false, stage: 1 },
      { chain: SOLANA_MAINNET, read: "solana_finalized", depositAddressShape: true, stage: 4 },
      { chain: BITCOIN_MAINNET, read: "bitcoin_confirmations", depositAddressShape: true, stage: 4 },
    ] satisfies AttestedChain[]
  ).map((c) => [c.chain, c]),
);

export function attestedChain(chain: string): AttestedChain | null {
  return ATTESTED_CHAINS.get(chain) ?? null;
}
