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
