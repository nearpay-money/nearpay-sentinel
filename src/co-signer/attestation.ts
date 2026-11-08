/**
 * The attestation object sentinel signs (lld/sentinel.md §5, spec `Attestation`), pure. Every deposit /
 * requirement field is copied field by field from what the checks verified (the request, after R4 proved
 * it is the provider's), the merchant and destination come from identity's registry row, and the asset
 * display data and token contract from sentinel's own token-registry read (CR-15-07, spec 0.2.1) — never
 * from the request, rails or the payer.
 */
import type { Attestation } from "@nearpay/spec";
import { destinationFingerprint } from "@nearpay-internal/chains";
import type { RegistryRow } from "../address-integrity/checks.js";

export interface AttestationInput {
  readonly kind: "route_quote" | "intents_transfer";
  readonly attempt_id: string;
  readonly livemode: boolean;
  readonly deposit?:
    | {
        readonly address: string;
        readonly memo: string | null;
        readonly chain: string;
        readonly origin_asset_id: string;
        readonly amount_in: string;
        readonly deadline: string;
      }
    | undefined;
  readonly requirement?:
    | {
        readonly pay_to: string;
        readonly token: string;
        readonly amount: string;
        readonly fee_to: string;
        readonly fee_amount: string;
        readonly binding: string;
        readonly deadline: string;
      }
    | undefined;
}

export function buildAttestation(
  b: AttestationInput,
  row: Pick<RegistryRow, "merchant_name" | "kyb_verified" | "asset_id" | "chain" | "address_norm">,
  asset: {
    readonly symbol: string;
    readonly decimals: number;
    readonly token?: { readonly standard: string; readonly address: string | null } | null;
  },
  nowMs: number,
): Attestation {
  const d = b.kind === "route_quote" ? b.deposit : undefined;
  const r = b.kind === "intents_transfer" ? b.requirement : undefined;
  if (!d && !r)
    throw new Error(`${b.kind} attestation without its ${b.kind === "route_quote" ? "deposit" : "requirement"}`);
  const deadline = (d?.deadline ?? r?.deadline) as string;
  return {
    v: 1,
    kind: b.kind,
    attempt_id: b.attempt_id as Attestation["attempt_id"],
    livemode: b.livemode,
    ...(d
      ? {
          deposit: {
            address: d.address,
            memo: d.memo,
            chain: d.chain,
            origin_asset_id: d.origin_asset_id,
            amount_in: d.amount_in,
            deadline: d.deadline,
          },
        }
      : {}),
    ...(r
      ? {
          requirement: {
            pay_to: r.pay_to,
            token: r.token,
            amount: r.amount,
            fee_to: r.fee_to,
            fee_amount: r.fee_amount,
            binding: r.binding,
            deadline: r.deadline,
          },
        }
      : {}),
    merchant: { name: row.merchant_name, kyb_verified: row.kyb_verified },
    destination: {
      asset_id: row.asset_id,
      chain: row.chain,
      fingerprint: destinationFingerprint(row.chain, row.address_norm, row.asset_id),
    },
    asset: {
      asset_id: (d?.origin_asset_id ?? r?.token) as string,
      symbol: asset.symbol,
      decimals: asset.decimals,
      // spec 0.2.1: inside the signed object, from the same registry read (never the request)
      token: asset.token ? { standard: asset.token.standard, address: asset.token.address } : null,
    },
    issued_at: new Date(Math.floor(nowMs / 1000) * 1000).toISOString(),
    expires_at: new Date(deadline).toISOString(),
  } as Attestation;
}
