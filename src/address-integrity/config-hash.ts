/**
 * Fee-configuration fingerprint (SENTINEL-1 deploy-skew guard, lld/sentinel.md §12), pure. Rails builds the
 * quote's `referral` and `appFees` from the same four settings sentinel checks them against (R3, R6):
 * `NP_TREASURY_ACCOUNT`, `NP_TEST_TREASURY_ACCOUNT`, `NP_REFERRAL`, `NP_PROVIDER_SPLIT`. When the two services
 * run different values (one redeployed, not the other) every quote fails R3/R6 on every merchant. Both export
 * the same fingerprint as `nearpay_<svc>_fee_config_info{hash}` = 1, and the deploy stack alerts when more than
 * one distinct hash is exposed (`FeeConfigSkew`).
 *
 * Definition (any service must reproduce it byte for byte): the first 16 lowercase hex characters of
 * SHA-256 over the RFC 8785 canonical JSON of
 * `{"v":1,"treasury_live":<string|null>,"treasury_test":<string>,"referral":<string>,
 *   "provider_split":{"share_bps":<int>,"floor_bps":<int>,"stable_floor_bps":<int>}}`.
 */
import { createHash } from "node:crypto";
import canonicalize from "canonicalize";
import type { ProviderSplit } from "./checks.js";

export interface FeeConfig {
  readonly treasury: string | null;
  readonly testTreasury: string;
  readonly referral: string;
  readonly split: ProviderSplit;
}

export function feeConfigHash(c: FeeConfig): string {
  const doc = {
    v: 1,
    treasury_live: c.treasury ?? null,
    treasury_test: c.testTreasury,
    referral: c.referral,
    provider_split: {
      share_bps: c.split.shareBps,
      floor_bps: c.split.floorBps,
      stable_floor_bps: c.split.stableFloorBps,
    },
  };
  return createHash("sha256")
    .update(canonicalize(doc) as string, "utf8")
    .digest("hex")
    .slice(0, 16);
}
