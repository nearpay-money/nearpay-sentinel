/** Independent re-verification rules (§7), on recorded NEAR transactions and synthetic executions. */
import type { Execution } from "@nearpay-internal/spec";
import { describe, expect, it } from "vitest";
import {
  attribute,
  consistencyFailures,
  destinationSide,
  destinationVerdict,
  nearTransfers,
  normalRecipient,
  received,
  refundFailures,
  SKEW_MS,
  settlementChain,
} from "../../src/independent-reconciliation/audit.js";
import { txKey, usdMicros } from "../../src/independent-reconciliation/auditor.js";
import { execution, USDC_NEAR } from "../support/executions.js";
import { fixture } from "../support/keys.js";

interface RpcTx {
  result: { receipts_outcome: { outcome: { executor_id: string; logs: string[]; status: Record<string, unknown> } }[] };
}
const receipts = (file: string) =>
  fixture<RpcTx>(`near/${file}`).result.receipts_outcome.map((o) => ({
    executor: o.outcome.executor_id,
    logs: o.outcome.logs,
    success: "SuccessValue" in o.outcome.status || "SuccessReceiptId" in o.outcome.status,
  }));

describe("nearTransfers (recorded transactions)", () => {
  it("reads both mt_transfers of one Intents batch", () => {
    const t = nearTransfers(receipts("tx-intents-transfer.json"), "intents.near");
    expect(t).toEqual([
      {
        via: "intents",
        to: "e7e163850ad161d83d50814ab1e1fbee45cb7c033de1a5585f6feaa7fff4bd58",
        assetId: "nep245:v2_1.omni.hot.tg:137_qiStmoQJDQPTebaPjgx5VBxZv6L",
        amount: 1503822n,
      },
      {
        via: "intents",
        to: "solver-multichain-asset-escrow.near",
        assetId: "nep141:eth-0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48.omft.near",
        amount: 1503974n,
      },
    ]);
  });
  it("ignores mt_transfer logs of another contract (only intents.near moves Intents balances)", () => {
    expect(nearTransfers(receipts("tx-intents-transfer.json"), "other.near")).toEqual([]);
  });
  it("reads a NEP-141 ft_transfer with the token contract as the asset", () => {
    const t = nearTransfers(receipts("tx-usdc-ft-transfer.json"), "intents.near");
    expect(t).toEqual([{ via: "ft", to: "v2.ref-finance.near", assetId: USDC_NEAR, amount: 232035480n }]);
    expect(received(t, "ft", "v2.ref-finance.near", USDC_NEAR)).toBe(232035480n);
    expect(received(t, "intents", "v2.ref-finance.near", USDC_NEAR)).toBe(0n);
  });
  it("ignores failed receipts and malformed events", () => {
    const ok =
      'EVENT_JSON:{"standard":"nep141","version":"1.0.0","event":"ft_transfer","data":[{"new_owner_id":"m.near","amount":"5"}]}';
    const r = [
      { executor: "usdc.near", logs: [ok], success: false },
      {
        executor: "usdc.near",
        logs: [
          'EVENT_JSON:{"standard":"nep141","version":"1.0.0","event":"ft_transfer","data":[{"new_owner_id":"m.near","amount":"-1"}]}',
          'EVENT_JSON:{"standard":"nep141","version":"1.0.0","event":"ft_transfer","data":{"new_owner_id":"m.near"}}',
          'EVENT_JSON:{"standard":"nep245","version":"1.0.0","event":"mt_transfer","data":[{"new_owner_id":"m.near","token_ids":["a","b"],"amounts":["1"]}]}',
          "not an event",
        ],
        success: true,
      },
      {
        executor: "intents.near",
        logs: [
          'EVENT_JSON:{"standard":"nep245","version":"1.0.0","event":"mt_transfer","data":[{"new_owner_id":"M.near","token_ids":["a",7],"amounts":["1","2"]},{"token_ids":["a"],"amounts":["1"]}]}',
        ],
        success: true,
      },
    ];
    expect(nearTransfers(r, "intents.near")).toEqual([{ via: "intents", to: "m.near", assetId: "a", amount: 1n }]);
  });
});

describe("consistency of rails' settlement", () => {
  it("accepts a consistent settlement", () => {
    expect(consistencyFailures(execution())).toEqual([]);
  });
  it("compares EVM recipients in their normal form", () => {
    const x = execution({ settlement: { recipient: "0x52908400098527886e0f7030069857d2e4169ee7" } });
    expect(
      consistencyFailures({ ...x, evidence: { ...ev(x), recipient: "0x52908400098527886E0F7030069857D2E4169EE7" } }),
    ).toEqual([]);
  });
  it.each([
    ["not succeeded", (x: Execution) => ({ ...x, state: "held" }), /state is held/],
    ["no evidence", (x: Execution) => ({ ...x, evidence: null }), /without evidence/],
    [
      "evidence for another recipient",
      (x: Execution) => ({ ...x, evidence: { ...ev(x), recipient: "0x2222222222222222222222222222222222222222" } }),
      /recipient/,
    ],
    [
      "evidence recipient unparseable",
      (x: Execution) => ({ ...x, evidence: { ...ev(x), recipient: "nope" } }),
      /recipient/,
    ],
    ["evidence for another asset", (x: Execution) => ({ ...x, evidence: { ...ev(x), asset_id: USDC_NEAR } }), /asset/],
    [
      "evidence on another chain",
      (x: Execution) => ({ ...x, evidence: { ...ev(x), chain: "eip155:1" } }),
      /chain eip155:1/,
    ],
    ["no settled amount", (x: Execution) => ({ ...x, settled_amount: null }), /no settled amount/],
    ["settled differs from evidence", (x: Execution) => ({ ...x, settled_amount: "1" }), /settled 1 != evidence/],
    [
      "recipient invalid for its chain",
      (x: Execution) => ({ ...x, settlement: { ...x.settlement, recipient: "merchant.near" } }),
      /not a valid address/,
    ],
  ] as const)("refuses %s", (_n, mut, reason) => {
    const out = consistencyFailures(mut(execution()) as Execution);
    expect(out.some((r) => reason.test(r))).toBe(true);
  });
  it("refuses an asset that does not live on the settlement chain", () => {
    const x = execution({
      settlement: { asset_id: "nep141:arb-0xaf88d065e77c8cc2239327c5edb3a432268e5831.omft.near" },
    });
    expect(consistencyFailures(x)).toContain(
      "asset nep141:arb-0xaf88d065e77c8cc2239327c5edb3a432268e5831.omft.near does not live on eip155:8453",
    );
  });
  it("an Intents settlement happens on NEAR whatever the asset", () => {
    const x = execution({
      settlement: { recipient: "Merchant.near", recipient_type: "intents", chain: "eip155:8453" },
    });
    expect(settlementChain(x)).toBe("near:mainnet");
    expect(normalRecipient(x)).toBe("merchant.near");
    expect(consistencyFailures(x)).toEqual([]);
  });
});

function ev(x: Execution): NonNullable<Execution["evidence"]> {
  return x.evidence as NonNullable<Execution["evidence"]>;
}

describe("attribution (double use)", () => {
  it("passes when the chain covers this settlement", () => {
    expect(attribute(2000017n, 2000017n, 0n).result).toBe("pass");
  });
  it("lets one batch settle several payments to the same merchant", () => {
    expect(attribute(4000034n, 2000017n, 2000017n).result).toBe("pass");
  });
  it("refuses a transaction already attributed to another execution", () => {
    expect(attribute(2000017n, 2000017n, 2000017n)).toMatchObject({ result: "mismatch" });
  });
  it("refuses a chain amount below the settled one", () => {
    expect(attribute(2000016n, 2000017n, 0n)).toMatchObject({ result: "mismatch", reason: expect.stringMatching(/</) });
  });
  it("refuses a non-positive settled amount", () => {
    expect(attribute(5n, 0n, 0n).result).toBe("mismatch");
  });
});

describe("destination verdict", () => {
  const created = Date.parse("2026-11-05T10:00:00.000Z");
  const entry = (o: Partial<Parameters<typeof destinationVerdict>[1][number]> = {}) => ({
    type: "chain_address",
    chain: "eip155:8453",
    address_norm: "0x1111111111111111111111111111111111111111",
    active_at: new Date(created - 86_400_000),
    disabled_at: null,
    ...o,
  });
  it("passes a destination active at creation", () => {
    expect(destinationVerdict(execution(), [entry()]).result).toBe("pass");
  });
  it("passes a destination disabled after the execution was created", () => {
    expect(destinationVerdict(execution(), [entry({ disabled_at: new Date(created + 1) })]).result).toBe("pass");
  });
  it("tolerates clock skew between identity and rails", () => {
    expect(destinationVerdict(execution(), [entry({ active_at: new Date(created + SKEW_MS) })]).result).toBe("pass");
    expect(destinationVerdict(execution(), [entry({ disabled_at: new Date(created - SKEW_MS) })]).result).toBe("pass");
  });
  it.each([
    ["no rows", []],
    ["another address", [entry({ address_norm: "0x2222222222222222222222222222222222222222" })]],
    ["another chain", [entry({ chain: "eip155:1" })]],
    ["another type", [entry({ type: "intents_account" })]],
  ])("refuses %s", (_n, rows) => {
    expect(destinationVerdict(execution(), rows as never)).toMatchObject({
      result: "mismatch",
      reason: /not a destination/,
    });
  });
  it.each([
    ["never active", entry({ active_at: null })],
    ["activated after creation", entry({ active_at: new Date(created + SKEW_MS + 1) })],
    ["disabled before creation", entry({ disabled_at: new Date(created - SKEW_MS - 1) })],
  ])("refuses a destination %s", (_n, row) => {
    expect(destinationVerdict(execution(), [row])).toMatchObject({ result: "mismatch", reason: /not active/ });
  });
  it("matches Intents accounts case-insensitively and on any chain", () => {
    const x = execution({ settlement: { recipient: "Merchant.near", recipient_type: "intents" } });
    expect(
      destinationVerdict(x, [entry({ type: "intents_account", chain: "near:mainnet", address_norm: "merchant.near" })])
        .result,
    ).toBe("pass");
  });
  it("refuses an unparseable recipient", () => {
    const x = execution({ settlement: { recipient: "nope" } });
    expect(destinationVerdict(x, [entry()])).toMatchObject({ result: "mismatch" });
  });
});

describe("sampling value", () => {
  it("is amount / 10^decimals × price in USD micros", () => {
    expect(usdMicros(2_000_017n, 6, "1")).toBe(2_000_017n);
    expect(usdMicros(10n ** 18n, 18, "3456.78")).toBe(3_456_780_000n);
    expect(usdMicros(1n, 0, "0.5")).toBe(500_000n);
  });
  it("is null for a price that is not a plain decimal", () => {
    expect(usdMicros(1n, 0, "1e-7")).toBeNull();
    expect(usdMicros(1n, 0, "-1")).toBeNull();
  });
});

describe("transaction keys", () => {
  it("case-folds hex hashes and keeps base58 hashes exact", () => {
    expect(txKey("eip155:8453", "0xABC")).toBe("0xabc");
    expect(txKey("near:mainnet", "AXvXuteK8UUNE3nhGx3Cdmxm1ax3CiqCx2MyFkbCwpYv")).toBe(
      "AXvXuteK8UUNE3nhGx3Cdmxm1ax3CiqCx2MyFkbCwpYv",
    );
  });
});

describe("refund legs (kind: refund)", () => {
  const MERCHANT = "merchant.near";
  const refund = (o: Partial<Execution> = {}) =>
    execution({
      kind: "refund",
      origin: { asset_id: USDC_NEAR, chain: "near:mainnet", refund_to: MERCHANT, refund_type: "intents" },
      settlement: { recipient: "payer.near", recipient_type: "intents", chain: "near:mainnet", asset_id: USDC_NEAR },
      refund: {
        swap_type: null,
        amount: "2000017",
        amount_out_expected: null,
        min_amount_out: null,
        token: null,
        transfer: {
          signer_id: MERCHANT,
          receiver_id: "payer.near",
          token: USDC_NEAR,
          amount: "2000017",
          memo: "np1:4vJ9JU1bJJE96FWSJKvHsmmFADCg4gpZQff4P3bkLKi",
          deadline: "2026-11-05T10:15:00.000Z",
        },
      },
      ...o,
    });

  it("checks the source (the merchant's destination), not the payer's refund address", () => {
    const { side, view } = destinationSide(refund());
    expect(side).toBe("refund_source");
    expect(view.settlement).toMatchObject({ recipient: MERCHANT, recipient_type: "intents", asset_id: USDC_NEAR });
    const row = {
      type: "intents_account",
      chain: "near:mainnet",
      address_norm: MERCHANT,
      active_at: new Date(0),
      disabled_at: null,
    };
    expect(destinationVerdict(view, [row]).result).toBe("pass");
    expect(destinationVerdict(view, [{ ...row, address_norm: "other.near" }]).result).toBe("mismatch");
    const chainSource = destinationSide(
      refund({
        origin: { asset_id: USDC_NEAR, chain: "eip155:8453", refund_to: "0xAbC", refund_type: "origin_chain" },
      }),
    );
    expect(chainSource.view.settlement).toMatchObject({ recipient_type: "destination_chain", chain: "eip155:8453" });
    expect(destinationSide(execution()).side).toBe("recipient");
  });

  it("a merchant-signed transfer must come from the source, in the source asset", () => {
    expect(refundFailures(refund())).toEqual([]);
    expect(refundFailures(execution())).toEqual([]);
    expect(refundFailures(refund({ refund: null }))).toEqual([]);
    const base = refund();
    const t = base.refund?.transfer as NonNullable<NonNullable<Execution["refund"]>["transfer"]>;
    expect(
      refundFailures({
        ...base,
        refund: { ...(base.refund as object), transfer: { ...t, signer_id: "x.near" } } as Execution["refund"],
      }),
    ).toEqual(["refund transfer is not signed by the refund source"]);
    expect(
      refundFailures({
        ...base,
        refund: { ...(base.refund as object), transfer: { ...t, token: "nep141:wrap.near" } } as Execution["refund"],
      }),
    ).toEqual(["refund transfer asset is not the source asset"]);
    expect(refundFailures({ ...base, origin: { ...base.origin, refund_type: "origin_chain" } })).toContain(
      "refund transfer from a non-Intents source",
    );
    expect(consistencyFailures(refund())).toEqual([]);
  });
});
