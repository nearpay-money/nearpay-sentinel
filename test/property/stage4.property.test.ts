/**
 * Properties of the Stage 4 rules (lld/sentinel.md §16): an SPL mint is attested only for the asset id it
 * hashes to; sentinel's Solana and Bitcoin reads count exactly what reached the recipient in the asset and
 * nothing else; the confirmation tier never weakens as the value grows.
 */
import { keccak_256 } from "@noble/hashes/sha3.js";
import bs58 from "bs58";
import fc from "fast-check";
import { describe, expect, it } from "vitest";
import { reconcileToken, splAssetHash } from "../../src/address-integrity/assets.js";
import { bitcoinReceived, bitcoinScript, solanaReceived } from "../../src/independent-reconciliation/chain-reads.js";
import { BITCOIN_CONFIRMATION_TIERS, requiredConfirmations } from "../../src/spec-0.4.0-placeholder.js";

const bytes32 = fc.uint8Array({ minLength: 32, maxLength: 32 });
const hex = (b: Uint8Array) => Buffer.from(b).toString("hex");

describe("SPL mint ↔ asset id", () => {
  it("a mint reconciles with its own asset id and with no other", () => {
    fc.assert(
      fc.property(bytes32, bytes32, (a, b) => {
        const mint = bs58.encode(a);
        const hash20 = hex(keccak_256(a).subarray(12));
        expect(splAssetHash(mint)).toBe(hash20);
        const id = `nep141:sol-${hash20}.omft.near`;
        expect(reconcileToken(id, { standard: "spl", address: mint })).toEqual({
          ok: true,
          token: { standard: "spl", address: mint },
        });
        if (hex(a) !== hex(b))
          expect(reconcileToken(id, { standard: "spl", address: bs58.encode(b) })).toEqual({ ok: false });
      }),
    );
  });
});

describe("Solana read", () => {
  const R = "H314ws4NAZj5cXEzLVXyLZ3vrwWYuhDEz2cSa5EMs7DR";
  const MINT = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v";
  const HASH = splAssetHash(MINT) as string;
  const OTHER_MINT = "Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB";
  const balance = fc.record({
    owner: fc.constantFrom(R, "bHc9jeXo4NK4ma1W4aLwU5REmqhzTKnzXq79JEeb3Dq"),
    mint: fc.constantFrom(MINT, OTHER_MINT),
    pre: fc.option(fc.bigInt({ min: 0n, max: 10n ** 15n }), { nil: undefined }),
    post: fc.bigInt({ min: 0n, max: 10n ** 15n }),
  });
  it("SPL: the recipient's delta in the asset's mint, never negative, never other owners or mints", () => {
    fc.assert(
      fc.property(fc.array(balance, { maxLength: 6 }), (rows) => {
        const pre = rows.flatMap((r, i) =>
          r.pre === undefined
            ? []
            : [{ accountIndex: i, mint: r.mint, owner: r.owner, uiTokenAmount: { amount: r.pre.toString() } }],
        );
        const post = rows.map((r, i) => ({
          accountIndex: i,
          mint: r.mint,
          owner: r.owner,
          uiTokenAmount: { amount: r.post.toString() },
        }));
        const result = {
          slot: 1,
          meta: { err: null, preTokenBalances: pre, postTokenBalances: post },
          transaction: { message: { accountKeys: rows.map((_, i) => `k${i}`) } },
        };
        const mine = rows.filter((r) => r.owner === R && r.mint === MINT);
        const delta = mine.reduce((s, r) => s + r.post - (r.pre ?? 0n), 0n);
        expect(solanaReceived(result, R, { kind: "spl", hash20: HASH })?.amount).toBe(delta > 0n ? delta : 0n);
      }),
    );
  });
  it("a failed transaction never counts", () => {
    fc.assert(
      fc.property(fc.oneof(fc.string(), fc.object()), (err) => {
        const read = solanaReceived(
          {
            slot: 1,
            meta: { err, preBalances: [0], postBalances: [9] },
            transaction: { message: { accountKeys: [R] } },
          },
          R,
          { kind: "native" },
        );
        expect(read).toMatchObject({ failed: true, amount: 0n });
      }),
    );
  });
});

describe("Bitcoin read and tiers", () => {
  const R = "bc1qgjvrfv789jcls63y95cgan53lq88jnuh32w0fq";
  const OTHER = "bc1pzkakv8d86xwnrvzx262umfvz04dxjeegc4lez8aqdlx50zjfsr5qrjf5pr";
  const TXID = "3a1ced31d7b7d6bace194c90a24e69d62cc3888ed20e15f18f7cf285bb12bd53";
  it("sums exactly the outputs paying the recipient's script; confirmations = tip − height + 1", () => {
    fc.assert(
      fc.property(
        fc.array(fc.record({ ours: fc.boolean(), value: fc.integer({ min: 0, max: 2_100_000_000_000 }) }), {
          maxLength: 8,
        }),
        fc.option(fc.integer({ min: 800_000, max: 900_000 }), { nil: null }),
        fc.integer({ min: 0, max: 10 }),
        (outs, height, ahead) => {
          const tx = {
            txid: TXID,
            vout: outs.map((o) => ({
              scriptpubkey: bitcoinScript(o.ours ? R : OTHER),
              scriptpubkey_address: R,
              value: o.value,
            })),
            status:
              height === null
                ? { confirmed: false }
                : { confirmed: true, block_height: height, block_hash: "ab".repeat(32) },
          };
          const tip = (height ?? 850_000) + ahead;
          const read = bitcoinReceived(tx, tip, R, TXID);
          const want = outs.filter((o) => o.ours).reduce((s, o) => s + BigInt(o.value), 0n);
          expect(read?.amount).toBe(want);
          expect(read?.confirmations).toBe(height === null ? 0 : ahead + 1);
        },
      ),
    );
  });
  it("the required confirmations never decrease as the value grows", () => {
    fc.assert(
      fc.property(fc.bigInt({ min: 0n, max: 10n ** 15n }), fc.bigInt({ min: 0n, max: 10n ** 15n }), (a, b) => {
        const [lo, hi] = a <= b ? [a, b] : [b, a];
        expect(requiredConfirmations(BITCOIN_CONFIRMATION_TIERS, lo)).toBeLessThanOrEqual(
          requiredConfirmations(BITCOIN_CONFIRMATION_TIERS, hi),
        );
      }),
    );
  });
});
