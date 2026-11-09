/**
 * Sentinel's own reads of Solana and Bitcoin settlements (lld/sentinel.md §16), pure: what a finalized
 * Solana transaction or a confirmed Bitcoin transaction moved to a recipient. The rules are rails' §21.3
 * rules pinned by spec `chains-solana-bitcoin.json` (`evidence`); sentinel re-derives everything from
 * the raw RPC answer and the asset id, never from rails' evidence:
 *
 * - Solana SPL: Σ post − Σ pre of the token balances whose `owner` is the recipient and whose `mint`
 *   hashes to the asset id's `hash20` (a missing pre entry counts 0: the ATA was created in the
 *   transaction); SOL: post − pre lamports at the recipient's account index. `meta.err` set = failed.
 * - Bitcoin: Σ value of the outputs whose scriptPubKey is the recipient's (re-derived from the address,
 *   never from Esplora's `scriptpubkey_address`); confirmations = tip − height + 1 (unconfirmed = 0).
 */
import * as btc from "@scure/btc-signer";
import { splAssetHash } from "../address-integrity/assets.js";

export type SolanaAsset = { readonly kind: "native" } | { readonly kind: "spl"; readonly hash20: string };

export interface SolanaRead {
  readonly failed: boolean;
  readonly amount: bigint;
  readonly slot: number;
  readonly blockTime: number | null;
  /** The mint that settled (hashes to the asset id), null for SOL or when the recipient got none. */
  readonly mint: string | null;
  readonly tokenAccounts: readonly string[];
}

const INT = /^\d+$/;

interface TokenBalance {
  accountIndex: number;
  mint: string;
  owner?: string;
  uiTokenAmount: { amount: string };
}

function tokenBalances(v: unknown): TokenBalance[] | null {
  if (v === undefined || v === null) return [];
  if (!Array.isArray(v)) return null;
  const out: TokenBalance[] = [];
  for (const b of v) {
    if (
      typeof b !== "object" ||
      b === null ||
      !Number.isInteger((b as TokenBalance).accountIndex) ||
      typeof (b as TokenBalance).mint !== "string" ||
      typeof (b as TokenBalance).uiTokenAmount?.amount !== "string" ||
      !INT.test((b as TokenBalance).uiTokenAmount.amount)
    )
      return null;
    out.push(b as TokenBalance);
  }
  return out;
}

function lamports(v: unknown): bigint[] | null {
  if (!Array.isArray(v)) return null;
  const out: bigint[] = [];
  for (const x of v) {
    if (typeof x === "number" && Number.isSafeInteger(x) && x >= 0) out.push(BigInt(x));
    else if (typeof x === "string" && INT.test(x)) out.push(BigInt(x));
    else return null;
  }
  return out;
}

/** Account keys in index order: static keys, then (non-parsed encodings) loaded writable, loaded readonly. */
function accountKeys(message: unknown, meta: unknown): string[] | null {
  const keys = (message as { accountKeys?: unknown } | null)?.accountKeys;
  if (!Array.isArray(keys)) return null;
  const out: string[] = [];
  let parsed = false;
  for (const k of keys) {
    if (typeof k === "string") out.push(k);
    else if (typeof k === "object" && k !== null && typeof (k as { pubkey?: unknown }).pubkey === "string") {
      out.push((k as { pubkey: string }).pubkey);
      parsed = true; // jsonParsed lists lookup-table keys inline (`source: lookupTable`)
    } else return null;
  }
  const loaded = (meta as { loadedAddresses?: { writable?: unknown; readonly?: unknown } } | null)?.loadedAddresses;
  if (!parsed && loaded) {
    for (const list of [loaded.writable, loaded.readonly]) {
      if (list === undefined || list === null) continue;
      if (!Array.isArray(list) || list.some((x) => typeof x !== "string")) return null;
      out.push(...(list as string[]));
    }
  }
  return out;
}

/**
 * What `getTransaction(…, finalized, jsonParsed)` shows `recipient` received in `asset`; null when the
 * answer is malformed (treated as unverifiable by the caller, never as a pass).
 */
export function solanaReceived(result: unknown, recipient: string, asset: SolanaAsset): SolanaRead | null {
  if (typeof result !== "object" || result === null) return null;
  const r = result as { slot?: unknown; blockTime?: unknown; meta?: unknown; transaction?: { message?: unknown } };
  if (!Number.isSafeInteger(r.slot) || (r.slot as number) < 0) return null;
  const blockTime = Number.isSafeInteger(r.blockTime) ? (r.blockTime as number) : null;
  const meta = r.meta as { err?: unknown; preBalances?: unknown; postBalances?: unknown } | null | undefined;
  if (!meta || typeof meta !== "object") return null;
  const slot = r.slot as number;
  const failed = meta.err !== null && meta.err !== undefined;
  if (failed) return { failed, amount: 0n, slot, blockTime, mint: null, tokenAccounts: [] };

  if (asset.kind === "native") {
    const keys = accountKeys(r.transaction?.message, meta);
    const pre = lamports(meta.preBalances);
    const post = lamports(meta.postBalances);
    if (!keys || !pre || !post || pre.length !== keys.length || post.length !== keys.length) return null;
    let amount = 0n;
    keys.forEach((k, i) => {
      if (k === recipient) amount += (post[i] as bigint) - (pre[i] as bigint);
    });
    return { failed, amount: amount > 0n ? amount : 0n, slot, blockTime, mint: null, tokenAccounts: [] };
  }

  const pre = tokenBalances((meta as { preTokenBalances?: unknown }).preTokenBalances);
  const post = tokenBalances((meta as { postTokenBalances?: unknown }).postTokenBalances);
  if (!pre || !post) return null;
  const keys = accountKeys(r.transaction?.message, meta);
  const hashOf = new Map<string, string | null>();
  const ours = (b: TokenBalance) => {
    if (b.owner !== recipient) return false;
    if (!hashOf.has(b.mint)) hashOf.set(b.mint, splAssetHash(b.mint));
    return hashOf.get(b.mint) === asset.hash20;
  };
  const sum = (list: TokenBalance[]) => list.filter(ours).reduce((s, b) => s + BigInt(b.uiTokenAmount.amount), 0n);
  const delta = sum(post) - sum(pre);
  const mine = post.filter(ours);
  const preAmount = new Map(pre.filter(ours).map((b) => [b.accountIndex, BigInt(b.uiTokenAmount.amount)]));
  const changed = mine.filter((b) => BigInt(b.uiTokenAmount.amount) !== (preAmount.get(b.accountIndex) ?? 0n));
  return {
    failed,
    amount: delta > 0n ? delta : 0n,
    slot,
    blockTime,
    mint: mine[0]?.mint ?? null,
    tokenAccounts: changed.map((b) => keys?.[b.accountIndex] ?? `#${b.accountIndex}`),
  };
}

export interface BitcoinRead {
  readonly amount: bigint;
  readonly outputs: readonly { vout: number; value: bigint }[];
  readonly confirmations: number;
  readonly blockHeight: number | null;
  readonly blockHash: string | null;
}

/** The scriptPubKey (hex) of a mainnet Bitcoin address; null when it is not one. */
export function bitcoinScript(address: string): string | null {
  try {
    return Buffer.from(btc.OutScript.encode(btc.Address(btc.NETWORK).decode(address))).toString("hex");
  } catch {
    return null;
  }
}

/**
 * What Esplora's `/tx/{txid}` (with the tip height from `/blocks/tip/height`) shows `recipient`
 * received; null when the answer is malformed or the recipient is not a mainnet address.
 */
export function bitcoinReceived(tx: unknown, tipHeight: number, recipient: string, txid: string): BitcoinRead | null {
  const script = bitcoinScript(recipient);
  if (!script || typeof tx !== "object" || tx === null || !Number.isSafeInteger(tipHeight)) return null;
  const t = tx as {
    txid?: unknown;
    vout?: unknown;
    status?: { confirmed?: unknown; block_height?: unknown; block_hash?: unknown };
  };
  if (t.txid !== txid || !Array.isArray(t.vout)) return null;
  const outputs: { vout: number; value: bigint }[] = [];
  for (const [i, o] of (t.vout as unknown[]).entries()) {
    const out = o as { scriptpubkey?: unknown; value?: unknown };
    if (typeof out?.scriptpubkey !== "string") return null;
    if (!(typeof out.value === "number" && Number.isSafeInteger(out.value) && out.value >= 0)) return null;
    if (out.scriptpubkey.toLowerCase() === script) outputs.push({ vout: i, value: BigInt(out.value) });
  }
  const amount = outputs.reduce((s, o) => s + o.value, 0n);
  const confirmed = t.status?.confirmed === true;
  const height = confirmed && Number.isSafeInteger(t.status?.block_height) ? (t.status?.block_height as number) : null;
  if (confirmed && height === null) return null;
  const hash =
    confirmed && typeof t.status?.block_hash === "string" && /^[0-9a-f]{64}$/.test(t.status.block_hash)
      ? t.status.block_hash
      : null;
  const confirmations = height === null ? 0 : Math.max(0, tipHeight - height + 1);
  return { amount, outputs, confirmations, blockHeight: height, blockHash: hash };
}
