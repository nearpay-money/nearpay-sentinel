/**
 * Settlement audit (lld/sentinel.md §7), run by `sentinel-auditor` as the `audit.execution` job that
 * the `evt.rails.execution.settled` consumer enqueues. Two findings per sampled execution:
 *
 * - `destination` — the recipient was the account's registered destination (identity's registry
 *   view), active when the execution was created; for a refund leg (`kind: refund`) the same of its
 *   source (`origin.refund_to`), since the recipient is the payer;
 * - `settlement` — rails' settlement is self-consistent and sentinel's own read shows it: the
 *   destination chain with sentinel's RPC credentials (Tier A: EVM, NEAR; Stage 4: Solana finalized
 *   token-balance delta, Bitcoin outputs + confirmations per tier — §16), the sandbox's simulated
 *   chain (test mode), or the provider's signed status with sentinel's key (Tier B, and live chains
 *   outside the attested set). An attested Stage 4 chain without a sentinel reader is never sent to
 *   Tier B: it records `unverifiable` and alerts `audit_coverage_missing{chain}` (fail closed).
 *
 * Not final / not found / unreachable is transient: the job retries with backoff (about 85 minutes
 * over {@link AUDIT_MAX_ATTEMPTS} attempts) and the last attempt records `unverifiable`. Every
 * non-pass finding emits `evt.sentinel.audit_finding.created` (compliance opens a case; mismatch pages).
 */

import { normalizeAddress } from "@nearpay-internal/chains";
import { emit, sql } from "@nearpay-internal/db";
import { fromUuid, toUuid, uuidv7 } from "@nearpay-internal/ids";
import type { Execution } from "@nearpay-internal/spec";
import { BITCOIN_CONFIRMATION_TIERS, BITCOIN_MAINNET, requiredConfirmations } from "@nearpay-money/spec";
import { assetShape, NEAR } from "../address-integrity/assets.js";
import { attestedChain } from "../address-integrity/attested-chains.js";
import type { Sentinel } from "../app/context.js";
import { ChainUnavailable } from "../infra/clients/chains.js";
import {
  type AuditResult,
  attribute,
  consistencyFailures,
  destinationSide,
  destinationVerdict,
  nearTransfers,
  normalRecipient,
  type Observed,
  received,
  settlementChain,
  type Via,
} from "./audit.js";
import { bitcoinReceived, type SolanaAsset, solanaReceived } from "./chain-reads.js";

export const AUDIT_JOB = "audit.execution";
export const AUDIT_MAX_ATTEMPTS = 10;

/** Transient: retried until the last attempt, which records `unverifiable`. */
export class AuditRetry extends Error {
  override readonly name = "AuditRetry";
}

type CheckKind = "destination" | "settlement";

interface ChainRead {
  readonly chain: string;
  readonly hash: string;
  readonly recipient: string;
  readonly assetId: string;
  readonly observed: bigint;
}

interface Verdict {
  readonly result: AuditResult;
  readonly details: Record<string, unknown>;
  /** A chain read to attribute (pass only after the double-use check). */
  readonly read?: ChainRead;
}

/** Transaction hash as stored and compared: hex (EVM, Bitcoin) case-folded, base58 (NEAR, Solana) exact. */
export function txKey(chain: string, hash: string): string {
  return chain.startsWith("eip155:") || chain.startsWith("bip122:") ? hash.toLowerCase() : hash;
}

const verdict = (result: AuditResult, reason: string, details: Record<string, unknown> = {}): Verdict => ({
  result,
  details: { reason, ...details },
});

// ------------------------------------------------------------------------------------- sampling

/**
 * Stage 1–2 audit everything (`NP_AUDIT_SAMPLE_RATE=1`). Below 1, an execution is audited when the
 * draw selects it or its value is at least `auditAlwaysUsdMicros` — or unknown (conservative). The
 * value comes from rails' price snapshot and asset decimals: it only decides sampling, never a verdict.
 */
export async function sampled(s: Sentinel, x: Execution): Promise<boolean> {
  if (s.auditSampleRate >= 1 || s.random() < s.auditSampleRate) return true;
  const amount = x.settled_amount ?? x.settlement.expected;
  const asset = await s.rails.asset(x.settlement.asset_id, x.livemode).catch(() => null);
  const price = x.price_snapshot?.primary_usd ?? asset?.price_usd ?? null;
  if (!asset || price === null) return true;
  const micros = usdMicros(BigInt(amount), asset.decimals, price);
  return micros === null || micros >= s.auditAlwaysUsdMicros;
}

/** `amount / 10^decimals × price` in USD micros (floor); null for an unparseable price. */
export function usdMicros(amount: bigint, decimals: number, price: string): bigint | null {
  const m = /^(\d+)(?:\.(\d+))?$/.exec(price);
  if (!m) return null;
  const frac = m[2] ?? "";
  const priceScaled = BigInt(`${m[1]}${frac}`); // price × 10^frac.length
  return (amount * priceScaled * 1_000_000n) / (10n ** BigInt(decimals) * 10n ** BigInt(frac.length));
}

// ------------------------------------------------------------------------------------- checks

async function destinationCheck(s: Sentinel, x: Execution): Promise<Verdict> {
  const { side, view } = destinationSide(x);
  let rows: Parameters<typeof destinationVerdict>[1];
  try {
    rows = await s.registry
      .selectFrom("sentinel_destination_registry")
      .select(["id", "type", "chain", "address_norm", "status", "active_at", "disabled_at"])
      .where("account_id", "=", toUuid(x.account_id, "acct"))
      .where("livemode", "=", x.livemode)
      .where("asset_id", "=", view.settlement.asset_id)
      .execute();
  } catch (e) {
    throw new AuditRetry(`registry unreachable: ${e instanceof Error ? e.message : String(e)}`);
  }
  const v = destinationVerdict(view, rows);
  return verdict(v.result, side === "refund_source" ? `refund source: ${v.reason}` : v.reason, {
    side,
    [side === "refund_source" ? "source" : "recipient"]: view.settlement.recipient,
    asset_id: view.settlement.asset_id,
  });
}

async function settlementCheck(s: Sentinel, x: Execution): Promise<Verdict> {
  const failures = consistencyFailures(x);
  if (failures.length) return verdict("mismatch", failures.join("; "));
  const e = x.evidence as NonNullable<Execution["evidence"]>;
  const recipient = normalRecipient(x) as string;
  const chain = settlementChain(x);
  const base = { tx_hash: e.tx_hash, chain, tier: e.tier, source: e.source };
  if (!x.livemode) return sandboxRead(s, x, recipient, base);
  if (e.tier === "B") return providerCheck(s, x, recipient, { ...base, why: "rails accepted Tier B evidence" });
  const own = attestedChain(chain)?.read;
  if (own === "solana_finalized") return solanaRead(s, x, recipient, base);
  if (own === "bitcoin_confirmations") return bitcoinRead(s, x, recipient, base);
  if (chain === NEAR) return nearRead(s, x, recipient, base);
  if (chain.startsWith("eip155:")) {
    const reader = s.evm.get(chain);
    const shape = assetShape(x.settlement.asset_id);
    if (reader && (shape.kind === "erc20" || shape.kind === "native")) return evmRead(s, x, recipient, base);
    return providerCheck(s, x, recipient, {
      ...base,
      why: reader ? "asset contract not derivable from its id" : "no sentinel RPC for this chain",
    });
  }
  return providerCheck(s, x, recipient, { ...base, why: "no sentinel chain reader for this chain family" });
}

function chainRead(
  x: Execution,
  recipient: string,
  via: Via,
  transfers: readonly Observed[],
  details: Record<string, unknown>,
): Verdict {
  const e = x.evidence as NonNullable<Execution["evidence"]>;
  const observed = received(transfers, via, recipient, x.settlement.asset_id);
  return {
    result: "pass",
    details: { ...details, observed: observed.toString() },
    read: { chain: e.chain, hash: e.tx_hash, recipient, assetId: x.settlement.asset_id, observed },
  };
}

async function sandboxRead(
  s: Sentinel,
  x: Execution,
  recipient: string,
  base: Record<string, unknown>,
): Promise<Verdict> {
  if (!s.test) return verdict("unverifiable", "sandbox not configured", base);
  const e = x.evidence as NonNullable<Execution["evidence"]>;
  let tx: Awaited<ReturnType<NonNullable<Sentinel["test"]>["tx"]>>;
  try {
    tx = await s.test.tx(e.chain, e.tx_hash);
  } catch (err) {
    throw new AuditRetry(`sandbox unreachable: ${err instanceof Error ? err.message : String(err)}`);
  }
  if (!tx) throw new AuditRetry("simulated transaction not found");
  const sim = tx;
  // Stage 4 (§16, sandbox §10): a landed-but-failed Solana tx moved nothing; Bitcoin needs its tier
  if (sim.failed === true) return verdict("mismatch", "simulated settlement transaction failed", base);
  if (settlementChain(x) === BITCOIN_MAINNET) {
    const required = await bitcoinTier(s, x);
    const confirmations = typeof sim.confirmations === "number" ? sim.confirmations : 0;
    if (confirmations < required)
      throw new AuditRetry(`simulated Bitcoin transaction has ${confirmations}/${required} confirmations`);
  } else if (!tx.finalized) throw new AuditRetry("simulated transaction not final");
  // Intents accounts and NEAR accounts compare lower-case; other chains in their normal form (EVM
  // lower-case, bech32 lower-case, Solana base58 exactly as written)
  const lower = x.settlement.recipient_type === "intents" || x.settlement.chain === NEAR;
  const transfers: Observed[] = tx.transfers.map((t) => ({
    via: "sim",
    to: lower ? t.to.toLowerCase() : safeNormal(x.settlement.chain, t.to),
    assetId: t.token,
    amount: /^\d+$/.test(t.amount) ? BigInt(t.amount) : 0n,
  }));
  return chainRead(x, recipient, "sim", transfers, { ...base, simulated: true });
}

function safeNormal(chain: string, address: string): string {
  try {
    return normalizeAddress(chain, address);
  } catch {
    return address;
  }
}

async function nearRead(s: Sentinel, x: Execution, recipient: string, base: Record<string, unknown>): Promise<Verdict> {
  if (!s.near) return providerCheck(s, x, recipient, { ...base, why: "no sentinel NEAR RPC" });
  const e = x.evidence as NonNullable<Execution["evidence"]>;
  let tx: Awaited<ReturnType<NonNullable<Sentinel["near"]>["tx"]>>;
  try {
    tx = await s.near.tx(e.tx_hash);
  } catch (err) {
    if (err instanceof ChainUnavailable) throw new AuditRetry(`NEAR RPC: ${err.message}`);
    throw err;
  }
  if (!tx) throw new AuditRetry("NEAR transaction not found");
  if (!tx.final) throw new AuditRetry("NEAR transaction not final");
  const via: Via = x.settlement.recipient_type === "intents" ? "intents" : "ft";
  return chainRead(x, recipient, via, nearTransfers(tx.receipts, s.intentsContract), base);
}

async function evmRead(s: Sentinel, x: Execution, recipient: string, base: Record<string, unknown>): Promise<Verdict> {
  const e = x.evidence as NonNullable<Execution["evidence"]>;
  const shape = assetShape(x.settlement.asset_id);
  const reader = s.evm.get(x.settlement.chain);
  if (!reader) throw new Error("unreachable: evmRead without a reader");
  let tx: Awaited<ReturnType<typeof reader.transfers>>;
  try {
    tx = await reader.transfers(e.tx_hash);
  } catch (err) {
    if (err instanceof ChainUnavailable) throw new AuditRetry(`EVM RPC: ${err.message}`);
    throw err;
  }
  if (!tx) throw new AuditRetry("EVM transaction not found");
  if (!tx.final) throw new AuditRetry("EVM transaction not finalized");
  if (!tx.ok) return verdict("mismatch", "settlement transaction reverted", base);
  const transfers: Observed[] =
    shape.kind === "erc20"
      ? tx.erc20
          .filter((t) => t.contract === shape.contract)
          .map((t) => ({ via: "evm", to: t.to, assetId: x.settlement.asset_id, amount: t.amount }))
      : tx.native.to
        ? [{ via: "evm", to: tx.native.to, assetId: x.settlement.asset_id, amount: tx.native.amount }]
        : [];
  return chainRead(x, recipient, "evm", transfers, {
    ...base,
    token: shape.kind === "erc20" ? shape.contract : "native",
  });
}

/** An attested Stage 4 chain without a sentinel reader: unverifiable, never Tier B (§16, fail closed). */
function coverageMissing(s: Sentinel, x: Execution, chain: string, base: Record<string, unknown>): Verdict {
  s.metrics.coverageMissing(chain);
  s.log.error({ execution: x.id, chain }, "ALERT audit_coverage_missing: no sentinel reader for this chain");
  return verdict("unverifiable", `no sentinel reader configured for ${chain} (audit_coverage_missing)`, base);
}

async function solanaRead(
  s: Sentinel,
  x: Execution,
  recipient: string,
  base: Record<string, unknown>,
): Promise<Verdict> {
  const e = x.evidence as NonNullable<Execution["evidence"]>;
  if (!s.solana) return coverageMissing(s, x, e.chain, base);
  const shape = assetShape(x.settlement.asset_id);
  let asset: SolanaAsset;
  if (shape.kind === "native" && shape.chain === e.chain) asset = { kind: "native" };
  else if (shape.kind === "spl" && shape.chain === e.chain) asset = { kind: "spl", hash20: shape.hash20 };
  else return verdict("unverifiable", "the asset's Solana token is not derivable from its id", base);
  let result: unknown;
  try {
    result = await s.solana.transaction(e.tx_hash);
  } catch (err) {
    if (err instanceof ChainUnavailable) throw new AuditRetry(`Solana RPC: ${err.message}`);
    throw err;
  }
  if (result === null) throw new AuditRetry("Solana transaction not found or not finalized");
  const read = solanaReceived(result, recipient, asset);
  if (!read) throw new AuditRetry("Solana RPC answer is malformed");
  if (read.failed) return verdict("mismatch", "settlement transaction failed (meta.err)", base);
  return {
    result: "pass",
    details: {
      ...base,
      token: asset.kind === "spl" ? (read.mint ?? `hash20:${asset.hash20}`) : "native",
      observed: read.amount.toString(),
      chain_read: { slot: read.slot, amount: read.amount.toString() },
    },
    read: { chain: e.chain, hash: e.tx_hash, recipient, assetId: x.settlement.asset_id, observed: read.amount },
  };
}

/**
 * Confirmations a Bitcoin settlement needs (§16): the tier for its USD value, priced with the decimals and
 * USD price of sentinel's own token registry for the mode; no registry, no price or an unparseable value →
 * the strictest (last) tier.
 */
async function bitcoinTier(s: Sentinel, x: Execution): Promise<number> {
  const strictest = (BITCOIN_CONFIRMATION_TIERS[BITCOIN_CONFIRMATION_TIERS.length - 1] as { confirmations: number })
    .confirmations;
  const registry = x.livemode ? s.liveTokens : s.testTokens;
  const display = registry ? await registry.asset(x.settlement.asset_id).catch(() => null) : null;
  if (!display?.priceUsd || x.settled_amount === null || !/^\d+$/.test(x.settled_amount)) return strictest;
  const micros = usdMicros(BigInt(x.settled_amount), display.decimals, display.priceUsd);
  return micros === null ? strictest : requiredConfirmations(BITCOIN_CONFIRMATION_TIERS, micros);
}

async function bitcoinRead(
  s: Sentinel,
  x: Execution,
  recipient: string,
  base: Record<string, unknown>,
): Promise<Verdict> {
  const e = x.evidence as NonNullable<Execution["evidence"]>;
  if (!s.bitcoin) return coverageMissing(s, x, e.chain, base);
  const shape = assetShape(x.settlement.asset_id);
  if (!(shape.kind === "native" && shape.chain === e.chain))
    return verdict("unverifiable", "the asset is not the chain's native coin", base);
  const txid = e.tx_hash.toLowerCase();
  let got: Awaited<ReturnType<NonNullable<Sentinel["bitcoin"]>["tx"]>>;
  try {
    got = await s.bitcoin.tx(txid);
  } catch (err) {
    if (err instanceof ChainUnavailable) throw new AuditRetry(`Esplora: ${err.message}`);
    throw err;
  }
  if (!got) throw new AuditRetry("Bitcoin transaction not found");
  const read = bitcoinReceived(got.tx, got.tipHeight, recipient, txid);
  if (!read) throw new AuditRetry("Esplora answer is malformed");
  const required = await bitcoinTier(s, x);
  if (read.confirmations < required)
    throw new AuditRetry(`Bitcoin transaction has ${read.confirmations}/${required} confirmations`);
  return {
    result: "pass",
    details: {
      ...base,
      token: "native",
      observed: read.amount.toString(),
      chain_read: {
        block_height: read.blockHeight,
        amount: read.amount.toString(),
        confirmations: read.confirmations,
        required_confirmations: required,
      },
    },
    read: { chain: e.chain, hash: txid, recipient, assetId: x.settlement.asset_id, observed: read.amount },
  };
}

/** Tier B: the provider's signed status, read with sentinel's own credentials. */
async function providerCheck(
  s: Sentinel,
  x: Execution,
  recipient: string,
  base: Record<string, unknown>,
): Promise<Verdict> {
  const d = x.deposit;
  if (x.provider !== "oneclick" || !d)
    return verdict("unverifiable", "no independent read for this settlement", { ...base, provider: x.provider });
  if (!s.live) return verdict("unverifiable", "1Click not configured", base);
  const st = await s.live.status(d.address, d.memo);
  if (!st.ok) {
    if (st.kind === "not_found") return verdict("mismatch", "1Click does not know the deposit address", base);
    throw new AuditRetry(`1Click status: ${st.detail}`);
  }
  const q = st.status.quoteResponse;
  const problems: string[] = [];
  if (!s.live.verifySignature(q)) problems.push("provider signature does not verify");
  if (q.quoteRequest.referral !== s.referral) problems.push("referral is not NearPay's");
  if (q.quote.depositAddress !== d.address) problems.push("deposit address differs");
  if (q.quoteRequest.destinationAsset !== x.settlement.asset_id) problems.push("destination asset differs");
  const quoted =
    x.settlement.recipient_type === "intents"
      ? q.quoteRequest.recipient.toLowerCase()
      : safeNormal(x.settlement.chain, q.quoteRequest.recipient);
  if (quoted !== recipient) problems.push("recipient differs");
  if (st.status.status !== "SUCCESS") problems.push(`provider status is ${st.status.status}`);
  const out = st.status.swapDetails.amountOut;
  const settled = BigInt(x.settled_amount as string);
  if (!out || !/^\d+$/.test(out)) problems.push("provider reports no amountOut");
  else if (BigInt(out) < settled) problems.push(`provider amountOut ${out} < settled ${settled}`);
  const e = x.evidence as NonNullable<Execution["evidence"]>;
  const hashes = st.status.swapDetails.destinationChainTxHashes.map((h) => txKey(e.chain, h.hash));
  if (!hashes.includes(txKey(e.chain, e.tx_hash))) problems.push("evidence transaction is not one of the provider's");
  const details = { ...base, check: "provider_status", provider_status: st.status.status, amount_out: out ?? null };
  if (problems.length) return verdict("mismatch", problems.join("; "), details);
  return verdict("pass", "provider's signed status shows the settlement", details);
}

// ------------------------------------------------------------------------------------- recording

async function existing(s: Sentinel, executionId: string): Promise<Set<CheckKind>> {
  const rows = await s.db
    .selectFrom("audit_findings")
    .select("check_kind")
    .where("execution_id", "=", executionId)
    .execute();
  return new Set(rows.map((r) => r.check_kind));
}

/** Records one finding (once per execution and check) and emits it when it is not a pass. */
async function record(s: Sentinel, x: Execution, kind: CheckKind, v: Verdict): Promise<AuditResult | null> {
  return s.db.transaction().execute(async (tx) => {
    let result = v.result;
    let details = v.details;
    const read = v.read;
    if (read && result === "pass") {
      // serialise audits of one transaction, then attribute it (double-use, §7)
      const hash = txKey(read.chain, read.hash);
      await sql`select pg_advisory_xact_lock(hashtextextended(${`${read.chain}|${hash}`}, 0))`.execute(tx);
      const others = await sql<{ total: string }>`
        select coalesce(sum(amount), 0)::text as total from audit_findings
        where tx_chain = ${read.chain} and tx_hash = ${hash} and recipient = ${read.recipient}
          and asset_id = ${read.assetId} and result = 'pass' and execution_id <> ${x.id}`.execute(tx);
      const a = attribute(read.observed, BigInt(x.settled_amount as string), BigInt(others.rows[0]?.total ?? "0"));
      result = a.result;
      details = { ...details, reason: a.reason, attributed_elsewhere: others.rows[0]?.total ?? "0" };
    }
    const id = uuidv7();
    const inserted = await tx
      .insertInto("audit_findings")
      .values({
        id,
        execution_id: x.id,
        account_id: toUuid(x.account_id, "acct"),
        livemode: x.livemode,
        check_kind: kind,
        result,
        details: JSON.stringify(details),
        ...(read && result === "pass"
          ? {
              tx_chain: read.chain,
              tx_hash: txKey(read.chain, read.hash),
              recipient: read.recipient,
              asset_id: read.assetId,
              amount: x.settled_amount as string,
            }
          : {}),
      })
      .onConflict((oc) => oc.columns(["execution_id", "check_kind"]).doNothing())
      .returning("id")
      .executeTakeFirst();
    if (!inserted) return null;
    if (result !== "pass") {
      await emit(tx, {
        subject: "evt.sentinel.audit_finding.created",
        aggregate: { type: "audit_finding", id: fromUuid("fnd", id), version: 1 },
        accountId: toUuid(x.account_id, "acct"),
        livemode: x.livemode,
        data: {
          object: {
            id: fromUuid("fnd", id),
            execution_id: x.id,
            account_id: x.account_id,
            livemode: x.livemode,
            check_kind: kind,
            result,
            details,
          },
        },
      });
    }
    return result;
  });
}

function report(s: Sentinel, x: Execution, kind: CheckKind, result: AuditResult | null, v: Verdict): void {
  if (result === null) return;
  s.metrics.finding(result);
  const ctx = { execution: x.id, check: kind, livemode: x.livemode, details: v.details };
  if (result === "mismatch") s.log.error(ctx, "ALERT audit mismatch: settlement not confirmed independently");
  else if (result === "unverifiable") s.log.warn(ctx, "audit could not verify a settlement");
}

/**
 * Audits one settled execution. `attempt` is the job attempt (1-based); a transient failure on the
 * last attempt records `unverifiable` instead of retrying. Checks already recorded are skipped, so a
 * retry only repeats what is still open.
 */
export async function auditExecution(s: Sentinel, x: Execution, attempt: number): Promise<void> {
  const done = await existing(s, x.id);
  const checks: [CheckKind, (s: Sentinel, x: Execution) => Promise<Verdict>][] = [
    ["destination", destinationCheck],
    ["settlement", settlementCheck],
  ];
  let retry: AuditRetry | null = null;
  for (const [kind, check] of checks) {
    if (done.has(kind)) continue;
    let v: Verdict;
    try {
      v = await check(s, x);
    } catch (e) {
      if (!(e instanceof AuditRetry)) throw e;
      if (attempt < AUDIT_MAX_ATTEMPTS) {
        retry ??= e;
        continue;
      }
      v = verdict("unverifiable", `${e.message} after ${attempt} attempts`);
    }
    report(s, x, kind, await record(s, x, kind, v), v);
  }
  if (retry) throw retry;
}
