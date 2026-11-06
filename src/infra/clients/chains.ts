/**
 * Sentinel's own chain readers (lld/sentinel.md §9: own provider accounts, 3 s), deliberately not
 * shared with rails: an EVM JSON-RPC pool (receipts, transactions, the `finalized` head) and a NEAR RPC
 * pool (`EXPERIMENTAL_tx_status`, `wait_until: NONE`).
 */
const TRANSFER = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef";

export class ChainUnavailable extends Error {
  override readonly name = "ChainUnavailable";
}

async function rpcCall(
  f: typeof fetch,
  urls: readonly string[],
  method: string,
  params: unknown,
  timeoutMs: number,
): Promise<unknown> {
  let last = "no RPC configured";
  for (const url of urls) {
    try {
      const res = await f(url, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ jsonrpc: "2.0", id: "sentinel", method, params }),
        signal: AbortSignal.timeout(timeoutMs),
      });
      if (!res.ok) {
        last = `${url} responded ${res.status}`;
        continue;
      }
      return await res.json();
    } catch (e) {
      last = `${url}: ${e instanceof Error ? e.message : String(e)}`;
    }
  }
  throw new ChainUnavailable(last);
}

export interface EvmReader {
  /** Transfers in a final transaction: ERC-20 logs (by contract) and the native value; null when not found. */
  transfers(hash: string): Promise<
    | { final: false }
    | {
        final: true;
        ok: boolean;
        erc20: { contract: string; to: string; amount: bigint }[];
        native: { to: string | null; amount: bigint };
      }
    | null
  >;
}

export function evmReader(o: { urls: readonly string[]; fetch?: typeof fetch; timeoutMs?: number }): EvmReader {
  const f = o.fetch ?? fetch;
  const t = o.timeoutMs ?? 3_000;
  const call = async (method: string, params: unknown[]) => {
    const body = (await rpcCall(f, o.urls, method, params, t)) as { result?: unknown; error?: { message?: string } };
    if (body.error) throw new ChainUnavailable(`${method}: ${body.error.message ?? "rpc error"}`);
    return body.result ?? null;
  };
  return {
    async transfers(hash) {
      const receipt = (await call("eth_getTransactionReceipt", [hash])) as {
        status: string;
        blockNumber: string;
        logs: { address: string; topics: string[]; data: string }[];
      } | null;
      if (!receipt) return null;
      const head = (await call("eth_getBlockByNumber", ["finalized", false])) as { number?: string } | null;
      if (!head?.number) throw new ChainUnavailable("no finalized block");
      if (BigInt(receipt.blockNumber) > BigInt(head.number)) return { final: false };
      const tx = (await call("eth_getTransactionByHash", [hash])) as { to: string | null; value: string } | null;
      const erc20 = receipt.logs
        .filter((l) => l.topics[0]?.toLowerCase() === TRANSFER && l.topics.length === 3)
        .flatMap((l) => {
          try {
            return [
              {
                contract: l.address.toLowerCase(),
                to: `0x${(l.topics[2] as string).slice(-40).toLowerCase()}`,
                amount: BigInt(l.data === "0x" ? "0x0" : l.data),
              },
            ];
          } catch {
            return [];
          }
        });
      return {
        final: true,
        ok: receipt.status === "0x1",
        erc20,
        native: { to: tx?.to?.toLowerCase() ?? null, amount: tx ? BigInt(tx.value) : 0n },
      };
    },
  };
}

export interface NearReader {
  tx(
    hash: string,
  ): Promise<
    { final: false } | { final: true; receipts: { executor: string; logs: string[]; success: boolean }[] } | null
  >;
}

export function nearReader(o: {
  urls: readonly string[];
  senderHint: string;
  fetch?: typeof fetch;
  timeoutMs?: number;
}): NearReader {
  const f = o.fetch ?? fetch;
  return {
    async tx(hash) {
      const body = (await rpcCall(
        f,
        o.urls,
        "EXPERIMENTAL_tx_status",
        { tx_hash: hash, sender_account_id: o.senderHint, wait_until: "NONE" },
        o.timeoutMs ?? 3_000,
      )) as {
        result?: {
          final_execution_status: string;
          receipts_outcome: { outcome: { executor_id: string; logs: string[]; status: Record<string, unknown> } }[];
        };
        error?: { cause?: { name?: string }; message?: string };
      };
      if (body.error) {
        if (body.error.cause?.name === "UNKNOWN_TRANSACTION") return null;
        throw new ChainUnavailable(body.error.cause?.name ?? body.error.message ?? "rpc error");
      }
      const r = body.result;
      if (!r) throw new ChainUnavailable("empty result");
      if (r.final_execution_status !== "FINAL") return { final: false };
      return {
        final: true,
        receipts: r.receipts_outcome.map((x) => ({
          executor: x.outcome.executor_id,
          logs: x.outcome.logs,
          success: "SuccessValue" in x.outcome.status || "SuccessReceiptId" in x.outcome.status,
        })),
      };
    },
  };
}
