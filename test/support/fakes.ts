/**
 * Test doubles for systems that cannot run locally: a 1Click-compatible status server (quotes signed
 * with a test manager key using the SDK's quote hash, so the SDK verifies them exactly like 1Click's)
 * and a NEAR RPC answering `EXPERIMENTAL_tx_status` from recorded or synthetic responses. The sandbox
 * (test mode) and EVM chains (Anvil) run for real in containers instead.
 */
import { generateKeyPairSync, randomBytes, sign } from "node:crypto";
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import type { AddressInfo } from "node:net";
import { quoteHash } from "@defuse-protocol/one-click-sdk-typescript";
import type { OneClickQuoteResponse } from "@nearpay-internal/spec";
import bs58 from "bs58";
import { fixture } from "./keys.js";

export interface FakeServer {
  readonly url: string;
  readonly requests: {
    method: string;
    path: string;
    query: URLSearchParams;
    headers: IncomingMessage["headers"];
    body: unknown;
  }[];
  stop(): Promise<void>;
}

export type Handler = (req: {
  method: string;
  path: string;
  query: URLSearchParams;
  body: unknown;
  headers: IncomingMessage["headers"];
}) => { status: number; body: unknown } | Promise<{ status: number; body: unknown }>;

export async function fakeServer(handler: Handler): Promise<FakeServer> {
  const requests: FakeServer["requests"] = [];
  const server = createServer(async (req: IncomingMessage, res: ServerResponse) => {
    const chunks: Buffer[] = [];
    for await (const c of req) chunks.push(c as Buffer);
    const text = Buffer.concat(chunks).toString("utf8");
    let body: unknown = text;
    try {
      body = text ? JSON.parse(text) : undefined;
    } catch {}
    const u = new URL(req.url ?? "/", "http://x");
    const r = { method: req.method ?? "GET", path: u.pathname, query: u.searchParams, headers: req.headers, body };
    requests.push(r);
    try {
      const out = await handler(r);
      res.writeHead(out.status, { "content-type": "application/json" });
      res.end(out.body === undefined ? "" : JSON.stringify(out.body));
    } catch (e) {
      res.writeHead(500, { "content-type": "application/json" });
      res.end(JSON.stringify({ message: String(e) }));
    }
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  const { port } = server.address() as AddressInfo;
  return { url: `http://127.0.0.1:${port}`, requests, stop: () => new Promise<void>((r) => server.close(() => r())) };
}

// ---------------------------------------------------------------------------------------------
// 1Click
// ---------------------------------------------------------------------------------------------

export const PROVIDER_FEE_ACCOUNT = "5880ad2b362620fadf759cbceb1cd5737ce8c6ed7fb8e9942881e6731f9247dd";

export interface FakeStatus {
  status: string;
  swapDetails?: Record<string, unknown>;
}

export interface FakeOneClick extends FakeServer {
  /** `ed25519:<base58>` key the fake signs with. */
  readonly managerPublicKey: string;
  /**
   * Registers a non-dry quote for a fresh deposit address, built from the recorded quote with `over`
   * applied to its request and quote; `afterSign` mutates it after signing (signature-failure tests).
   */
  quote(o: {
    request?: Partial<OneClickQuoteResponse["quoteRequest"]>;
    quote?: Partial<OneClickQuoteResponse["quote"]>;
    afterSign?: (q: OneClickQuoteResponse) => void;
    status?: FakeStatus;
  }): OneClickQuoteResponse;
  /** Status per deposit address (absent → 404). */
  readonly statuses: Map<string, FakeStatus>;
  /** Next status calls fail with this HTTP status (unavailability tests). */
  failNext: number;
}

export async function fakeOneClick(): Promise<FakeOneClick> {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const raw = Buffer.from(publicKey.export({ format: "jwk" }).x as string, "base64url");
  const statuses = new Map<string, FakeStatus>();
  const quotes = new Map<string, OneClickQuoteResponse>();
  // the handler reads the control from the returned object itself (set by the tests)
  let ctl: { failNext: number } = { failNext: 0 };
  const server = await fakeServer((req) => {
    if (req.path !== "/v0/status") return { status: 404, body: { message: "not found" } };
    if (ctl.failNext > 0) {
      ctl.failNext--;
      return { status: 503, body: { message: "unavailable" } };
    }
    const address = req.query.get("depositAddress") ?? "";
    const s = statuses.get(address);
    const q = quotes.get(address);
    if (!s || !q) return { status: 404, body: fixture("oneclick/status-404.json") };
    return {
      status: 200,
      body: {
        correlationId: "c",
        quoteResponse: q,
        status: s.status,
        updatedAt: new Date().toISOString(),
        swapDetails: {
          intentHashes: [],
          nearTxHashes: [],
          originChainTxHashes: [],
          destinationChainTxHashes: [],
          ...s.swapDetails,
        },
      },
    };
  });
  const fake: FakeOneClick = Object.assign(server, {
    managerPublicKey: `ed25519:${bs58.encode(raw)}`,
    statuses,
    failNext: 0,
    quote(o: Parameters<FakeOneClick["quote"]>[0]) {
      const base = fixture<OneClickQuoteResponse>("oneclick/dry-quote.json");
      const address = `0x${randomBytes(20).toString("hex")}`;
      const deadline = new Date(Date.now() + 30 * 60_000);
      deadline.setUTCMilliseconds(0);
      const q: OneClickQuoteResponse = {
        ...base,
        correlationId: randomBytes(8).toString("hex"),
        timestamp: new Date().toISOString(),
        quoteRequest: { ...base.quoteRequest, dry: false, deadline: deadline.toISOString(), ...o.request },
        quote: { ...base.quote, depositAddress: address, deadline: deadline.toISOString(), ...o.quote },
        signature: "",
      };
      const hash = quoteHash({ ...q, signature: "" } as never);
      q.signature = `ed25519:${bs58.encode(sign(null, Buffer.from(hash, "utf8"), privateKey))}`;
      o.afterSign?.(q);
      quotes.set(q.quote.depositAddress as string, q);
      statuses.set(q.quote.depositAddress as string, o.status ?? { status: "PENDING_DEPOSIT" });
      return q;
    },
  }) as FakeOneClick;
  ctl = fake;
  return fake;
}

// ---------------------------------------------------------------------------------------------
// NEAR
// ---------------------------------------------------------------------------------------------

/** NEAR JSON-RPC answering EXPERIMENTAL_tx_status: hash → response body (absent → UNKNOWN_TRANSACTION). */
export async function fakeNearRpc(txs: Map<string, unknown>): Promise<FakeServer> {
  return fakeServer((req) => {
    const b = req.body as { method: string; params: { tx_hash: string } };
    if (b.method !== "EXPERIMENTAL_tx_status")
      return { status: 200, body: { jsonrpc: "2.0", id: 1, error: { message: "unsupported" } } };
    return { status: 200, body: txs.get(b.params?.tx_hash) ?? fixture("near/tx-unknown.json") };
  });
}

/** A FINAL `EXPERIMENTAL_tx_status` result with one successful receipt carrying `logs`. */
export function nearTx(executor: string, logs: string[], final = true): unknown {
  return {
    jsonrpc: "2.0",
    id: "sentinel",
    result: {
      final_execution_status: final ? "FINAL" : "EXECUTED_OPTIMISTIC",
      receipts_outcome: [{ outcome: { executor_id: executor, logs, status: { SuccessValue: "" } } }],
    },
  };
}

export const mtTransfer = (to: string, token: string, amount: string) =>
  `EVENT_JSON:${JSON.stringify({
    standard: "nep245",
    version: "1.0.0",
    event: "mt_transfer",
    data: [{ old_owner_id: "solver.near", new_owner_id: to, token_ids: [token], amounts: [amount] }],
  })}`;
