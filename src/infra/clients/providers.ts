/**
 * Provider status lookups with sentinel's own credentials (lld/sentinel.md §9): 1Click `/v0/status`
 * (own API key, 2 s, 1 retry) in live mode, the sandbox (1 s, service token) in test mode. Signatures
 * are verified with the 1Click SDK — the pinned 1Click key live, the sandbox key in test mode.
 */
import { verifyQuoteSignature } from "@defuse-protocol/one-click-sdk-typescript";
import { HttpError, httpClient } from "@nearpay-internal/http";
import { type OneClickQuoteResponse, OneClickStatusResponse, sandboxGetTx } from "@nearpay-internal/spec";
import bs58 from "bs58";

export type StatusLookup =
  | { readonly ok: true; readonly status: OneClickStatusResponse }
  | { readonly ok: false; readonly kind: "not_found" | "unavailable"; readonly detail: string };

export interface StatusProvider {
  status(address: string, memo: string | null): Promise<StatusLookup>;
  verifySignature(q: OneClickQuoteResponse): boolean;
}

/** `ed25519:<base58>` from a base64url raw key (or an `ed25519:` key as is). */
export function managerKey(pub: string): string {
  if (pub.startsWith("ed25519:")) return pub;
  const raw = Buffer.from(pub, "base64url");
  if (raw.length !== 32) throw new RangeError("expected a 32-byte Ed25519 public key");
  return `ed25519:${bs58.encode(raw)}`;
}

function provider(o: {
  target: string;
  baseUrl: string;
  timeoutMs: number;
  attempts: number;
  headers: Record<string, string>;
  serviceToken?: () => Promise<string>;
  key?: string;
  fetch?: typeof fetch;
}): StatusProvider {
  const client = httpClient({
    target: o.target,
    baseUrl: o.baseUrl,
    timeoutMs: o.timeoutMs,
    attempts: o.attempts,
    breaker: false,
    ...(o.serviceToken ? { serviceToken: o.serviceToken } : {}),
    ...(o.fetch ? { fetch: o.fetch } : {}),
  });
  return {
    async status(address, memo) {
      try {
        const res = await client.request({
          method: "GET",
          path: "/v0/status",
          headers: o.headers,
          query: { depositAddress: address, ...(memo ? { depositMemo: memo } : {}) },
        });
        const parsed = OneClickStatusResponse.safeParse(res.body);
        if (!parsed.success) return { ok: false, kind: "unavailable", detail: "malformed status response" };
        return { ok: true, status: parsed.data };
      } catch (e) {
        if (e instanceof HttpError && e.status === 404)
          return { ok: false, kind: "not_found", detail: "unknown deposit address" };
        return { ok: false, kind: "unavailable", detail: e instanceof Error ? e.message : String(e) };
      }
    },
    verifySignature: (q) => {
      try {
        return o.key ? verifyQuoteSignature(q as never, o.key) : verifyQuoteSignature(q as never);
      } catch {
        return false; // a malformed signature or key never verifies
      }
    },
  };
}

export function oneClickStatus(o: {
  baseUrl: string;
  apiKey?: string | undefined;
  fetch?: typeof fetch;
  managerPublicKey?: string;
}) {
  return provider({
    target: "oneclick",
    baseUrl: o.baseUrl,
    timeoutMs: 2_000,
    attempts: 2,
    headers: o.apiKey ? { "x-api-key": o.apiKey } : {},
    ...(o.managerPublicKey ? { key: managerKey(o.managerPublicKey) } : {}),
    ...(o.fetch ? { fetch: o.fetch } : {}),
  });
}

export interface SandboxStatus extends StatusProvider {
  tx(
    chain: string,
    hash: string,
  ): Promise<{ finalized: boolean; transfers: { token: string; to: string; amount: string }[] } | null>;
}

export function sandboxStatus(o: {
  baseUrl: string;
  signingPubkey: string;
  serviceToken: () => Promise<string>;
  fetch?: typeof fetch;
}): SandboxStatus {
  const p = provider({
    target: "sandbox",
    baseUrl: o.baseUrl,
    timeoutMs: 1_000,
    attempts: 1,
    headers: {},
    serviceToken: o.serviceToken,
    key: managerKey(o.signingPubkey),
    ...(o.fetch ? { fetch: o.fetch } : {}),
  });
  const client = httpClient({
    target: "sandbox",
    baseUrl: o.baseUrl,
    timeoutMs: 2_000,
    attempts: 2,
    breaker: false,
    serviceToken: o.serviceToken,
    ...(o.fetch ? { fetch: o.fetch } : {}),
  });
  return {
    ...p,
    async tx(chain, hash) {
      try {
        return await client.call(sandboxGetTx, { params: { chain, hash } });
      } catch (e) {
        if (e instanceof HttpError && e.status === 404) return null;
        throw e;
      }
    },
  };
}
