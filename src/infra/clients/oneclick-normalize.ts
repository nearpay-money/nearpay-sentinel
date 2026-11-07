/**
 * What live 1Click responses actually look like, versus its OpenAPI (seen on mainnet, 2026-11-07):
 * - optional fields that have no value are sent as `null` rather than omitted (`swapDetails.amountOut`,
 *   `quoteRequest.virtualChainRecipient`, …). The OpenAPI marks none of them nullable;
 * - `GET /v0/status` nests the quote response without its `correlationId` (the trace id is only at the top level);
 * - `appFees[]` items carry an extra `limitOrderId: null`.
 *
 * Responses are normalised before they are validated against the spec's transcription of the OpenAPI: `null`
 * properties are dropped (the same as absent: the SDK's signed fields treat both as unset), and a missing nested
 * `quoteResponse.correlationId` takes the top-level one. Nothing that 1Click signs is changed, so quote
 * signatures verify exactly as before.
 */
export function normalizeOneClick(body: unknown): unknown {
  const out = dropNulls(body);
  if (isObject(out) && isObject(out.quoteResponse) && out.quoteResponse.correlationId === undefined) {
    if (typeof out.correlationId === "string") out.quoteResponse.correlationId = out.correlationId;
  }
  return out;
}

function isObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

function dropNulls(v: unknown): unknown {
  if (Array.isArray(v)) return v.map(dropNulls);
  if (!isObject(v)) return v;
  const o: Record<string, unknown> = {};
  for (const [k, x] of Object.entries(v)) if (x !== null) o[k] = dropNulls(x);
  return o;
}

/**
 * 1Click partner auth: a JWT (three base64url parts) goes in `Authorization: Bearer` (the OpenAPI's JWT-auth
 * scheme); any other key in `X-API-Key`.
 */
export function oneClickAuthHeaders(apiKey: string | undefined): Record<string, string> {
  if (!apiKey) return {};
  return /^[\w-]+\.[\w-]+\.[\w-]+$/.test(apiKey) ? { authorization: `Bearer ${apiKey}` } : { "x-api-key": apiKey };
}
