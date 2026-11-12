/**
 * 1Click partner auth: a JWT (three base64url parts) goes in `Authorization: Bearer` (the OpenAPI's JWT-auth
 * scheme); any other key in `X-API-Key`.
 *
 * Live response bodies are no longer normalised here: spec 0.2.0 transcribes the live shape (optional fields
 * nullish, the nested status `quoteResponse.correlationId` optional), so bodies are validated as received.
 */
const JWT = /^[\w-]+\.[\w-]+\.[\w-]+$/;

export function oneClickAuthHeaders(apiKey: string | undefined): Record<string, string> {
  if (!apiKey) return {};
  return JWT.test(apiKey) ? { authorization: `Bearer ${apiKey}` } : { "x-api-key": apiKey };
}

/**
 * The `exp` claim (unix seconds) of a JWT partner key, read without verifying it (SENTINEL-3: only to warn
 * before 1Click starts refusing the key — `nearpay_sentinel_oneclick_key_expiry_seconds`, alert `OneClickKeyExpiring`
 * at < 7 days). null for a key that is not a JWT, has no numeric `exp`, or does not decode.
 */
export function jwtExpiry(apiKey: string | undefined): number | null {
  if (!apiKey || !JWT.test(apiKey)) return null;
  try {
    const payload = JSON.parse(Buffer.from(apiKey.split(".")[1] as string, "base64url").toString("utf8")) as {
      exp?: unknown;
    };
    return typeof payload.exp === "number" && Number.isFinite(payload.exp) && payload.exp > 0
      ? Math.floor(payload.exp)
      : null;
  } catch {
    return null;
  }
}
