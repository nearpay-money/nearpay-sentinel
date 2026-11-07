/**
 * 1Click partner auth: a JWT (three base64url parts) goes in `Authorization: Bearer` (the OpenAPI's JWT-auth
 * scheme); any other key in `X-API-Key`.
 *
 * Live response bodies are no longer normalised here: spec 0.2.0 transcribes the live shape (optional fields
 * nullish, the nested status `quoteResponse.correlationId` optional), so bodies are validated as received.
 */
export function oneClickAuthHeaders(apiKey: string | undefined): Record<string, string> {
  if (!apiKey) return {};
  return /^[\w-]+\.[\w-]+\.[\w-]+$/.test(apiKey) ? { authorization: `Bearer ${apiKey}` } : { "x-api-key": apiKey };
}
