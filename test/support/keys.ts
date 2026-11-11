/** Ed25519 helpers for tests: PKCS#8 PEM from a 32-byte seed (the spec test vectors give seeds). */
import { createPrivateKey, generateKeyPairSync, type KeyObject, sign } from "node:crypto";
import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
import canonicalize from "canonicalize";

const PKCS8_ED25519 = "302e020100300506032b657004220420";

export function pemFromSeed(seedHex: string): string {
  const der = Buffer.from(`${PKCS8_ED25519}${seedHex}`, "hex");
  return createPrivateKey({ key: der, format: "der", type: "pkcs8" })
    .export({ type: "pkcs8", format: "pem" })
    .toString();
}

export function newKeyPair(): { pem: string; privateKey: KeyObject; publicRaw: string } {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  return {
    pem: privateKey.export({ type: "pkcs8", format: "pem" }).toString(),
    privateKey,
    publicRaw: publicKey.export({ format: "jwk" }).x as string,
  };
}

/** A payments-style attestation ticket: `b64u(JCS(payload)).b64u(sig)`. */
export function mintTicket(
  privateKey: KeyObject,
  payload: { attempt_id: string; livemode: boolean; deposit_key: string; exp: number },
): string {
  const bytes = Buffer.from(canonicalize(payload) as string, "utf8");
  return `${bytes.toString("base64url")}.${sign(null, bytes, privateKey).toString("base64url")}`;
}

const require = createRequire(import.meta.url);

/** A spec test vector (`@nearpay-money/spec/test-vectors/<name>.json`). */
export function vector<T = unknown>(name: string): T {
  return JSON.parse(readFileSync(require.resolve(`@nearpay-money/spec/test-vectors/${name}.json`), "utf8")) as T;
}

export const fixture = <T = unknown>(path: string): T =>
  JSON.parse(readFileSync(new URL(`../fixtures/${path}`, import.meta.url), "utf8")) as T;
