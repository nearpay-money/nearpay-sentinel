import { defineConfig } from "vitest/config";

// Coverage gate (foundations §16): ≥ 90% branch coverage on the pure rules — the co-signing checks,
// asset ids, the audit rules and the signing/ticket code (sentinel has no src/domain).
export default defineConfig({
  test: {
    coverage: {
      provider: "v8",
      include: ["src/address-integrity/**/*.ts", "src/independent-reconciliation/audit.ts", "src/co-signer/crypto.ts"],
      reporter: ["text", "json-summary"],
      thresholds: { branches: 90 },
    },
  },
});
