/**
 * Anvil (Foundry) as a real EVM node for the auditor tests. A 49-byte token contract
 * emits `Transfer(msg.sender, to, value)` for calldata `to ‖ value` — exactly the log an ERC-20
 * transfer leaves, which is all the auditor reads. Anvil's `finalized` tag trails the head by 64
 * blocks, so tests mine 64 blocks to finalize.
 */
import { GenericContainer, type StartedTestContainer, Wait } from "testcontainers";

const TRANSFER_TOPIC = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef";

export const ANVIL_IMAGE = "ghcr.io/foundry-rs/foundry:v1.4.4";

// PUSH1 0x20 CALLDATALOAD PUSH1 0 MSTORE PUSH1 0 CALLDATALOAD CALLER PUSH32 <Transfer> PUSH1 0x20 PUSH1 0 LOG3 STOP
const RUNTIME = `602035600052600035337f${TRANSFER_TOPIC.slice(2)}60206000a300`;
// PUSH1 len DUP1 PUSH1 11 PUSH1 0 CODECOPY PUSH1 0 RETURN
const INIT = `60${(RUNTIME.length / 2).toString(16).padStart(2, "0")}80600b6000396000f3`;

export interface Anvil {
  readonly url: string;
  readonly account: string;
  rpc<T = unknown>(method: string, params?: unknown[]): Promise<T>;
  /** Deploys the transfer-emitting token; returns its address. */
  deployToken(): Promise<string>;
  /** Emits Transfer(account → to, value) from `token`; returns the tx hash. */
  transfer(token: string, to: string, value: bigint): Promise<string>;
  /** A native transfer; returns the tx hash. */
  sendNative(to: string, value: bigint): Promise<string>;
  /** Deploys a contract whose every call reverts; returns its address. */
  deployReverter(): Promise<string>;
  /** Calls `to` with `data` and a fixed gas limit (mined even when it reverts); returns the tx hash. */
  call(to: string, data: string): Promise<string>;
  mine(blocks: number): Promise<void>;
  container: StartedTestContainer;
}

export async function startAnvil(): Promise<Anvil> {
  const container = await new GenericContainer(ANVIL_IMAGE)
    .withEntrypoint(["anvil"])
    .withCommand(["--host", "0.0.0.0", "--port", "8545"])
    .withExposedPorts(8545)
    .withWaitStrategy(Wait.forLogMessage(/Listening on/))
    .start();
  const url = `http://${container.getHost()}:${container.getMappedPort(8545)}`;
  let id = 0;
  const rpc = async <T>(method: string, params: unknown[] = []): Promise<T> => {
    const r = await fetch(url, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ jsonrpc: "2.0", id: ++id, method, params }),
    });
    const body = (await r.json()) as { result?: T; error?: { message: string } };
    if (body.error) throw new Error(`${method}: ${body.error.message}`);
    return body.result as T;
  };
  const [account] = await rpc<string[]>("eth_accounts");
  const send = async (tx: Record<string, string>) => {
    const hash = await rpc<string>("eth_sendTransaction", [{ from: account, ...tx }]);
    for (let i = 0; i < 50; i++) {
      const receipt = await rpc<{ status: string; contractAddress: string | null } | null>(
        "eth_getTransactionReceipt",
        [hash],
      );
      if (receipt) return { hash, receipt };
      await new Promise((r) => setTimeout(r, 50));
    }
    throw new Error(`no receipt for ${hash}`);
  };
  const word = (hex: string) => hex.replace(/^0x/, "").padStart(64, "0");
  return {
    url,
    account: account as string,
    rpc,
    async deployToken() {
      const { receipt } = await send({ data: `0x${INIT}${RUNTIME}`, gas: "0x100000" });
      if (!receipt.contractAddress) throw new Error("deploy failed");
      return receipt.contractAddress.toLowerCase();
    },
    async transfer(token, to, value) {
      return (await send({ to: token, data: `0x${word(to)}${word(value.toString(16))}`, gas: "0x30000" })).hash;
    },
    async sendNative(to, value) {
      return (await send({ to, value: `0x${value.toString(16)}` })).hash;
    },
    async deployReverter() {
      // runtime PUSH1 0 PUSH1 0 REVERT; init copies it
      const runtime = "60006000fd";
      const { receipt } = await send({ data: `0x6005600c60003960056000f3${runtime}`, gas: "0x100000" });
      if (!receipt.contractAddress) throw new Error("deploy failed");
      return receipt.contractAddress.toLowerCase();
    },
    async call(to, data) {
      return (await send({ to, data, gas: "0x30000" })).hash;
    },
    async mine(blocks) {
      await rpc("anvil_mine", [`0x${blocks.toString(16)}`]);
    },
    container,
  };
}
