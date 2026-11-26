import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";

const baseUrl = process.env.TEST_BASE_URL ?? "http://127.0.0.1:8787";

const status = await fetch(`${baseUrl}/`);
assert.equal(status.status, 200);
const statusBody = await status.json();
assert.equal(statusBody.protocol, "x402");
assert.deepEqual(statusBody.endpoints, [
  "/v1/sanitize",
  "/v1/verify-uk-company",
  "/v1/full-audit",
  "/v1/uk-deep-kyb",
]);

const discovery = await fetch(`${baseUrl}/llms.txt`);
assert.equal(discovery.status, 200, "GET /llms.txt should return 200");
assert.match(discovery.headers.get("content-type") ?? "", /text\/plain/i);
const llms = await discovery.text();
assert.match(llms, /\$0\.005 USDC/);
assert.match(llms, /\$0\.02 USDC/);
assert.match(llms, /\$0\.022 USDC/);
assert.match(llms, /\$0\.15 USDC/);
assert.match(llms, /Authorization: Bearer/);

const mcpResponse = await fetch(`${baseUrl}/.well-known/mcp.json`);
assert.equal(mcpResponse.status, 200);
const mcp = await mcpResponse.json();
assert.equal(mcp.tools.length, 4);
assert.ok(mcp.tools.every((tool) => tool._meta["x402:payment"].httpStatus === 402));
assert.equal(
  mcp.tools.find((tool) => tool.name === "uk_deep_kyb")._meta["x402:payment"].atomicUnits,
  "150000",
);
assert.match(mcp.description, /Bearer/);

const openapiResponse = await fetch(`${baseUrl}/openapi.json`);
assert.equal(openapiResponse.status, 200);
const openapi = await openapiResponse.json();
assert.equal(openapi.openapi, "3.1.0");
assert.equal(openapi.paths["/v1/sanitize"].post["x-x402-payment"].network, "eip155:8453");
assert.equal(openapi.paths["/v1/uk-deep-kyb"].post["x-x402-payment"].network, "eip155:8453");
assert.equal(
  openapi.paths["/v1/uk-deep-kyb"].post.responses["402"].headers["PAYMENT-REQUIRED"].schema.type,
  "string",
);

const unpaid = await fetch(`${baseUrl}/v1/sanitize`, {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({ text: "hello", strip_pii: false }),
});
assert.equal(unpaid.status, 402, "POST /v1/sanitize should require payment");
assert.ok(
  unpaid.headers.get("PAYMENT-REQUIRED"),
  "402 response should include a PAYMENT-REQUIRED x402 header",
);
const payment = JSON.parse(
  Buffer.from(unpaid.headers.get("PAYMENT-REQUIRED"), "base64").toString("utf8"),
);
assert.equal(payment.x402Version, 2);
assert.ok(payment.accepts?.some((item) => item.network === "eip155:8453"));
assert.ok(
  payment.accepts?.some(
    (item) => item.scheme === "exact" && item.amount === "5000" && item.asset,
  ),
  "challenge should require exactly 5000 token atomic units",
);

const deepKyb = await fetch(`${baseUrl}/v1/uk-deep-kyb`, {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({ company_number: "01234567" }),
});
assert.equal(deepKyb.status, 402, "deep KYB should require payment");
const deepKybHeader = deepKyb.headers.get("PAYMENT-REQUIRED");
assert.ok(deepKybHeader, "deep KYB 402 response should include payment requirements");
const deepKybPayment = JSON.parse(
  Buffer.from(deepKybHeader, "base64").toString("utf8"),
);
assert.ok(
  deepKybPayment.accepts?.some(
    (item) =>
      item.scheme === "exact" &&
      item.amount === "150000" &&
      item.asset &&
      item.payTo === "0x74d0ff6d0912231fdd728fc5ddbeeed3bbfec92f",
  ),
  "deep KYB challenge should require 150000 token units sent to the configured wallet",
);

const invalidKey = await fetch(`${baseUrl}/v1/sanitize`, {
  method: "POST",
  headers: {
    Authorization: "Bearer invalid-local-test-key",
    "Content-Type": "application/json",
  },
  body: JSON.stringify({ text: "invalid key", strip_pii: false }),
});
assert.equal(invalidKey.status, 402, "an unknown API key must not bypass payment");

if (process.env.TEST_API_KEY) {
  const keyed = await fetch(`${baseUrl}/v1/sanitize`, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${process.env.TEST_API_KEY}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ text: "keyed request", strip_pii: false }),
  });
  assert.equal(keyed.status, 200, "a valid KV API key should bypass x402");
}

const bridge = spawnSync(
  process.execPath,
  ["mcp-server.mjs"],
  {
    input: [
      JSON.stringify({
        jsonrpc: "2.0",
        id: 1,
        method: "initialize",
        params: { protocolVersion: "2025-03-26" },
      }),
      JSON.stringify({ jsonrpc: "2.0", id: 2, method: "tools/list" }),
      JSON.stringify({
        jsonrpc: "2.0",
        id: 3,
        method: "tools/call",
        params: {
          name: "sanitize_text",
          arguments: { text: "bridge test", strip_pii: false },
        },
      }),
      "",
    ].join("\n"),
    encoding: "utf8",
    env: { ...process.env, AGENTGUARD_API_URL: baseUrl, AGENTGUARD_API_KEY: "" },
  },
);
assert.equal(bridge.status, 0, bridge.stderr);
const bridgeMessages = bridge.stdout
  .trim()
  .split("\n")
  .map((line) => JSON.parse(line));
assert.equal(bridgeMessages[0].result.serverInfo.name, "agentguard-cloudflare-bridge");
assert.equal(bridgeMessages[1].result.tools.length, 4);
const bridgeCall = bridgeMessages.find((message) => message.id === 3);
assert.equal(bridgeCall.result.isError, true);
assert.match(bridgeCall.result.content[0].text, /"http_status":402/);
assert.match(bridgeCall.result.content[0].text, /"payment_required":"/);

console.log("Discovery, x402 pricing, Bearer auth, and MCP bridge tests passed.");
