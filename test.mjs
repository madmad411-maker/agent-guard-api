import assert from "node:assert/strict";

const baseUrl = process.env.TEST_BASE_URL ?? "http://127.0.0.1:8787";

const status = await fetch(`${baseUrl}/`);
assert.equal(status.status, 200);
const statusBody = await status.json();
assert.equal(statusBody.protocol, "x402");
assert.deepEqual(statusBody.endpoints, [
  "/v1/sanitize",
  "/v1/verify-uk-company",
  "/v1/full-audit",
]);

const discovery = await fetch(`${baseUrl}/llms.txt`);
assert.equal(discovery.status, 200, "GET /llms.txt should return 200");
assert.match(discovery.headers.get("content-type") ?? "", /text\/plain/i);
const llms = await discovery.text();
assert.match(llms, /\$0\.005 USDC/);
assert.match(llms, /\$0\.02 USDC/);
assert.match(llms, /\$0\.022 USDC/);

const mcpResponse = await fetch(`${baseUrl}/.well-known/mcp.json`);
assert.equal(mcpResponse.status, 200);
const mcp = await mcpResponse.json();
assert.equal(mcp.tools.length, 3);
assert.ok(mcp.tools.every((tool) => tool._meta["x402:payment"].httpStatus === 402));

const openapiResponse = await fetch(`${baseUrl}/openapi.json`);
assert.equal(openapiResponse.status, 200);
const openapi = await openapiResponse.json();
assert.equal(openapi.openapi, "3.1.0");
assert.equal(openapi.paths["/v1/sanitize"].post["x-x402-payment"].network, "eip155:8453");

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

console.log("Discovery, MCP/OpenAPI manifests, and Base x402 challenge checks passed.");
