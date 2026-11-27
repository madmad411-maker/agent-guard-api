import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";

const baseUrl = process.env.TEST_BASE_URL ?? "http://127.0.0.1:8787";

const status = await fetch(`${baseUrl}/`);
assert.equal(status.status, 200);
assert.match(status.headers.get("content-type") ?? "", /application\/json/i);
const statusBody = await status.json();
assert.equal(statusBody.protocol, "x402");
assert.deepEqual(statusBody.endpoints, [
  "/v1/sanitize",
  "/v1/verify-uk-company",
  "/v1/full-audit",
  "/v1/uk-deep-kyb",
]);

const landing = await fetch(`${baseUrl}/`, {
  headers: { Accept: "text/html,application/xhtml+xml" },
});
assert.equal(landing.status, 200);
assert.match(landing.headers.get("content-type") ?? "", /text\/html/i);
const landingHtml = await landing.text();
assert.match(landingHtml, /AgentGuard — AI Security & UK Company KYB/);
assert.match(landingHtml, /Live status: Operational/);
assert.match(landingHtml, /name="viewport" content="width=device-width, initial-scale=1\.0"/);
assert.match(landingHtml, /Interactive live sandbox/);
assert.match(landingHtml, /value="00445790"/);
assert.match(landingHtml, /\/v1\/verify-uk-company/);
assert.match(landingHtml, /\/v1\/sanitize/);
assert.match(landingHtml, /overflow-x:hidden/);
assert.match(landingHtml, /overflow-x:auto/);
assert.match(landingHtml, /Free Sandbox/);
assert.match(landingHtml, /Pay-As-You-Go/);
assert.match(landingHtml, /£15/);
assert.match(landingHtml, /1,000 API credits/);
assert.match(landingHtml, /£29/);
assert.match(landingHtml, /5,000 requests per month/);
assert.match(landingHtml, /£99/);
assert.match(landingHtml, /25,000 requests per month/);
assert.match(landingHtml, /Agency/);
assert.match(landingHtml, /£199/);
assert.match(landingHtml, /75,000 calls per month/);
assert.match(landingHtml, /Autonomous x402/);
assert.match(landingHtml, /USDC/);
assert.match(landingHtml, /\/bulk-check/);
assert.match(landingHtml, /\/templates/);
assert.match(landingHtml, /\/llms\.txt/);
assert.match(landingHtml, /\/openapi\.json/);
assert.match(landingHtml, /\/\.well-known\/mcp\.json/);
assert.match(landingHtml, /\/sitemap.xml/);

const missingAdminAuth = await fetch(`${baseUrl}/admin/issue-key`, {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({ customer_email: "buyer@example.com", plan: "starter" }),
});
assert.equal(missingAdminAuth.status, 401, "key issuance must reject missing admin auth");

const unauthorizedIssue = await fetch(`${baseUrl}/admin/issue-key`, {
  method: "POST",
  headers: {
    Authorization: "Bearer invalid-admin-test-secret",
    "Content-Type": "application/json",
  },
  body: JSON.stringify({ customer_email: "buyer@example.com", plan: "starter" }),
});
assert.equal(unauthorizedIssue.status, 401, "key issuance must reject invalid admin secrets");

if (process.env.TEST_ADMIN_SECRET) {
  const issuedResponse = await fetch(`${baseUrl}/admin/issue-key`, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${process.env.TEST_ADMIN_SECRET}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      customer_email: "buyer@example.com",
      plan: "starter",
    }),
  });
  assert.equal(issuedResponse.status, 201, "valid admin secret should issue an API key");
  assert.match(issuedResponse.headers.get("cache-control") ?? "", /no-store/i);
  const issued = await issuedResponse.json();
  assert.match(issued.api_key, /^kyb_live_[a-f0-9]{64}$/);
  assert.equal(issued.customer_email, "buyer@example.com");
  assert.equal(issued.plan, "starter");
  assert.ok(Number.isFinite(Date.parse(issued.created_at)));

  const issuedKeyCall = await fetch(`${baseUrl}/v1/sanitize`, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${issued.api_key}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ text: "issued key test", strip_pii: false }),
  });
  assert.equal(issuedKeyCall.status, 200, "newly issued key should bypass x402");
}

const discovery = await fetch(`${baseUrl}/llms.txt`);
assert.equal(discovery.status, 200, "GET /llms.txt should return 200");
assert.match(discovery.headers.get("content-type") ?? "", /text\/plain/i);
const llms = await discovery.text();
const manifestOrigin = llms.match(/^Base URL: (.+)$/m)?.[1];
assert.ok(manifestOrigin, "llms.txt should include its request origin");
assert.match(landingHtml, new RegExp(manifestOrigin.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")));
assert.match(llms, /\$0\.005 USDC/);
assert.match(llms, /\$0\.02 USDC/);
assert.match(llms, /\$0\.022 USDC/);
assert.match(llms, /\$0\.15 USDC/);
assert.match(llms, /Authorization: Bearer/);
assert.match(llms, /five free calls per IP per UTC day/);

const robots = await fetch(`${baseUrl}/robots.txt`);
assert.equal(robots.status, 200);
const robotsTxt = await robots.text();
assert.match(robotsTxt, /User-agent: \*/);
assert.match(robotsTxt, /Allow: \//);
assert.match(robotsTxt, /Sitemap: https:\/\/kybguard\.uk\/sitemap\.xml/);
assert.match(robotsTxt, /# LLMs: https:\/\/kybguard\.uk\/llms\.txt/);

const sitemap = await fetch(`${baseUrl}/sitemap.xml`);
assert.equal(sitemap.status, 200);
assert.match(sitemap.headers.get("content-type") ?? "", /application\/xml/i);
const sitemapXml = await sitemap.text();
assert.match(sitemapXml, /https:\/\/kybguard\.uk\/<\/loc>/);
assert.match(sitemapXml, /https:\/\/kybguard\.uk\/llms\.txt/);
assert.match(sitemapXml, /https:\/\/kybguard\.uk\/\.well-known\/mcp\.json/);
assert.match(sitemapXml, /https:\/\/kybguard\.uk\/openapi\.json/);
for (const path of [
  "/bulk-check",
  "/templates",
  "/guides/companies-house-mcp",
  "/guides/uk-kyb-api",
  "/guides/uk-ni-number-pii-redaction",
]) {
  assert.match(sitemapXml, new RegExp(`https://kybguard\\.uk${path.replaceAll("/", "\\/")}`));
}

const bulkCheck = await fetch(`${baseUrl}/bulk-check`);
assert.equal(bulkCheck.status, 200);
assert.match(bulkCheck.headers.get("content-type") ?? "", /text\/html/i);
const bulkCheckHtml = await bulkCheck.text();
assert.match(bulkCheckHtml, /Bulk CSV UK Company Screener/);
assert.match(bulkCheckHtml, /Screen Companies/);
assert.match(bulkCheckHtml, /Buy 1,000 Credits for £15/);
assert.match(bulkCheckHtml, /Download Enriched CSV/);
assert.match(bulkCheckHtml, /await fetch\("\/v1\/verify-uk-company"/);
assert.match(bulkCheckHtml, /companyNumbers\.length>100/);

const templatesPage = await fetch(`${baseUrl}/templates`);
assert.equal(templatesPage.status, 200);
assert.match(await templatesPage.text(), /Import from File/);
const n8nTemplateResponse = await fetch(`${baseUrl}/templates/n8n-uk-kyb.json`);
assert.equal(n8nTemplateResponse.status, 200);
assert.match(n8nTemplateResponse.headers.get("content-type") ?? "", /application\/json/i);
assert.match(n8nTemplateResponse.headers.get("content-disposition") ?? "", /attachment/);
const n8nTemplate = await n8nTemplateResponse.json();
assert.equal(n8nTemplate.name, "KYBGuard UK Company Audit");
assert.equal(n8nTemplate.nodes.find((node) => node.type === "n8n-nodes-base.webhook").name, "Receive KYB request");
const n8nHttpNode = n8nTemplate.nodes.find((node) => node.type === "n8n-nodes-base.httpRequest");
assert.equal(n8nHttpNode.parameters.url, "https://api.kybguard.uk/v1/full-audit");
assert.match(n8nHttpNode.parameters.headerParameters.parameters[0].value, /KYBGUARD_API_KEY/);
const n8nIfNode = n8nTemplate.nodes.find((node) => node.type === "n8n-nodes-base.if");
assert.equal(n8nIfNode.parameters.conditions.combinator, "or");

for (const [path, title] of [
  ["/guides/companies-house-mcp", /How to Connect UK Companies House to Claude &amp; Cursor via MCP/],
  ["/guides/uk-kyb-api", /Automated UK KYB &amp; Beneficial Ownership \(PSC\) Verification API/],
  ["/guides/uk-ni-number-pii-redaction", /Stripping Prompt Injections &amp; Redacting UK National Insurance Numbers for LLMs/],
]) {
  const guide = await fetch(`${baseUrl}${path}`);
  assert.equal(guide.status, 200, `${path} should return 200`);
  assert.match(guide.headers.get("content-type") ?? "", /text\/html/i);
  assert.match(await guide.text(), title);
}

const mcpResponse = await fetch(`${baseUrl}/.well-known/mcp.json`);
assert.equal(mcpResponse.status, 200);
const mcp = await mcpResponse.json();
assert.equal(mcp.tools.length, 4);
assert.equal(mcp.serverUrl, manifestOrigin);
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
assert.equal(openapi.servers[0].url, manifestOrigin);
assert.equal(openapi.paths["/v1/sanitize"].post["x-x402-payment"].network, "eip155:8453");
assert.equal(openapi.paths["/v1/uk-deep-kyb"].post["x-x402-payment"].network, "eip155:8453");
assert.equal(openapi.paths["/audit/{audit_id}"].get.operationId, "getAuditReceipt");
assert.ok(openapi.paths["/v1/full-audit"].post.responses["200"]);
assert.equal(
  openapi.paths["/v1/uk-deep-kyb"].post.responses["402"].headers["PAYMENT-REQUIRED"].schema.type,
  "string",
);

const missingReceipt = await fetch(`${baseUrl}/audit/${"0".repeat(64)}`);
assert.equal(missingReceipt.status, 404);

const freeSandboxIp = `198.51.100.${Math.floor(Math.random() * 254) + 1}`;
const freeSanitize = () =>
  fetch(`${baseUrl}/v1/sanitize`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "cf-connecting-ip": freeSandboxIp,
    },
    body: JSON.stringify({
      text: "Contact test@example.com",
      strip_pii: true,
    }),
  });
const firstFree = await freeSanitize();
assert.equal(firstFree.status, 200, "first unauthenticated sanitize call should be free");
assert.equal(firstFree.headers.get("X-Free-Remaining"), "4");
const upgradeUrl = new URL(firstFree.headers.get("X-Upgrade-Url"));
assert.equal(upgradeUrl.protocol, "https:");
assert.equal(upgradeUrl.pathname, "/checkout/starter");
const sanitizedFree = await firstFree.json();
assert.equal(sanitizedFree.pii_redacted, true);
assert.match(sanitizedFree.clean_text, /\[REDACTED_EMAIL\]/);
assert.doesNotMatch(sanitizedFree.clean_text, /test@example\.com/);

for (const remaining of ["3", "2", "1", "0"]) {
  const freeResponse = await freeSanitize();
  assert.equal(freeResponse.status, 200, "up to five calls should be free");
  assert.equal(freeResponse.headers.get("X-Free-Remaining"), remaining);
}

const freeQuotaExceeded = await freeSanitize();
assert.equal(freeQuotaExceeded.status, 402, "sixth free call should require payment");
assert.ok(
  freeQuotaExceeded.headers.get("PAYMENT-REQUIRED"),
  "402 response should include a PAYMENT-REQUIRED x402 header",
);
const payment = JSON.parse(
  Buffer.from(freeQuotaExceeded.headers.get("PAYMENT-REQUIRED"), "base64").toString("utf8"),
);
assert.equal(payment.x402Version, 2);
assert.ok(payment.accepts?.some((item) => item.network === "eip155:8453"));
assert.ok(
  payment.accepts?.some(
    (item) => item.scheme === "exact" && item.amount === "5000" && item.asset,
  ),
  "challenge should require exactly 5000 token atomic units",
);

const freeVerify = await fetch(`${baseUrl}/v1/verify-uk-company`, {
  method: "POST",
  headers: {
    "Content-Type": "application/json",
    "cf-connecting-ip": `192.0.2.${Math.floor(Math.random() * 254) + 1}`,
  },
  body: JSON.stringify({ company_number: "!" }),
});
assert.equal(freeVerify.status, 400, "unauthenticated company verification should reach the handler");
assert.equal(freeVerify.headers.get("X-Free-Remaining"), "4");

const paymentHeaderRequest = await fetch(`${baseUrl}/v1/sanitize`, {
  method: "POST",
  headers: {
    "Content-Type": "application/json",
    "cf-connecting-ip": `203.0.113.${Math.floor(Math.random() * 254) + 1}`,
    "PAYMENT-SIGNATURE": "invalid-test-signature",
  },
  body: JSON.stringify({ text: "payment header test", strip_pii: false }),
});
assert.equal(paymentHeaderRequest.status, 402);
assert.equal(paymentHeaderRequest.headers.get("X-Free-Remaining"), null);

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
assert.equal(invalidKey.headers.get("X-Free-Remaining"), null);

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
assert.equal(bridgeCall.result.isError, false);
assert.match(bridgeCall.result.content[0].text, /"http_status":200/);
assert.match(bridgeCall.result.content[0].text, /"clean_text":"bridge test"/);

console.log("Discovery, free sandbox, x402 pricing, Bearer auth, and MCP bridge tests passed.");
