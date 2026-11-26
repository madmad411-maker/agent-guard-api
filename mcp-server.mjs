import readline from "node:readline";

const apiBaseUrl = (
  process.env.AGENTGUARD_API_URL ??
  "https://api.kybguard.uk"
).replace(/\/+$/, "");
const apiKey = process.env.AGENTGUARD_API_KEY;
const tools = [
  {
    name: "sanitize_text",
    description: "Sanitize untrusted text and optionally redact PII ($0.005 USDC via x402).",
    inputSchema: {
      type: "object",
      properties: {
        text: { type: "string" },
        strip_pii: { type: "boolean" },
      },
      required: ["text", "strip_pii"],
      additionalProperties: false,
    },
    path: "/v1/sanitize",
  },
  {
    name: "verify_uk_company",
    description: "Verify a UK company with Companies House ($0.02 USDC via x402).",
    inputSchema: {
      type: "object",
      properties: { company_number: { type: "string" } },
      required: ["company_number"],
      additionalProperties: false,
    },
    path: "/v1/verify-uk-company",
  },
  {
    name: "full_audit",
    description: "Sanitize text and verify a UK company ($0.022 USDC via x402).",
    inputSchema: {
      type: "object",
      properties: {
        company_number: { type: "string" },
        payload_text: { type: "string" },
      },
      required: ["company_number", "payload_text"],
      additionalProperties: false,
    },
    path: "/v1/full-audit",
  },
  {
    name: "uk_deep_kyb",
    description: "Run deep UK company KYB checks ($0.15 USDC via x402).",
    inputSchema: {
      type: "object",
      properties: { company_number: { type: "string" } },
      required: ["company_number"],
      additionalProperties: false,
    },
    path: "/v1/uk-deep-kyb",
  },
];

function send(message) {
  process.stdout.write(`${JSON.stringify(message)}\n`);
}

async function handle(request) {
  const { id, method, params = {} } = request;
  if (method === "notifications/initialized" || method?.startsWith("notifications/")) {
    return;
  }
  if (method === "initialize") {
    send({
      jsonrpc: "2.0",
      id,
      result: {
        protocolVersion: params.protocolVersion ?? "2025-03-26",
        capabilities: { tools: {} },
        serverInfo: { name: "agentguard-cloudflare-bridge", version: "1.0.0" },
      },
    });
    return;
  }
  if (method === "ping") {
    send({ jsonrpc: "2.0", id, result: {} });
    return;
  }
  if (method === "tools/list") {
    send({
      jsonrpc: "2.0",
      id,
      result: {
        tools: tools.map(({ name, description, inputSchema }) => ({
          name,
          description,
          inputSchema,
        })),
      },
    });
    return;
  }
  if (method === "tools/call") {
    const tool = tools.find((candidate) => candidate.name === params.name);
    if (!tool) {
      send({
        jsonrpc: "2.0",
        id,
        error: { code: -32602, message: `Unknown tool: ${params.name}` },
      });
      return;
    }

    try {
      const headers = { "content-type": "application/json" };
      if (apiKey) headers.authorization = `Bearer ${apiKey}`;
      const response = await fetch(`${apiBaseUrl}${tool.path}`, {
        method: "POST",
        headers,
        body: JSON.stringify(params.arguments ?? {}),
      });
      const text = await response.text();
      const paymentRequired = response.headers.get("PAYMENT-REQUIRED");
      let payload;
      try {
        payload = JSON.parse(text);
      } catch {
        payload = { response: text };
      }
      send({
        jsonrpc: "2.0",
        id,
        result: {
          isError: !response.ok,
          content: [
            {
              type: "text",
              text: JSON.stringify({
                http_status: response.status,
                payment_required: paymentRequired,
                body: payload,
              }),
            },
          ],
        },
      });
    } catch (error) {
      send({
        jsonrpc: "2.0",
        id,
        result: {
          isError: true,
          content: [{ type: "text", text: error instanceof Error ? error.message : String(error) }],
        },
      });
    }
    return;
  }
  send({ jsonrpc: "2.0", id, error: { code: -32601, message: "Method not found" } });
}

const input = readline.createInterface({ input: process.stdin, crlfDelay: Infinity });
input.on("line", (line) => {
  try {
    const request = JSON.parse(line);
    void handle(request).catch((error) => {
      if (request?.id !== undefined) {
        send({
          jsonrpc: "2.0",
          id: request.id,
          error: {
            code: -32603,
            message: error instanceof Error ? error.message : String(error),
          },
        });
      }
    });
  } catch {
    send({ jsonrpc: "2.0", id: null, error: { code: -32700, message: "Parse error" } });
  }
});
