#!/usr/bin/env node
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";

const API_BASE_URL = "https://api.kybguard.uk";
const configuredApiKey = process.env.KYBGUARD_API_KEY?.trim();
const apiKey =
  configuredApiKey?.toLowerCase() === "optional_ag_key_for_higher_limits"
    ? undefined
    : configuredApiKey || undefined;

const server = new McpServer({
  name: "kybguard-mcp",
  version: "0.1.0",
});

type ToolResult = {
  content: [{ type: "text"; text: string }];
  isError?: boolean;
};

function errorResult(message: string): ToolResult {
  return {
    isError: true,
    content: [{ type: "text", text: message }],
  };
}

async function callApi(
  path: string,
  payload: Record<string, unknown>,
): Promise<ToolResult> {
  const headers = new Headers({ "Content-Type": "application/json" });
  if (apiKey) headers.set("Authorization", `Bearer ${apiKey}`);

  let response: Response;
  try {
    response = await fetch(`${API_BASE_URL}${path}`, {
      method: "POST",
      headers,
      body: JSON.stringify(payload),
    });
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    return errorResult(`KYBGuard request failed: ${message}`);
  }

  let responseBody: unknown;
  try {
    const responseText = await response.text();
    try {
      responseBody = JSON.parse(responseText);
    } catch {
      responseBody = { response: responseText };
    }
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    return errorResult(`Could not read the KYBGuard response: ${message}`);
  }

  return {
    isError: !response.ok,
    content: [
      {
        type: "text",
        text: JSON.stringify(
          {
            http_status: response.status,
            payment_required: response.headers.get("PAYMENT-REQUIRED"),
            body: responseBody,
          },
          null,
          2,
        ),
      },
    ],
  };
}

server.registerTool(
  "sanitize",
  {
    description:
      "Sanitize untrusted text and optionally redact PII before passing it to an LLM.",
    inputSchema: {
      text: z.string(),
      strip_pii: z.boolean().optional(),
    },
  },
  async ({ text, strip_pii }) =>
    callApi("/v1/sanitize", { text, strip_pii: strip_pii ?? true }),
);

server.registerTool(
  "verify_uk_company",
  {
    description: "Verify a UK company using its Companies House company number.",
    inputSchema: {
      company_number: z.string(),
    },
  },
  async ({ company_number }) =>
    callApi("/v1/verify-uk-company", { company_number }),
);

server.registerTool(
  "full_audit",
  {
    description:
      "Run a UK company verification and sanitize associated text, returning an audit receipt.",
    inputSchema: {
      company_number: z.string(),
      payload_text: z.string(),
    },
  },
  async ({ company_number, payload_text }) =>
    callApi("/v1/full-audit", { company_number, payload_text }),
);

server.registerTool(
  "uk_deep_kyb",
  {
    description:
      "Run a deeper UK KYB check including company status, directors, and Persons with Significant Control.",
    inputSchema: {
      company_number: z.string(),
    },
  },
  async ({ company_number }) =>
    callApi("/v1/uk-deep-kyb", { company_number }),
);

const transport = new StdioServerTransport();
await server.connect(transport);
