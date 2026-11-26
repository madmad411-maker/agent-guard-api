import { HTTPFacilitatorClient } from "@x402/core/server";
import { ExactEvmScheme } from "@x402/evm/exact/server";
import {
  paymentMiddleware,
  x402ResourceServer,
} from "@x402/hono";
import type { RouteConfig, RoutesConfig } from "@x402/core/server";
import { Hono } from "hono";
import type { Context } from "hono";

type Bindings = {
  WALLET_ADDRESS?: string;
  COMPANIES_HOUSE_API_KEY?: string;
  FACILITATOR_URL: string;
  NETWORK: string;
};

type SanitizeResult = {
  clean_text: string;
  threat_score: number;
  flags: string[];
  pii_redacted: boolean;
  timestamp: string;
};

type CompanyResult = {
  status: 200 | 400 | 404 | 502 | 503;
  body: Record<string, unknown>;
};

const BASE_NETWORK: `${string}:${string}` = "eip155:8453";
const COMPANY_API = "https://api.company-information.service.gov.uk/company/";
const PLACEHOLDER = /^\[PASTE_.+_HERE\]$/;
const MAX_TEXT_LENGTH = 50_000;

const app = new Hono<{ Bindings: Bindings }>();
const paymentMiddlewareCache = new Map<
  string,
  ReturnType<typeof paymentMiddleware>
>();

const prices = {
  sanitize: { amount: "5000", decimal: "$0.005" },
  verify: { amount: "20000", decimal: "$0.02" },
  audit: { amount: "22000", decimal: "$0.022" },
} as const;

function isConfigured(value: string | undefined): value is string {
  return Boolean(value && !PLACEHOLDER.test(value.trim()));
}

function validWallet(value: string | undefined): value is string {
  return Boolean(
    value &&
      /^0x[a-fA-F0-9]{40}$/.test(value) &&
      !/^0x0{40}$/i.test(value),
  );
}

function paymentRoutes(wallet: string): RoutesConfig {
  const payment = (price: string, description: string): RouteConfig => ({
    accepts: {
      scheme: "exact",
      price,
      network: BASE_NETWORK,
      payTo: wallet,
    },
    description,
    mimeType: "application/json",
  });

  return {
    "POST /v1/sanitize": payment(
      prices.sanitize.decimal,
      "Sanitize untrusted text and optionally redact PII",
    ),
    "POST /v1/verify-uk-company": payment(
      prices.verify.decimal,
      "Verify a UK company with Companies House",
    ),
    "POST /v1/full-audit": payment(
      prices.audit.decimal,
      "Run text sanitization and UK company verification together",
    ),
  };
}

app.get("/", (c) =>
  c.json({
    service: "AgentGuard UK & Sanitizer API",
    status: "operational",
    protocol: "x402",
    endpoints: [
      "/v1/sanitize",
      "/v1/verify-uk-company",
      "/v1/full-audit",
    ],
  }),
);

app.get("/llms.txt", (c) =>
  c.text(
    `# AgentGuard UK & Sanitizer API

Machine-readable security sanitization and UK company compliance checks.
Protocol: x402 HTTP 402 micropayments. Network: Base mainnet (eip155:8453).
Payment token: USDC. Send JSON with Content-Type: application/json.
An unpaid request returns HTTP 402 with x402 payment requirements; retry with a valid payment.

## POST /v1/sanitize — $0.005 USDC (5000 atomic units)
Input JSON: {"text":"untrusted text","strip_pii":true}
Output JSON: {"clean_text":"...","threat_score":0,"flags":[],"pii_redacted":false,"timestamp":"ISO-8601"}
Removes common prompt-injection phrases, jailbreak markers, and hidden zero-width characters.
When strip_pii is true, redacts emails, UK phone numbers, UK National Insurance numbers,
payment card numbers that pass a Luhn check, and IBANs.

## POST /v1/verify-uk-company — $0.02 USDC (20000 atomic units)
Input JSON: {"company_number":"01234567"}
Output JSON: {"verified":true,"compliance_pass":true,"company_name":"Example Ltd","status":"active","insolvency_history":false,"incorporated_on":"2000-01-01","checked_at":"ISO-8601"}
Company data is fetched live from the UK Companies House API. Not-found and upstream-error responses
are returned as explicit JSON errors. A compliance pass requires active status and an explicit
Companies House has_insolvency_history value of false.

## POST /v1/full-audit — $0.022 USDC (22000 atomic units)
Input JSON: {"company_number":"01234567","payload_text":"untrusted text"}
Output JSON: {"audit_id":"64-character SHA-256 hex","company_verification":{...},"sanitization":{...}}
Both checks run concurrently. The audit ID hashes the canonical results and audit timestamp.

## Errors
400 means invalid JSON/input. 402 means payment is required or could not be accepted.
404 means a company number was not found. 502/503 indicate an upstream service or configuration error.
`,
    200,
    { "Content-Type": "text/plain; charset=utf-8" },
  ),
);

app.get("/.well-known/mcp.json", (c) =>
  c.json({
    mcpVersion: "2025-03-26",
    name: "agentguard-uk-sanitizer",
    description:
      "Paid AgentGuard sanitization and UK company verification tools. Calls use x402 HTTP 402 payments in USDC on Base (eip155:8453).",
    tools: [
      {
        name: "sanitize_text",
        description:
          "Remove common prompt-injection content and optionally redact PII. Price: 0.005 USDC (5000 atomic units).",
        inputSchema: {
          type: "object",
          properties: {
            text: { type: "string", maxLength: MAX_TEXT_LENGTH },
            strip_pii: { type: "boolean" },
          },
          required: ["text", "strip_pii"],
          additionalProperties: false,
        },
        _meta: {
          "x402:payment": {
            scheme: "exact",
            network: BASE_NETWORK,
            asset: "USDC",
            price: "$0.005",
            atomicUnits: prices.sanitize.amount,
            httpStatus: 402,
            endpoint: "POST /v1/sanitize",
          },
        },
      },
      {
        name: "verify_uk_company",
        description:
          "Check live UK Companies House company status and insolvency history. Price: 0.02 USDC (20000 atomic units).",
        inputSchema: {
          type: "object",
          properties: {
            company_number: {
              type: "string",
              pattern: "^[A-Za-z0-9]{1,8}$",
            },
          },
          required: ["company_number"],
          additionalProperties: false,
        },
        _meta: {
          "x402:payment": {
            scheme: "exact",
            network: BASE_NETWORK,
            asset: "USDC",
            price: "$0.02",
            atomicUnits: prices.verify.amount,
            httpStatus: 402,
            endpoint: "POST /v1/verify-uk-company",
          },
        },
      },
      {
        name: "full_audit",
        description:
          "Concurrently sanitize text and verify a UK company, returning a SHA-256 audit ID. Price: 0.022 USDC (22000 atomic units).",
        inputSchema: {
          type: "object",
          properties: {
            company_number: {
              type: "string",
              pattern: "^[A-Za-z0-9]{1,8}$",
            },
            payload_text: { type: "string", maxLength: MAX_TEXT_LENGTH },
          },
          required: ["company_number", "payload_text"],
          additionalProperties: false,
        },
        _meta: {
          "x402:payment": {
            scheme: "exact",
            network: BASE_NETWORK,
            asset: "USDC",
            price: "$0.022",
            atomicUnits: prices.audit.amount,
            httpStatus: 402,
            endpoint: "POST /v1/full-audit",
          },
        },
      },
    ],
    payment: {
      protocol: "x402",
      httpStatus: 402,
      scheme: "exact",
      network: BASE_NETWORK,
      asset: "USDC",
      paymentRequiredHeader: "PAYMENT-REQUIRED",
    },
  }),
);

app.get("/openapi.json", (c) =>
  c.json({
    openapi: "3.1.0",
    info: {
      title: "AgentGuard UK & Sanitizer API",
      version: "1.0.0",
      description:
        "AI agent text sanitization and UK company checks protected by x402 USDC payments on Base.",
    },
    servers: [{ url: "/" }],
    paths: {
      "/": {
        get: {
          summary: "Service status",
          responses: {
            "200": {
              description: "Service status and endpoint list",
              content: { "application/json": { schema: { type: "object" } } },
            },
          },
        },
      },
      "/llms.txt": {
        get: {
          summary: "AI-agent endpoint and pricing documentation",
          responses: {
            "200": {
              description: "Plain-text service instructions",
              content: { "text/plain": { schema: { type: "string" } } },
            },
          },
        },
      },
      "/.well-known/mcp.json": {
        get: {
          summary: "MCP tool manifest",
          responses: {
            "200": {
              description: "MCP tool definitions and x402 requirements",
              content: { "application/json": { schema: { type: "object" } } },
            },
          },
        },
      },
      "/openapi.json": {
        get: {
          summary: "This OpenAPI specification",
          responses: {
            "200": {
              description: "OpenAPI 3.1 document",
              content: { "application/json": { schema: { type: "object" } } },
            },
          },
        },
      },
      "/v1/sanitize": {
        post: {
          summary: "Sanitize untrusted text",
          description: "Price: $0.005 USDC (5000 atomic units), Base.",
          ...paidOperation(
            "sanitizeText",
            {
              type: "object",
              properties: {
                text: { type: "string", maxLength: MAX_TEXT_LENGTH },
                strip_pii: { type: "boolean" },
              },
              required: ["text", "strip_pii"],
              additionalProperties: false,
            },
            {
              type: "object",
              properties: {
                clean_text: { type: "string" },
                threat_score: { type: "integer", minimum: 0, maximum: 100 },
                flags: { type: "array", items: { type: "string" } },
                pii_redacted: { type: "boolean" },
                timestamp: { type: "string", format: "date-time" },
              },
              required: [
                "clean_text",
                "threat_score",
                "flags",
                "pii_redacted",
                "timestamp",
              ],
            },
          ),
        },
      },
      "/v1/verify-uk-company": {
        post: {
          summary: "Verify a UK company",
          description: "Price: $0.02 USDC (20000 atomic units), Base.",
          ...paidOperation(
            "verifyUkCompany",
            {
              type: "object",
              properties: {
                company_number: {
                  type: "string",
                  pattern: "^[A-Za-z0-9]{1,8}$",
                },
              },
              required: ["company_number"],
              additionalProperties: false,
            },
            {
              type: "object",
              properties: {
                verified: { type: "boolean" },
                compliance_pass: { type: "boolean" },
                company_name: { type: "string" },
                status: { type: "string" },
                insolvency_history: { type: "boolean" },
                incorporated_on: { type: "string" },
                checked_at: { type: "string", format: "date-time" },
              },
              required: [
                "verified",
                "compliance_pass",
                "company_name",
                "status",
                "insolvency_history",
                "incorporated_on",
                "checked_at",
              ],
            },
          ),
        },
      },
      "/v1/full-audit": {
        post: {
          summary: "Run a full compliance and sanitization audit",
          description: "Price: $0.022 USDC (22000 atomic units), Base.",
          ...paidOperation(
            "fullAudit",
            {
              type: "object",
              properties: {
                company_number: {
                  type: "string",
                  pattern: "^[A-Za-z0-9]{1,8}$",
                },
                payload_text: { type: "string", maxLength: MAX_TEXT_LENGTH },
              },
              required: ["company_number", "payload_text"],
              additionalProperties: false,
            },
            {
              type: "object",
              properties: {
                audit_id: {
                  type: "string",
                  pattern: "^[a-f0-9]{64}$",
                },
                company_verification: { type: "object" },
                sanitization: { type: "object" },
              },
              required: [
                "audit_id",
                "company_verification",
                "sanitization",
              ],
            },
          ),
        },
      },
    },
    components: {
      schemas: {
        X402Payment: {
          type: "object",
          description:
            "Unpaid requests return HTTP 402 and a PAYMENT-REQUIRED header containing x402 requirements for exact USDC on Base (eip155:8453).",
        },
      },
    },
  }),
);

function paidOperation(
  operationId: string,
  requestSchema: object,
  responseSchema: object,
) {
  return {
    operationId,
    "x-x402-payment": {
      required: true,
      scheme: "exact",
      network: BASE_NETWORK,
      asset: "USDC",
      responseHeader: "PAYMENT-REQUIRED",
    },
    requestBody: {
      required: true,
      content: { "application/json": { schema: requestSchema } },
    },
    responses: {
      "200": {
        description: "Successful result",
        content: { "application/json": { schema: responseSchema } },
      },
      "400": { description: "Invalid request JSON or fields" },
      "402": {
        description: "x402 payment required",
        headers: {
          "PAYMENT-REQUIRED": {
            schema: { type: "string" },
            description: "Base USDC x402 payment requirements",
          },
        },
      },
      "404": { description: "UK company not found" },
      "502": { description: "Upstream Companies House request failed" },
      "503": { description: "Required service configuration is missing" },
    },
  };
}

app.use("/v1/*", async (c, next) => {
  const wallet = c.env.WALLET_ADDRESS;
  if (!validWallet(wallet)) {
    return c.json(
      { error: "Payment recipient is not configured with a valid Base address" },
      503,
    );
  }
  if ((c.env.NETWORK || "").toLowerCase() !== "base") {
    return c.json({ error: "NETWORK must be configured as base" }, 503);
  }

  const facilitatorUrl = c.env.FACILITATOR_URL || "https://x402.org/facilitator";
  const cacheKey = `${facilitatorUrl}\n${wallet}`;
  let middleware = paymentMiddlewareCache.get(cacheKey);
  if (!middleware) {
    const resourceServer = new x402ResourceServer(
      new HTTPFacilitatorClient({ url: facilitatorUrl }),
    ).register(BASE_NETWORK, new ExactEvmScheme());
    middleware = paymentMiddleware(paymentRoutes(wallet), resourceServer);
    paymentMiddlewareCache.set(cacheKey, middleware);
  }
  return middleware(c, next);
});

app.post("/v1/sanitize", async (c) => {
  const input = await readJson(c);
  if (!input || typeof input.text !== "string" || typeof input.strip_pii !== "boolean") {
    return c.json(
      { error: "Expected JSON fields: text (string), strip_pii (boolean)" },
      400,
    );
  }
  if (input.text.length > MAX_TEXT_LENGTH) {
    return c.json({ error: `text must not exceed ${MAX_TEXT_LENGTH} characters` }, 413);
  }
  return c.json(sanitizeText(input.text, input.strip_pii));
});

app.post("/v1/verify-uk-company", async (c) => {
  const input = await readJson(c);
  if (!input || typeof input.company_number !== "string") {
    return c.json({ error: "Expected JSON field: company_number (string)" }, 400);
  }
  const result = await verifyCompany(input.company_number, c.env);
  return c.json(result.body, result.status);
});

app.post("/v1/full-audit", async (c) => {
  const input = await readJson(c);
  if (
    !input ||
    typeof input.company_number !== "string" ||
    typeof input.payload_text !== "string"
  ) {
    return c.json(
      {
        error:
          "Expected JSON fields: company_number (string), payload_text (string)",
      },
      400,
    );
  }
  const companyNumber = input.company_number;
  const payloadText = input.payload_text;
  if (payloadText.length > MAX_TEXT_LENGTH) {
    return c.json(
      { error: `payload_text must not exceed ${MAX_TEXT_LENGTH} characters` },
      413,
    );
  }

  const [sanitization, company] = await Promise.all([
    Promise.resolve().then(() => sanitizeText(payloadText, true)),
    verifyCompany(companyNumber, c.env),
  ]);
  const checkedAt = new Date().toISOString();
  const hashInput = JSON.stringify({
    company_number: companyNumber,
    company_verification: company.body,
    sanitization,
    checked_at: checkedAt,
  });
  const digest = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(hashInput),
  );
  const auditId = Array.from(new Uint8Array(digest), (byte) =>
    byte.toString(16).padStart(2, "0"),
  ).join("");

  return c.json({
    audit_id: auditId,
    company_verification: company.body,
    sanitization,
    checked_at: checkedAt,
  });
});

async function readJson(c: Context<{ Bindings: Bindings }>) {
  try {
    const body: unknown = await c.req.json();
    return isRecord(body) ? body : null;
  } catch {
    return null;
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function luhnValid(digits: string): boolean {
  let sum = 0;
  let alternate = false;
  for (let index = digits.length - 1; index >= 0; index -= 1) {
    let digit = Number(digits[index]);
    if (alternate) {
      digit *= 2;
      if (digit > 9) digit -= 9;
    }
    sum += digit;
    alternate = !alternate;
  }
  return sum % 10 === 0;
}

function sanitizeText(text: string, stripPii: boolean): SanitizeResult {
  const flags = new Set<string>();
  const weights: Record<string, number> = {
    prompt_injection: 45,
    system_prompt_override: 40,
    jailbreak_marker: 50,
    hidden_unicode: 25,
    pii_email: 0,
    pii_uk_phone: 0,
    pii_national_insurance: 0,
    pii_payment_card: 0,
    pii_iban: 0,
  };
  let cleanText = text;

  if (/[\u200B-\u200F\u202A-\u202E\u2060-\u206F\uFEFF]/u.test(cleanText)) {
    flags.add("hidden_unicode");
    cleanText = cleanText.replace(/[\u200B-\u200F\u202A-\u202E\u2060-\u206F\uFEFF]/gu, "");
  }

  const injectionRules: Array<[RegExp, string]> = [
    [
      /(?:^|\n)[^\n]*(?:ignore|disregard|forget)\s+(?:all\s+)?(?:the\s+)?(?:previous|prior|above|earlier)\s+(?:instructions?|prompts?)[^\n]*/giu,
      "prompt_injection",
    ],
    [
      /(?:^|\n)[^\n]*(?:system\s*prompt|developer\s*message)\s*:[^\n]*/giu,
      "system_prompt_override",
    ],
    [
      /(?:^|\n)[^\n]*(?:jailbreak|DAN\s+mode|do\s+anything\s+now|bypass\s+(?:all\s+)?(?:safety|restrictions?))[^\n]*/giu,
      "jailbreak_marker",
    ],
  ];
  for (const [pattern, flag] of injectionRules) {
    if (pattern.test(cleanText)) flags.add(flag);
    pattern.lastIndex = 0;
    cleanText = cleanText.replace(pattern, "\n");
  }

  const taggedBlocks = [
    /<jailbreak\b[^>]*>[\s\S]*?<\/jailbreak\s*>/giu,
    /<\|im_start\|>\s*system\b[\s\S]*?<\|im_end\|>/giu,
    /\[\s*(?:INST|SYSTEM|JAILBREAK)\s*\][\s\S]*?\[\s*\/\s*(?:INST|SYSTEM|JAILBREAK)\s*\]/giu,
  ];
  for (const pattern of taggedBlocks) {
    if (pattern.test(cleanText)) flags.add("jailbreak_marker");
    pattern.lastIndex = 0;
    cleanText = cleanText.replace(pattern, "\n");
  }

  const jailbreakTags = /<\/?(?:jailbreak|jailbroken|unsafe|untrusted|instruction|system|im_start|im_sep|im_end)(?:\s+[^>]*)?>/giu;
  const imTokens = /<\|(?:im_start|im_sep|im_end)\|>/giu;
  const bracketTags = /\[\s*\/?(?:INST|SYSTEM|JAILBREAK)\s*\]/giu;
  if (jailbreakTags.test(cleanText) || imTokens.test(cleanText) || bracketTags.test(cleanText)) {
    flags.add("jailbreak_marker");
  }
  jailbreakTags.lastIndex = 0;
  imTokens.lastIndex = 0;
  bracketTags.lastIndex = 0;
  cleanText = cleanText
    .replace(jailbreakTags, "")
    .replace(imTokens, "")
    .replace(bracketTags, "");

  if (stripPii) {
    const redact = (pattern: RegExp, flag: string, replacement: string) => {
      cleanText = cleanText.replace(pattern, (match) => {
        if (flag === "pii_payment_card" && !luhnValid(match.replace(/\D/g, ""))) {
          return match;
        }
        flags.add(flag);
        return replacement;
      });
    };
    redact(/\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/giu, "pii_email", "[REDACTED_EMAIL]");
    redact(
      /(?:\+44\s?(?:\(0\)\s?)?|0)(?:\d[\s().-]?){9,10}\b/gu,
      "pii_uk_phone",
      "[REDACTED_UK_PHONE]",
    );
    redact(
      /\b[A-CEGHJ-PR-TW-Z]{2}\s?\d{2}\s?\d{2}\s?\d{2}\s?[A-D]\b/giu,
      "pii_national_insurance",
      "[REDACTED_NATIONAL_INSURANCE]",
    );
    redact(
      /\b[A-Z]{2}\d{2}(?:[\s-]?[A-Z0-9]){11,30}\b/giu,
      "pii_iban",
      "[REDACTED_IBAN]",
    );
    redact(
      /(?<!\d)(?:\d[ -]?){13,19}(?!\d)/gu,
      "pii_payment_card",
      "[REDACTED_PAYMENT_CARD]",
    );
  }

  const threatScore = Math.min(
    100,
    Array.from(flags).reduce((score, flag) => score + (weights[flag] ?? 0), 0),
  );
  return {
    clean_text: cleanText.replace(/[ \t]+\n/gu, "\n").replace(/\n{3,}/gu, "\n\n").trim(),
    threat_score: threatScore,
    flags: Array.from(flags),
    pii_redacted: Array.from(flags).some((flag) => flag.startsWith("pii_")),
    timestamp: new Date().toISOString(),
  };
}

async function verifyCompany(
  companyNumber: string,
  env: Bindings,
): Promise<CompanyResult> {
  const checkedAt = new Date().toISOString();
  if (!/^[A-Za-z0-9]{1,8}$/.test(companyNumber)) {
    return {
      status: 400,
      body: { error: "Invalid UK company number format", checked_at: checkedAt },
    };
  }
  if (!isConfigured(env.COMPANIES_HOUSE_API_KEY)) {
    return {
      status: 503,
      body: {
        error: "Companies House API key is not configured",
        checked_at: checkedAt,
      },
    };
  }

  let response: Response;
  try {
    response = await fetch(
      `${COMPANY_API}${encodeURIComponent(companyNumber.toUpperCase())}`,
      {
        headers: {
          Authorization: `Basic ${btoa(`${env.COMPANIES_HOUSE_API_KEY}:`)}`,
          Accept: "application/json",
        },
      },
    );
  } catch {
    return {
      status: 502,
      body: { error: "Companies House API request failed", checked_at: checkedAt },
    };
  }

  if (response.status === 404) {
    return {
      status: 404,
      body: {
        verified: false,
        compliance_pass: false,
        error: "Company not found",
        company_number: companyNumber.toUpperCase(),
        checked_at: checkedAt,
      },
    };
  }
  if (!response.ok) {
    return {
      status: response.status === 429 ? 503 : 502,
      body: {
        error: "Companies House API returned an unsuccessful response",
        upstream_status: response.status,
        checked_at: checkedAt,
      },
    };
  }

  let profile: unknown;
  try {
    profile = await response.json();
  } catch {
    return {
      status: 502,
      body: { error: "Companies House API returned invalid JSON", checked_at: checkedAt },
    };
  }
  if (!isRecord(profile)) {
    return {
      status: 502,
      body: { error: "Companies House API returned an invalid profile", checked_at: checkedAt },
    };
  }

  const status =
    typeof profile.company_status === "string" ? profile.company_status : "unknown";
  const insolvencyHistory = profile.has_insolvency_history === true;
  return {
    status: 200,
    body: {
      verified: true,
      compliance_pass:
        status === "active" && profile.has_insolvency_history === false,
      company_name:
        typeof profile.company_name === "string" ? profile.company_name : "",
      status,
      insolvency_history: insolvencyHistory,
      incorporated_on:
        typeof profile.date_of_creation === "string" ? profile.date_of_creation : "",
      checked_at: checkedAt,
    },
  };
}

export default {
  fetch: app.fetch,
} satisfies ExportedHandler<Bindings>;
