import { HTTPFacilitatorClient } from "@x402/core/server";
import { ExactEvmScheme } from "@x402/evm/exact/server";
import {
  paymentMiddleware,
  x402ResourceServer,
} from "@x402/hono";
import type { RouteConfig, RoutesConfig } from "@x402/core/server";
import { Hono } from "hono";
import type { Context } from "hono";

interface Env {
  WALLET_ADDRESS?: string;
  COMPANIES_HOUSE_API_KEY?: string;
  FACILITATOR_URL: string;
  NETWORK: string;
  KYB_CACHE?: KVNamespace;
  API_KEYS?: KVNamespace;
  ADMIN_SECRET?: string;
  STRIPE_SECRET_KEY: string;
  STRIPE_WEBHOOK_SECRET: string;
}

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

type CompanyResource = {
  status: number;
  data: unknown;
  cached: boolean;
};

const BASE_NETWORK: `${string}:${string}` = "eip155:8453";
const COMPANY_API = "https://api.company-information.service.gov.uk/company/";
const PLACEHOLDER = /^\[PASTE_.+_HERE\]$/;
const MAX_TEXT_LENGTH = 50_000;
const KYB_CACHE_TTL_SECONDS = 6 * 60 * 60;
const DEFAULT_PUBLIC_ORIGIN = "https://api.kybguard.uk";

const app = new Hono<{ Bindings: Env }>();

app.use("*", async (c, next) => {
  const requestUrl = new URL(c.req.url);
  const forwardedProto = c.req
    .header("x-forwarded-proto")
    ?.split(",")[0]
    .trim()
    .toLowerCase();

  if (requestUrl.protocol === "http:" || forwardedProto === "http") {
    return c.redirect(c.req.url.replace(/^http:/i, "https:"), 301);
  }

  await next();
});

const paymentMiddlewareCache = new Map<
  string,
  ReturnType<typeof paymentMiddleware>
>();

const prices = {
  sanitize: { amount: "5000", decimal: "$0.005" },
  verify: { amount: "20000", decimal: "$0.02" },
  audit: { amount: "22000", decimal: "$0.022" },
  deepKyb: { amount: "150000", decimal: "$0.15" },
} as const;

const subscriptionPlans = {
  starter: { amount: 2900, credits: 5000, label: "Starter" },
  pro: { amount: 9900, credits: 25000, label: "Pro" },
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

function generateApiKey(): string {
  const keyBytes = crypto.getRandomValues(new Uint8Array(32));
  return `kyb_live_${Array.from(keyBytes, (byte) =>
    byte.toString(16).padStart(2, "0"),
  ).join("")}`;
}

async function saveApiKey(
  env: Env,
  metadata: Record<string, unknown>,
  apiKey = generateApiKey(),
): Promise<string> {
  if (!env.API_KEYS) throw new Error("API key storage is not configured");
  await env.API_KEYS.put(apiKey, JSON.stringify(metadata));
  return apiKey;
}

async function keyForStripeEvent(secret: string, eventId: string): Promise<string> {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const digest = new Uint8Array(
    await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(eventId)),
  );
  return `kyb_live_${Array.from(digest, (byte) =>
    byte.toString(16).padStart(2, "0"),
  ).join("")}`;
}

function hexToBytes(hex: string): Uint8Array | null {
  if (!/^[a-f0-9]{64}$/i.test(hex)) return null;
  return Uint8Array.from(
    hex.match(/.{2}/g) ?? [],
    (byte) => Number.parseInt(byte, 16),
  );
}

async function verifyStripeSignature(
  body: string,
  signatureHeader: string | undefined,
  secret: string,
): Promise<boolean> {
  if (!signatureHeader) return false;
  const fields = signatureHeader.split(",").map((field) => field.split("=", 2));
  const timestamp = fields.find(([name]) => name === "t")?.[1];
  const timestampSeconds = Number(timestamp);
  const nowSeconds = Math.floor(Date.now() / 1000);
  if (
    !timestamp ||
    !Number.isSafeInteger(timestampSeconds) ||
    Math.abs(nowSeconds - timestampSeconds) > 300
  ) {
    return false;
  }

  const signatures = fields
    .filter(([name]) => name === "v1")
    .map(([, value]) => hexToBytes(value ?? ""))
    .filter((value): value is Uint8Array => value !== null);
  if (signatures.length === 0) return false;

  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["verify"],
  );
  const signedPayload = new TextEncoder().encode(`${timestamp}.${body}`);
  const results = await Promise.all(
    signatures.map((signature) => {
      const signatureBuffer = new ArrayBuffer(signature.byteLength);
      new Uint8Array(signatureBuffer).set(signature);
      return crypto.subtle.verify(
        "HMAC",
        key,
        signatureBuffer,
        signedPayload,
      );
    }),
  );
  return results.some(Boolean);
}

function subscriptionId(value: unknown): string | null {
  if (typeof value === "string" && value.length > 0) return value;
  if (isRecord(value) && typeof value.id === "string" && value.id.length > 0) {
    return value.id;
  }
  return null;
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
    "POST /v1/uk-deep-kyb": payment(
      prices.deepKyb.decimal,
      "Run a deep UK company KYB check across profile, officers, and PSC data",
    ),
  };
}

app.get("/checkout/success", async (c) => {
  const sessionId = c.req.query("session_id");
  if (!sessionId || !c.env.API_KEYS) {
    return c.html(checkoutStatusPage("We couldn't find your checkout session."), 400);
  }

  let provisioned: unknown;
  try {
    provisioned = await c.env.API_KEYS.get(`session_${sessionId}`, "json");
  } catch (error) {
    console.error("Checkout session lookup failed", error);
    return c.html(checkoutStatusPage("We couldn't load your API key. Please contact support."), 503);
  }

  if (!isRecord(provisioned) || typeof provisioned.api_key !== "string") {
    return c.html(checkoutStatusPage("Provisioning your API key..."), 200);
  }

  const apiKey = escapeHtml(provisioned.api_key);
  const curlCommand = escapeHtml(
    `curl -X POST https://api.kybguard.uk/v1/verify-uk-company \\\n  -H 'Authorization: Bearer ${provisioned.api_key}' \\\n  -H 'Content-Type: application/json' \\\n  --data '{"company_number":"00000000"}'`,
  );
  return c.html(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Your AgentGuard API key</title><style>
:root{color-scheme:dark;--bg:#0b1220;--panel:#121d2e;--line:#25344a;--text:#edf4ff;--muted:#a9b8cb;--green:#57e3ad}
*{box-sizing:border-box}body{margin:0;min-height:100vh;background:radial-gradient(ellipse at 50% 0,#17283b,var(--bg) 60%);color:var(--text);font:16px/1.6 system-ui,sans-serif;display:grid;place-items:center;padding:24px}
main{width:min(100%,680px);padding:clamp(22px,6vw,42px);border:1px solid var(--line);border-radius:20px;background:#101a29eF;box-shadow:0 24px 80px #0006}h1{font-size:clamp(1.8rem,6vw,2.6rem);line-height:1.15;margin:12px 0}.muted{color:var(--muted)}.badge{color:var(--green);font-weight:700}
.key{margin:22px 0 12px;padding:14px;border:1px solid var(--line);border-radius:12px;background:#09111d;overflow-wrap:anywhere;font: .94rem/1.5 ui-monospace,monospace}
button{border:0;border-radius:10px;padding:12px 18px;background:var(--green);color:#07160f;font-weight:750;font-size:1rem;cursor:pointer}pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#09111d;border:1px solid var(--line);padding:16px;border-radius:12px;color:#d9e8f9;font-size:.86rem}a{color:var(--green)}
</style></head><body><main><span class="badge">Payment confirmed</span><h1>Your API key is ready</h1>
<p class="muted">Keep this key private. You can use it immediately to authenticate API requests.</p>
<div class="key" id="api-key">${apiKey}</div><button id="copy-key" type="button">Copy API key</button>
<h2>Try a company check</h2><p class="muted">Replace the example company number with the one you want to verify.</p><pre><code>${curlCommand}</code></pre>
<p class="muted">Need help? Visit <a href="https://kybguard.uk">kybguard.uk</a>.</p></main>
<script>document.getElementById("copy-key").addEventListener("click",async()=>{const button=document.getElementById("copy-key");try{await navigator.clipboard.writeText(document.getElementById("api-key").textContent||"");button.textContent="Copied";}catch{button.textContent="Copy unavailable";}});</script>
</body></html>`);
});

function checkoutStatusPage(message: string): string {
  const refresh = message.startsWith("Provisioning")
    ? '<meta http-equiv="refresh" content="2">'
    : "";
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">${refresh}
<title>AgentGuard checkout</title><style>body{margin:0;min-height:100vh;display:grid;place-items:center;padding:24px;background:#0b1220;color:#edf4ff;font:16px/1.6 system-ui,sans-serif}main{max-width:560px;padding:32px;border:1px solid #25344a;border-radius:18px;background:#121d2e}p{color:#a9b8cb}</style></head><body><main><h1>${escapeHtml(message)}</h1><p>This page will update automatically when your key is available.</p></main></body></html>`;
}

app.get("/checkout/:plan", async (c) => {
  const planName = c.req.param("plan");
  if (planName !== "starter" && planName !== "pro") {
    return c.json({ error: "Plan must be starter or pro" }, 400);
  }

  const stripeSecret = c.env.STRIPE_SECRET_KEY;
  if (!stripeSecret) return c.json({ error: "Stripe is not configured" }, 503);
  const plan = subscriptionPlans[planName];
  const form = new URLSearchParams({
    mode: "subscription",
    "line_items[0][price_data][currency]": "gbp",
    "line_items[0][price_data][unit_amount]": String(plan.amount),
    "line_items[0][price_data][recurring][interval]": "month",
    "line_items[0][price_data][product_data][name]":
      `AgentGuard UK ${plan.label} (${plan.credits.toLocaleString("en-GB")} requests/mo)`,
    "line_items[0][quantity]": "1",
    "metadata[plan]": planName,
    "metadata[credits]": String(plan.credits),
    success_url:
      "https://kybguard.uk/checkout/success?session_id={CHECKOUT_SESSION_ID}",
    cancel_url: "https://kybguard.uk/",
  });

  let stripeResponse: Response;
  try {
    stripeResponse = await fetch("https://api.stripe.com/v1/checkout/sessions", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${stripeSecret}`,
        "Content-Type": "application/x-www-form-urlencoded",
      },
      body: form,
    });
  } catch (error) {
    console.error("Stripe Checkout request failed", error);
    return c.json({ error: "Unable to create Stripe Checkout session" }, 502);
  }

  let stripeResult: unknown;
  try {
    stripeResult = await stripeResponse.json();
  } catch (error) {
    console.error("Stripe Checkout returned invalid JSON", error);
    return c.json({ error: "Stripe returned an invalid response" }, 502);
  }
  if (!stripeResponse.ok) {
    const details =
      isRecord(stripeResult) &&
      isRecord(stripeResult.error) &&
      typeof stripeResult.error.message === "string"
        ? stripeResult.error.message
        : "Stripe rejected the Checkout session request";
    return c.json({ error: "Stripe Checkout session creation failed", details }, 502);
  }
  if (!isRecord(stripeResult) || typeof stripeResult.url !== "string") {
    return c.json({ error: "Stripe returned no Checkout URL" }, 502);
  }
  return c.redirect(stripeResult.url, 302);
});

app.post("/webhooks/stripe", async (c) => {
  const body = await c.req.text();
  const webhookSecret = c.env.STRIPE_WEBHOOK_SECRET;
  if (!webhookSecret) return c.json({ error: "Stripe webhook is not configured" }, 503);

  let signatureValid: boolean;
  try {
    signatureValid = await verifyStripeSignature(
      body,
      c.req.header("Stripe-Signature"),
      webhookSecret,
    );
  } catch (error) {
    console.error("Stripe signature verification failed", error);
    return c.json({ error: "Invalid Stripe signature" }, 400);
  }
  if (!signatureValid) return c.json({ error: "Invalid Stripe signature" }, 400);

  let event: unknown;
  try {
    event = JSON.parse(body);
  } catch {
    return c.json({ error: "Invalid Stripe event JSON" }, 400);
  }
  if (
    !isRecord(event) ||
    typeof event.id !== "string" ||
    typeof event.type !== "string" ||
    !isRecord(event.data) ||
    !isRecord(event.data.object)
  ) {
    return c.json({ error: "Invalid Stripe event payload" }, 400);
  }
  if (
    event.type !== "checkout.session.completed" &&
    event.type !== "invoice.paid"
  ) {
    return c.json({ received: true });
  }
  if (!c.env.KYB_CACHE || !c.env.API_KEYS) {
    return c.json({ error: "Stripe webhook storage is not configured" }, 503);
  }

  try {
    const eventKey = `stripe_evt_${event.id}`;
    if (await c.env.KYB_CACHE.get(eventKey)) return c.json({ received: true });

    const stripeObject = event.data.object;
    if (event.type === "checkout.session.completed") {
      const metadata = isRecord(stripeObject.metadata) ? stripeObject.metadata : {};
      const planName = metadata.plan;
      const credits = metadata.credits;
      if (
        (planName !== "starter" && planName !== "pro") ||
        credits !== String(subscriptionPlans[planName].credits) ||
        typeof stripeObject.id !== "string"
      ) {
        return c.json({ error: "Checkout session is missing valid plan metadata" }, 400);
      }

      const plan = subscriptionPlans[planName];
      const customerDetails = isRecord(stripeObject.customer_details)
        ? stripeObject.customer_details
        : {};
      const email =
        typeof customerDetails.email === "string"
          ? customerDetails.email
          : typeof stripeObject.customer_email === "string"
            ? stripeObject.customer_email
            : "";
      const subId = subscriptionId(stripeObject.subscription);
      const apiKey = await keyForStripeEvent(webhookSecret, event.id);
      await saveApiKey(
        c.env,
        {
          customer_email: email,
          plan: planName,
          created_at: new Date().toISOString(),
          credits: plan.credits,
          monthly_quota: plan.credits,
          requests_used: 0,
          subscription_id: subId,
        },
        apiKey,
      );
      if (subId) {
        await c.env.API_KEYS.put(`subscription_${subId}`, apiKey);
      }
      await c.env.API_KEYS.put(
        `session_${stripeObject.id}`,
        JSON.stringify({ api_key: apiKey, plan: planName, credits: plan.credits }),
        { expirationTtl: 3600 },
      );
    } else if (
      event.type === "invoice.paid" &&
      stripeObject.billing_reason === "subscription_cycle"
    ) {
      const subId = subscriptionId(stripeObject.subscription);
      if (subId) {
        const apiKey = await c.env.API_KEYS.get(`subscription_${subId}`);
        if (apiKey) {
          const currentMetadata = await c.env.API_KEYS.get(apiKey, "json");
          if (isRecord(currentMetadata)) {
            const planName = currentMetadata.plan;
            if (planName === "starter" || planName === "pro") {
              await c.env.API_KEYS.put(
                apiKey,
                JSON.stringify({
                  ...currentMetadata,
                  credits: subscriptionPlans[planName].credits,
                  monthly_quota: subscriptionPlans[planName].credits,
                  requests_used: 0,
                  quota_reset_at: new Date().toISOString(),
                }),
              );
            }
          }
        }
      }
    }

    await c.env.KYB_CACHE.put(eventKey, "1", { expirationTtl: 7 * 24 * 60 * 60 });
    return c.json({ received: true });
  } catch (error) {
    console.error("Stripe webhook processing failed", error);
    return c.json({ error: "Stripe event processing failed" }, 500);
  }
});

app.get("/", (c) => {
  if (!acceptsHtml(c.req.header("Accept"))) {
    return c.json({
      service: "AgentGuard UK & Sanitizer API",
      status: "operational",
      protocol: "x402",
      endpoints: [
        "/v1/sanitize",
        "/v1/verify-uk-company",
        "/v1/full-audit",
        "/v1/uk-deep-kyb",
      ],
    });
  }

  const origin = escapeHtml(publicOrigin(c));
  return c.html(`<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="theme-color" content="#090d18">
  <meta name="description" content="Real-time AI agent sanitization and UK company KYB verification, paid with x402 USDC on Base.">
  <title>AgentGuard — AI Security & UK Company KYB</title>
  <style>
    :root{color-scheme:dark;--bg:#090d18;--panel:#111827;--line:#253148;--text:#edf3ff;--muted:#a9b7cb;--green:#57e3ad;--blue:#8eb8ff;--purple:#c3a6ff}
    *{box-sizing:border-box}
    body{margin:0;background:radial-gradient(ellipse at 80% -20%,#19335a 0,transparent 42%),var(--bg);color:var(--text);font:16px/1.6 ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}
    a{color:var(--blue);text-decoration:none}a:hover{text-decoration:underline}
    .wrap{width:min(1080px,100% - 36px);margin:0 auto}
    header{padding:22px 0;border-bottom:1px solid #ffffff12}
    nav{display:flex;align-items:center;justify-content:space-between;gap:16px}
    .brand{font-weight:750;letter-spacing:.02em;color:var(--text)}
    .navlinks{display:flex;gap:20px;flex-wrap:wrap;font-size:.92rem}
    main{padding:68px 0 56px}
    .hero{max-width:760px}
    .eyebrow{color:var(--green);font-size:.82rem;font-weight:700;letter-spacing:.14em;text-transform:uppercase}
    h1{font-size:clamp(2.4rem,7vw,4.7rem);line-height:1.04;letter-spacing:-.055em;margin:15px 0 20px}
    .lead{max-width:660px;color:var(--muted);font-size:1.14rem}
    .status{display:inline-flex;align-items:center;gap:9px;padding:7px 12px;border:1px solid #57e3ad55;border-radius:999px;background:#57e3ad12;color:var(--green);font-size:.9rem;font-weight:700}
    .dot{width:8px;height:8px;background:currentColor;border-radius:50%;box-shadow:0 0 12px currentColor}
    .actions{display:flex;gap:12px;flex-wrap:wrap;margin:28px 0 0}
    .button{display:inline-block;padding:10px 15px;border-radius:10px;border:1px solid var(--line);background:#ffffff08;color:var(--text);font-weight:650}
    .button.primary{background:var(--green);border-color:var(--green);color:#082017}
    section{margin-top:54px}
    h2{font-size:1.45rem;letter-spacing:-.02em;margin:0 0 16px}
    .grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:14px}
    .card{padding:19px;border:1px solid var(--line);border-radius:14px;background:linear-gradient(145deg,#141e30,#0e1522)}
    .card h3{margin:0 0 5px;font-size:1.02rem}
    .card p{margin:0;color:var(--muted);font-size:.93rem}
    .price{display:block;color:var(--green);font-size:1.25rem;font-weight:750;margin-top:12px}
    .rail{color:var(--muted);margin:15px 0 0}
    .plans{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:14px}
    .plan{padding:21px;border:1px solid var(--line);border-radius:14px;background:linear-gradient(145deg,#141e30,#0e1522)}
    .plan h3{margin:0;font-size:1.08rem}
    .plan-price{font-size:1.8rem;font-weight:800;letter-spacing:-.04em;margin:9px 0 0}
    .plan p{color:var(--muted);margin:4px 0}
    .plan .button{margin-top:14px}
    .plan.featured{border-color:#57e3ad77}
    .codegrid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:14px}
    pre{overflow:auto;margin:10px 0 0;padding:16px;border:1px solid var(--line);border-radius:12px;background:#070b13;color:#dbe8ff;font:13px/1.55 ui-monospace,SFMono-Regular,Consolas,monospace}
    .links{display:flex;gap:18px;flex-wrap:wrap}
    footer{padding:25px 0 38px;border-top:1px solid #ffffff12;color:var(--muted);font-size:.9rem}
    @media(max-width:680px){header{padding:17px 0}.navlinks{gap:12px;font-size:.84rem}main{padding-top:48px}.grid,.plans,.codegrid{grid-template-columns:1fr}.wrap{width:min(100% - 28px,1080px)}section{margin-top:42px}}
  </style>
</head>
<body>
  <header><nav class="wrap" aria-label="Main navigation">
    <a class="brand" href="${origin}/">AGENTGUARD</a>
    <div class="navlinks"><a href="#pricing">Pricing</a><a href="#quickstart">Quick start</a><a href="${origin}/openapi.json">API docs</a></div>
  </nav></header>
  <main class="wrap">
    <div class="hero">
      <span class="status"><span class="dot" aria-hidden="true"></span> Live status: Operational</span>
      <p class="eyebrow">AI security · UK company KYB</p>
      <h1>Trust the input.<br>Verify the business.</h1>
      <p class="lead">Sanitize agent-bound text, redact sensitive data, and verify UK companies with live Companies House records. Pay per request with x402 USDC on Base, or use a Bearer API key.</p>
      <div class="actions"><a class="button primary" href="#quickstart">Get started</a><a class="button" href="${origin}/llms.txt">Read agent docs</a></div>
    </div>

    <section id="pricing" aria-labelledby="pricing-title">
      <h2 id="pricing-title">Simple pay-per-call pricing</h2>
      <div class="grid">
        <article class="card"><h3>Text sanitization</h3><p>Prompt-injection cleanup and optional PII redaction.</p><span class="price">${prices.sanitize.decimal} USDC</span></article>
        <article class="card"><h3>UK company verification</h3><p>Company status, incorporation date, and insolvency check.</p><span class="price">${prices.verify.decimal} USDC</span></article>
        <article class="card"><h3>Full audit</h3><p>Run sanitization and company verification together.</p><span class="price">${prices.audit.decimal} USDC</span></article>
        <article class="card"><h3>Deep UK KYB</h3><p>Profile, directors, PSCs, and risk assessment.</p><span class="price">${prices.deepKyb.decimal} USDC</span></article>
      </div>
      <p class="rail">All x402 payments use USDC on Base (<code>eip155:8453</code>). Valid Bearer API keys in the API_KEYS KV namespace bypass payment.</p>
    </section>

    <section id="plans" aria-labelledby="plans-title">
      <h2 id="plans-title">Enterprise &amp; Prepaid API Keys</h2>
      <div class="plans">
        <article class="plan"><h3>Starter</h3><div class="plan-price">£29<span class="rail">/mo</span></div><p>5,000 requests per month</p><a class="button" href="mailto:keys@kybguard.uk?subject=KYBGuard%20API%20Key%20Request">Request / Buy API Key</a></article>
        <article class="plan featured"><h3>Pro</h3><div class="plan-price">£99<span class="rail">/mo</span></div><p>25,000 requests per month</p><a class="button primary" href="mailto:keys@kybguard.uk?subject=KYBGuard%20API%20Key%20Request">Request / Buy API Key</a></article>
        <article class="plan"><h3>Pay-As-You-Go</h3><div class="plan-price">x402</div><p>USDC micropayments on Base, billed per call</p><a class="button" href="#pricing">View per-call pricing</a></article>
      </div>
    </section>

    <section id="quickstart" aria-labelledby="quickstart-title">
      <h2 id="quickstart-title">Quick start</h2>
      <div class="codegrid">
        <div><h3>Try the API with curl</h3><p class="rail">An unpaid request returns HTTP 402 with x402 payment requirements.</p>
          <pre><code>curl -i ${origin}/v1/sanitize \\
  -H 'Content-Type: application/json' \\
  --data '{"text":"untrusted input","strip_pii":true}'</code></pre>
        </div>
        <div><h3>Connect an MCP client</h3><p class="rail">Add this stdio server to Claude, Cursor, or another MCP client.</p>
          <pre><code>{
  "command": "node",
  "args": ["/path/to/agent-guard-api/mcp-server.mjs"],
  "env": {
    "AGENTGUARD_API_URL": "${origin}",
    "AGENTGUARD_API_KEY": "&lt;your-api-key&gt;"
  }
}</code></pre>
        </div>
      </div>
    </section>

    <section aria-labelledby="docs-title">
      <h2 id="docs-title">Explore the API</h2>
      <div class="links"><a href="${origin}/llms.txt">llms.txt</a><a href="${origin}/openapi.json">OpenAPI 3.1</a><a href="${origin}/.well-known/mcp.json">MCP tool manifest</a></div>
    </section>
  </main>
  <footer><div class="wrap">AgentGuard UK &amp; Sanitizer API · <a href="${origin}">kybguard.uk</a> · Base USDC x402</div></footer>
</body>
</html>`);
});

function acceptsHtml(accept: string | undefined): boolean {
  return Boolean(
    accept?.split(",").some((mediaRange) => {
      const [mediaType, ...parameters] = mediaRange.split(";");
      if (mediaType.trim().toLowerCase() !== "text/html") return false;
      const quality = parameters.find((parameter) => /^\s*q=/i.test(parameter));
      return Number(quality?.split("=")[1] ?? 1) > 0;
    }),
  );
}

function escapeHtml(value: string): string {
  return value.replace(/[&<>"']/g, (character) => {
    const entities: Record<string, string> = {
      "&": "&amp;",
      "<": "&lt;",
      ">": "&gt;",
      '"': "&quot;",
      "'": "&#39;",
    };
    return entities[character] ?? character;
  });
}

app.post("/admin/issue-key", async (c) => {
  const secret = c.env.ADMIN_SECRET;
  const suppliedSecret = c.req.header("Authorization")?.match(
    /^Bearer\s+(\S+)$/i,
  )?.[1];
  if (!secret || !suppliedSecret || suppliedSecret !== secret) {
    return c.json(
      { error: "Unauthorized" },
      401,
      { "WWW-Authenticate": "Bearer" },
    );
  }
  if (!c.env.API_KEYS) {
    return c.json({ error: "API key storage is not configured" }, 503);
  }

  const input = await readJson(c);
  if (
    !input ||
    typeof input.customer_email !== "string" ||
    input.customer_email.length > 254 ||
    !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(input.customer_email) ||
    typeof input.plan !== "string" ||
    !["starter", "pro", "enterprise"].includes(input.plan.toLowerCase())
  ) {
    return c.json(
      {
        error:
          "Expected customer_email (valid email) and plan (starter, pro, or enterprise)",
      },
      400,
    );
  }

  const keyBytes = crypto.getRandomValues(new Uint8Array(32));
  const apiKey = `kyb_live_${Array.from(keyBytes, (byte) =>
    byte.toString(16).padStart(2, "0"),
  ).join("")}`;
  const metadata = {
    customer_email: input.customer_email,
    plan: input.plan.toLowerCase(),
    created_at: new Date().toISOString(),
  };
  try {
    await c.env.API_KEYS.put(apiKey, JSON.stringify(metadata));
  } catch (error) {
    console.error("API key issuance failed while saving key metadata", error);
    return c.json({ error: "Could not save the API key" }, 503);
  }

  return c.json(
    { api_key: apiKey, ...metadata },
    201,
    { "Cache-Control": "no-store" },
  );
});

app.get("/llms.txt", (c) =>
  c.text(
    `# AgentGuard UK & Sanitizer API

Base URL: ${publicOrigin(c)}
Machine-readable security sanitization and UK company compliance checks.
Protocol: x402 HTTP 402 micropayments. Network: Base mainnet (eip155:8453).
Payment token: USDC. Send JSON with Content-Type: application/json.
An unpaid request returns HTTP 402 with x402 payment requirements; retry with a valid payment.
Alternatively send Authorization: Bearer <token> for a token stored as a key in the API_KEYS KV namespace.

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

## POST /v1/uk-deep-kyb — $0.15 USDC (150000 atomic units)
Input JSON: {"company_number":"01234567"}
Output JSON: {"verified":true,"kyb_pass":true,"risk_score":0,"risk_flags":[],"company_name":"Example Ltd","status":"active","active_directors_count":2,"psc_count":1,"cached":false,"checked_at":"ISO-8601"}
Checks the company profile, active officers, and persons with significant control in parallel.
Successful Companies House responses are cached for six hours.

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
    serverUrl: publicOrigin(c),
    description:
      "AgentGuard sanitization and UK company verification tools. Calls accept a valid Authorization: Bearer API key or x402 USDC payments on Base (eip155:8453).",
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
      {
        name: "uk_deep_kyb",
        description:
          "Assess UK company status, active directors, PSC records, insolvency, and overdue accounts. Price: $0.15 USDC (150000 atomic units).",
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
            price: prices.deepKyb.decimal,
            atomicUnits: prices.deepKyb.amount,
            httpStatus: 402,
            endpoint: "POST /v1/uk-deep-kyb",
            bearerApiKeySupported: true,
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
      bearerApiKey: "Authorization: Bearer <token> (API_KEYS KV)",
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
        "AI agent text sanitization and UK company checks protected by x402 USDC payments on Base. A valid Authorization: Bearer API key bypasses x402.",
    },
    servers: [{ url: publicOrigin(c) }],
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
      "/v1/uk-deep-kyb": {
        post: {
          summary: "Run deep UK company KYB checks",
          description: "Price: $0.15 USDC (150000 atomic units), Base. Valid Bearer API keys bypass payment.",
          ...paidOperation(
            "ukDeepKyb",
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
                kyb_pass: { type: "boolean" },
                risk_score: { type: "integer", minimum: 0, maximum: 100 },
                risk_flags: { type: "array", items: { type: "string" } },
                company_name: { type: "string" },
                status: { type: "string" },
                active_directors_count: { type: "integer", minimum: 0 },
                psc_count: { type: "integer", minimum: 0 },
                cached: { type: "boolean" },
                checked_at: { type: "string", format: "date-time" },
              },
              required: [
                "verified",
                "kyb_pass",
                "risk_score",
                "risk_flags",
                "company_name",
                "status",
                "active_directors_count",
                "psc_count",
                "cached",
                "checked_at",
              ],
            },
          ),
        },
      },
    },
    components: {
      securitySchemes: {
        BearerAPIKey: {
          type: "http",
          scheme: "bearer",
          description:
            "Optional API key stored in the API_KEYS KV namespace. A valid key bypasses x402 payment.",
        },
      },
      schemas: {
        X402Payment: {
          type: "object",
          description:
            "Requests without a valid Bearer API key return HTTP 402 and a PAYMENT-REQUIRED header containing x402 requirements for exact USDC on Base (eip155:8453).",
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
    security: [{}, { BearerAPIKey: [] }],
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
  const authorization = c.req.header("Authorization");
  const bearer = authorization?.match(/^Bearer\s+(\S+)$/i)?.[1];
  if (bearer && c.env.API_KEYS) {
    try {
      if ((await c.env.API_KEYS.get(bearer)) !== null) return next();
    } catch (error) {
      console.error("API key lookup failed; requiring x402 payment", error);
    }
  }

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

app.post("/v1/uk-deep-kyb", async (c) => {
  const input = await readJson(c);
  if (!input || typeof input.company_number !== "string") {
    return c.json({ error: "Expected JSON field: company_number (string)" }, 400);
  }
  const result = await verifyDeepKyb(input.company_number, c.env);
  return c.json(result.body, result.status);
});

async function readJson(c: Context<{ Bindings: Env }>) {
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

function publicOrigin(c: Context<{ Bindings: Env }>): string {
  try {
    const origin = new URL(c.req.url).origin;
    return origin === "null" ? DEFAULT_PUBLIC_ORIGIN : origin;
  } catch {
    return DEFAULT_PUBLIC_ORIGIN;
  }
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
  env: Env,
): Promise<CompanyResult> {
  const checkedAt = new Date().toISOString();
  if (!/^[A-Za-z0-9]{1,8}$/.test(companyNumber)) {
    return {
      status: 400,
      body: { error: "Invalid UK company number format", checked_at: checkedAt },
    };
  }
  const resource = await fetchCompanyResource(companyNumber, "", env);
  if (resource.status === 503) {
    return {
      status: 503,
      body: isRecord(resource.data)
        ? { ...resource.data, checked_at: checkedAt }
        : { error: "Companies House API key is not configured", checked_at: checkedAt },
    };
  }
  if (resource.status === 404) {
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
  if (resource.status !== 200) {
    return {
      status: resource.status === 429 ? 503 : 502,
      body: {
        error: "Companies House API returned an unsuccessful response",
        upstream_status: resource.status,
        checked_at: checkedAt,
      },
    };
  }
  if (!isRecord(resource.data)) {
    return {
      status: 502,
      body: { error: "Companies House API returned an invalid profile", checked_at: checkedAt },
    };
  }

  const profile = resource.data;
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

async function verifyDeepKyb(
  companyNumber: string,
  env: Env,
): Promise<CompanyResult> {
  const checkedAt = new Date().toISOString();
  const normalizedNumber = companyNumber.toUpperCase();
  if (!/^[A-Za-z0-9]{1,8}$/.test(companyNumber)) {
    return {
      status: 400,
      body: { error: "Invalid UK company number format", checked_at: checkedAt },
    };
  }

  const [profileResult, officersResult, pscResult] = await Promise.all([
    fetchCompanyResource(normalizedNumber, "", env),
    fetchCompanyResource(normalizedNumber, "officers?items_per_page=100", env),
    fetchCompanyResource(
      normalizedNumber,
      "persons-with-significant-control?items_per_page=100",
      env,
    ),
  ]);
  if (profileResult.status === 503) {
    return {
      status: 503,
      body: { error: "Companies House API key is not configured", checked_at: checkedAt },
    };
  }
  if (profileResult.status === 404) {
    return {
      status: 404,
      body: {
        verified: false,
        kyb_pass: false,
        error: "Company not found",
        company_number: normalizedNumber,
        checked_at: checkedAt,
      },
    };
  }
  const failedResult = [profileResult, officersResult, pscResult].find(
    (result, index) =>
      result.status !== 200 &&
      !(index > 0 && result.status === 404),
  );
  if (failedResult) {
    return {
      status: failedResult.status === 429 ? 503 : 502,
      body: {
        error: "Companies House returned an unsuccessful deep KYB response",
        upstream_status: failedResult.status,
        checked_at: checkedAt,
      },
    };
  }
  if (!isRecord(profileResult.data)) {
    return {
      status: 502,
      body: { error: "Companies House returned an invalid company profile", checked_at: checkedAt },
    };
  }

  const profile = profileResult.data;
  const officers = officersResult.status === 404 ? [] : resourceItems(officersResult.data);
  const persons = pscResult.status === 404 ? [] : resourceItems(pscResult.data);
  const activeDirectors = officers.filter(
    (officer) =>
      typeof officer.officer_role === "string" &&
      /\bdirector\b/i.test(officer.officer_role) &&
      !officer.resigned_on,
  ).length;
  const activePscs = persons.filter((person) => !person.ceased_on).length;
  const companyStatus =
    typeof profile.company_status === "string" ? profile.company_status : "unknown";
  const riskFlags: string[] = [];
  let riskScore = 0;
  const addRisk = (flag: string, score: number) => {
    riskFlags.push(flag);
    riskScore += score;
  };
  if (companyStatus !== "active") addRisk("INACTIVE_STATUS", 35);
  if (profile.has_insolvency_history === true) {
    addRisk("INSOLVENCY_HISTORY", 40);
  } else if (profile.has_insolvency_history !== false) {
    addRisk("INSOLVENCY_STATUS_UNKNOWN", 20);
  }
  if (activeDirectors === 0) addRisk("NO_ACTIVE_DIRECTORS", 20);
  if (activePscs === 0) addRisk("NO_PSC_DECLARED", 10);
  const accounts = isRecord(profile.accounts) ? profile.accounts : {};
  const nextAccountsDue =
    typeof accounts.next_due === "string" ? Date.parse(accounts.next_due) : Number.NaN;
  if (
    accounts.overdue === true ||
    (Number.isFinite(nextAccountsDue) && nextAccountsDue < Date.now())
  ) {
    addRisk("OVERDUE_ACCOUNTS", 15);
  }
  riskScore = Math.min(100, riskScore);

  return {
    status: 200,
    body: {
      verified: true,
      kyb_pass:
        companyStatus === "active" &&
        profile.has_insolvency_history === false &&
        activeDirectors > 0 &&
        riskScore < 30,
      risk_score: riskScore,
      risk_flags: riskFlags,
      company_name:
        typeof profile.company_name === "string" ? profile.company_name : "",
      status: companyStatus,
      active_directors_count: activeDirectors,
      psc_count: activePscs,
      cached:
        profileResult.cached && officersResult.cached && pscResult.cached,
      checked_at: checkedAt,
    },
  };
}

function resourceItems(data: unknown): Record<string, unknown>[] {
  if (!isRecord(data) || !Array.isArray(data.items)) return [];
  return data.items.filter(isRecord);
}

async function fetchCompanyResource(
  companyNumber: string,
  resourcePath: string,
  env: Env,
): Promise<CompanyResource> {
  if (!isConfigured(env.COMPANIES_HOUSE_API_KEY)) {
    return {
      status: 503,
      data: { error: "Companies House API key is not configured" },
      cached: false,
    };
  }

  const normalizedNumber = companyNumber.toUpperCase();
  const cacheKey = `companies-house:${normalizedNumber}:${resourcePath || "profile"}`;
  if (env.KYB_CACHE) {
    try {
      const cachedData = await env.KYB_CACHE.get(cacheKey, "json");
      if (isRecord(cachedData)) {
        if (cachedData.__not_found === true) {
          return { status: 404, data: cachedData, cached: true };
        }
        return { status: 200, data: cachedData, cached: true };
      }
    } catch (error) {
      console.warn("Companies House cache read failed; fetching upstream", error);
    }
  }

  let response: Response;
  try {
    const suffix = resourcePath ? `/${resourcePath}` : "";
    response = await fetch(
      `${COMPANY_API}${encodeURIComponent(normalizedNumber)}${suffix}`,
      {
        headers: {
          Authorization: `Basic ${btoa(`${env.COMPANIES_HOUSE_API_KEY}:`)}`,
          Accept: "application/json",
        },
      },
    );
  } catch (error) {
    console.error("Companies House API request failed", error);
    return {
      status: 502,
      data: { error: "Companies House API request failed" },
      cached: false,
    };
  }

  if (!response.ok) {
    if (response.status === 404 && env.KYB_CACHE) {
      try {
        await env.KYB_CACHE.put(cacheKey, JSON.stringify({ __not_found: true }), {
          expirationTtl: KYB_CACHE_TTL_SECONDS,
        });
      } catch (error) {
        console.warn("Companies House not-found cache write failed", error);
      }
    }
    return {
      status: response.status,
      data: { error: "Companies House API returned an unsuccessful response" },
      cached: false,
    };
  }

  let data: unknown;
  try {
    data = await response.json();
  } catch (error) {
    console.error("Companies House API returned invalid JSON", error);
    return {
      status: 502,
      data: { error: "Companies House API returned invalid JSON" },
      cached: false,
    };
  }
  if (!isRecord(data)) {
    return {
      status: 502,
      data: { error: "Companies House API returned an invalid response" },
      cached: false,
    };
  }

  if (env.KYB_CACHE) {
    try {
      await env.KYB_CACHE.put(cacheKey, JSON.stringify(data), {
        expirationTtl: KYB_CACHE_TTL_SECONDS,
      });
    } catch (error) {
      console.warn("Companies House cache write failed", error);
    }
  }
  return { status: 200, data, cached: false };
}

export default {
  fetch: app.fetch,
} satisfies ExportedHandler<Env>;
