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

type AuditReceipt = {
  audit_id: string;
  timestamp: string;
  company_number: string;
  company_status: string;
  insolvency_flag: boolean | null;
  sanitized: true;
};

const BASE_NETWORK: `${string}:${string}` = "eip155:8453";
const COMPANY_API = "https://api.company-information.service.gov.uk/company/";
const PLACEHOLDER = /^\[PASTE_.+_HERE\]$/;
const MAX_TEXT_LENGTH = 50_000;
const KYB_CACHE_TTL_SECONDS = 6 * 60 * 60;
const FREE_DAILY_LIMIT = 5;
const FREE_COUNTER_TTL_SECONDS = 24 * 60 * 60;
const AUDIT_RECEIPT_TTL_SECONDS = 30 * 24 * 60 * 60;
const FREE_UPGRADE_URL = "https://kybguard.uk/checkout/starter";
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

const checkoutPlans = {
  starter: { amount: 2900, credits: 5000, label: "Starter", mode: "subscription" },
  pro: { amount: 9900, credits: 25000, label: "Pro", mode: "subscription" },
  agency: { amount: 19900, credits: 75000, label: "Agency", mode: "subscription" },
  payg: { amount: 1500, credits: 1000, label: "Pay-As-You-Go", mode: "payment" },
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
  if (
    planName !== "starter" &&
    planName !== "pro" &&
    planName !== "agency" &&
    planName !== "payg"
  ) {
    return c.json({ error: "Plan must be starter, pro, agency, or payg" }, 400);
  }

  const stripeSecret = c.env.STRIPE_SECRET_KEY;
  if (!stripeSecret) return c.json({ error: "Stripe is not configured" }, 503);
  const plan = checkoutPlans[planName];
  const form = new URLSearchParams({
    mode: plan.mode,
    "allowed_payment_method_types[0]": "card",
    "line_items[0][price_data][currency]": "gbp",
    "line_items[0][price_data][unit_amount]": String(plan.amount),
    "line_items[0][price_data][product_data][name]":
      plan.mode === "subscription"
        ? `AgentGuard UK ${plan.label} (${plan.credits.toLocaleString("en-GB")} requests/mo)`
        : `AgentGuard UK ${plan.label} (${plan.credits.toLocaleString("en-GB")} API credits)`,
    "line_items[0][quantity]": "1",
    "metadata[plan]": planName,
    "metadata[credits]": String(plan.credits),
    success_url:
      "https://kybguard.uk/checkout/success?session_id={CHECKOUT_SESSION_ID}",
    cancel_url: "https://kybguard.uk/",
  });
  if (plan.mode === "subscription") {
    form.set("line_items[0][price_data][recurring][interval]", "month");
  }

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
        (planName !== "starter" &&
          planName !== "pro" &&
          planName !== "agency" &&
          planName !== "payg") ||
        credits !== String(checkoutPlans[planName].credits) ||
        stripeObject.mode !== checkoutPlans[planName].mode ||
        typeof stripeObject.id !== "string"
      ) {
        return c.json({ error: "Checkout session is missing valid plan metadata" }, 400);
      }

      const plan = checkoutPlans[planName];
      const customerDetails = isRecord(stripeObject.customer_details)
        ? stripeObject.customer_details
        : {};
      const email =
        typeof customerDetails.email === "string"
          ? customerDetails.email
          : typeof stripeObject.customer_email === "string"
            ? stripeObject.customer_email
            : "";
      const subId =
        plan.mode === "subscription"
          ? subscriptionId(stripeObject.subscription)
          : null;
      const apiKey = await keyForStripeEvent(webhookSecret, event.id);
      await saveApiKey(
        c.env,
        {
          customer_email: email,
          plan: planName,
          created_at: new Date().toISOString(),
          credits: plan.credits,
          quota: plan.credits,
          requests_used: 0,
          ...(plan.mode === "subscription"
            ? { monthly_quota: plan.credits, subscription_id: subId }
            : {}),
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
            if (
              planName === "starter" ||
              planName === "pro" ||
              planName === "agency"
            ) {
              await c.env.API_KEYS.put(
                apiKey,
                JSON.stringify({
                  ...currentMetadata,
                  credits: checkoutPlans[planName].credits,
                  monthly_quota: checkoutPlans[planName].credits,
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
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <meta name="theme-color" content="#0b0f19">
  <meta name="description" content="Verify UK companies and sanitize AI inputs. Try the live sandbox with five free calls per IP each day.">
  <title>AgentGuard — AI Security & UK Company KYB</title>
  <style>
    :root{color-scheme:dark;--bg:#0b0f19;--surface:rgba(20,29,44,.78);--line:rgba(155,180,205,.18);--text:#edf4fb;--muted:#9aabbd;--emerald:#51e3ad;--cyan:#67d8f4}
    *{box-sizing:border-box}
    html,body{width:100%;max-width:100%;overflow-x:hidden}
    body{margin:0;min-height:100vh;background:radial-gradient(ellipse at 78% -15%,#15384a 0,transparent 38%),radial-gradient(ellipse at 8% 18%,#132843 0,transparent 32%),var(--bg);color:var(--text);font:16px/1.6 ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}
    a{color:var(--cyan);text-decoration:none}a:hover{text-decoration:underline}
    .wrap{width:min(1120px,calc(100% - 40px));margin:0 auto}
    header{padding:18px 0;border-bottom:1px solid var(--line);background:#0b0f19b8;backdrop-filter:blur(16px)}
    nav{display:flex;align-items:center;justify-content:space-between;gap:20px}
    .brand{font-weight:800;letter-spacing:.12em;color:var(--text)}
    .navlinks,.doclinks{display:flex;gap:20px;flex-wrap:wrap;font-size:.92rem}
    main{padding:54px 0 64px}
    .hero{max-width:790px}
    .eyebrow{color:var(--emerald);font-size:.78rem;font-weight:800;letter-spacing:.15em;text-transform:uppercase}
    h1{font-size:clamp(2.5rem,8vw,5rem);line-height:1.02;letter-spacing:-.06em;margin:14px 0 18px}
    h2{font-size:clamp(1.45rem,4vw,2rem);line-height:1.2;letter-spacing:-.03em;margin:0 0 10px}
    h3{line-height:1.25}
    .lead{max-width:700px;color:#c0cfdd;font-size:clamp(1rem,2.4vw,1.18rem)}
    .status{display:inline-flex;align-items:center;gap:9px;padding:6px 12px;border:1px solid #51e3ad45;border-radius:999px;background:#51e3ad10;color:var(--emerald);font-size:.86rem;font-weight:750}
    .dot{width:8px;height:8px;background:currentColor;border-radius:50%;box-shadow:0 0 12px currentColor}
    .actions{display:flex;gap:12px;flex-wrap:wrap;margin:24px 0 0}
    .button,button{display:inline-flex;align-items:center;justify-content:center;min-height:44px;padding:10px 16px;border:1px solid var(--line);border-radius:11px;background:#ffffff08;color:var(--text);font:inherit;font-weight:700;text-align:center;cursor:pointer}
    .button.primary,button.primary{background:var(--emerald);border-color:var(--emerald);color:#062018}
    button:disabled{opacity:.65;cursor:wait}
    section{margin-top:54px;min-width:0}
    .section-note{color:var(--muted);margin:0 0 18px}
    .glass{min-width:0;border:1px solid var(--line);border-radius:18px;background:linear-gradient(145deg,rgba(24,39,55,.86),rgba(14,21,34,.82));box-shadow:0 20px 55px #0003;backdrop-filter:blur(14px)}
    .demo-layout{display:grid;grid-template-columns:minmax(0,.92fr) minmax(0,1.08fr);gap:16px}
    .demo-form,.demo-result{min-width:0;padding:20px}
    .demo-form-grid{display:grid;grid-template-columns:1fr;gap:14px}
    label{display:block;margin-bottom:6px;color:#c8d6e2;font-size:.9rem;font-weight:650}
    input,select,textarea{display:block;width:100%;max-width:100%;min-height:46px;padding:11px 12px;border:1px solid var(--line);border-radius:10px;background:#090e18;color:var(--text);font:inherit}
    textarea{min-height:112px;resize:vertical}
    input:focus,select:focus,textarea:focus,button:focus-visible,a:focus-visible{outline:2px solid var(--cyan);outline-offset:2px}
    .demo-form button{width:100%;margin-top:14px}
    .demo-status{min-height:1.5em;margin:12px 0 0;color:var(--muted);font-size:.9rem}
    .result-head{display:flex;justify-content:space-between;gap:12px;align-items:center;margin-bottom:8px}
    .result-head strong{color:var(--cyan)}
    pre{display:block;width:100%;max-width:100%;overflow-x:auto;overscroll-behavior-x:contain;margin:10px 0 0;padding:16px;border:1px solid var(--line);border-radius:12px;background:#070b12;color:#d9e8f4;font:13px/1.55 ui-monospace,SFMono-Regular,Consolas,monospace;white-space:pre}
    pre code{display:block;width:max-content;min-width:100%;max-width:100%;overflow-x:auto;white-space:pre}
    .pricing-grid{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:12px}
    .price-card{display:flex;min-width:0;flex-direction:column;align-items:flex-start;padding:18px}
    .price-card h3{margin:5px 0;font-size:1.05rem}
    .price-card p{flex:1;margin:4px 0 14px;color:var(--muted);font-size:.9rem}
    .price{color:var(--emerald);font-size:1.45rem;font-weight:850;letter-spacing:-.04em}
    .price-card .button{width:100%;margin-top:auto}
    .price-card.featured{border-color:#51e3ad70;box-shadow:0 0 28px #51e3ad12}
    .microcopy{color:var(--muted);font-size:.9rem}
    .doclinks{gap:12px}
    .doclinks a{padding:7px 10px;border:1px solid var(--line);border-radius:9px;background:#ffffff06}
    footer{padding:24px 0 38px;border-top:1px solid var(--line);color:var(--muted);font-size:.9rem}
    [hidden]{display:none!important}
    @media(max-width:1000px){.pricing-grid{grid-template-columns:repeat(2,minmax(0,1fr))}}
    @media(max-width:767px){.wrap{width:calc(100% - 32px)}header{padding:14px 0}nav{align-items:flex-start;flex-direction:column;gap:10px}.navlinks{gap:12px}main{padding:38px 0 48px}.actions{align-items:stretch;flex-direction:column}.actions .button{width:100%}.demo-layout,.demo-form-grid,.pricing-grid{grid-template-columns:1fr}section{margin-top:40px}.demo-form,.demo-result{padding:16px}.price-card{padding:17px}.doclinks{flex-direction:column;align-items:stretch}.doclinks a{text-align:center}}
  </style>
</head>
<body>
  <header><nav class="wrap" aria-label="Main navigation">
    <a class="brand" href="${origin}/">AGENTGUARD</a>
    <div class="navlinks"><a href="#live-demo">Live demo</a><a href="#pricing">Pricing</a><a href="${origin}/bulk-check">Bulk screening</a><a href="${origin}/templates">n8n templates</a><a href="#docs">Docs</a></div>
  </nav></header>
  <main class="wrap">
    <div class="hero">
      <span class="status"><span class="dot" aria-hidden="true"></span> Live status: Operational</span>
      <p class="eyebrow">AI security · UK company KYB</p>
      <h1>Trust the input.<br>Verify the business.</h1>
      <p class="lead">Sanitize agent-bound text and check UK companies against live Companies House records. Start in the browser with five free calls per IP each day; no signup required.</p>
      <div class="actions"><a class="button primary" href="#live-demo">Try the live sandbox</a><a class="button" href="#pricing">Explore pricing</a></div>
    </div>

    <section id="live-demo" aria-labelledby="demo-title">
      <p class="eyebrow">Interactive live sandbox</p>
      <h2 id="demo-title">Make a real API call</h2>
      <p class="section-note">Try company verification or PII-safe sanitization. The five-call daily allowance is shared across these endpoints for your IP.</p>
      <div class="demo-layout">
        <form class="glass demo-form" id="sandbox-form">
          <div class="demo-form-grid">
            <div><label for="demo-action">Choose an endpoint</label>
              <select id="demo-action"><option value="verify">Verify a UK company</option><option value="sanitize">Sanitize text</option></select>
            </div>
            <div id="company-field"><label for="demo-company">Company number</label>
              <input id="demo-company" value="00445790" autocomplete="off" inputmode="text">
            </div>
            <div id="sanitize-field" hidden><label for="demo-text">Text to sanitize</label>
              <textarea id="demo-text">Contact test@example.com</textarea>
            </div>
          </div>
          <button class="primary" id="demo-submit" type="submit">Run free request</button>
          <p class="demo-status" id="demo-status" aria-live="polite">Five free requests per IP each day. No API key needed.</p>
        </form>
        <div class="glass demo-result">
          <div class="result-head"><strong>Live response</strong><span class="microcopy">JSON</span></div>
          <pre><code id="demo-output">Select an endpoint and run a request.</code></pre>
        </div>
      </div>
    </section>

    <section id="pricing" aria-labelledby="pricing-title">
      <p class="eyebrow">Flexible access</p>
      <h2 id="pricing-title">Choose how you build</h2>
      <div class="pricing-grid">
        <article class="glass price-card"><span class="microcopy">No signup</span><h3>Free Sandbox</h3><div class="price">Free</div><p>5 calls per IP per day across sanitize and verification.</p><a class="button" href="#live-demo">Try it now</a></article>
        <article class="glass price-card featured"><span class="microcopy">One-time pack</span><h3>Pay-As-You-Go</h3><div class="price">£15</div><p>1,000 API credits. Pay once, no monthly commitment.</p><a class="button primary" href="${origin}/checkout/payg">Get 1,000 credits</a></article>
        <article class="glass price-card"><span class="microcopy">Monthly plan</span><h3>Starter</h3><div class="price">£29<span class="microcopy"> / mo</span></div><p>5,000 requests per month for growing projects.</p><a class="button" href="${origin}/checkout/starter">Choose Starter</a></article>
        <article class="glass price-card"><span class="microcopy">Monthly plan</span><h3>Pro</h3><div class="price">£99<span class="microcopy"> / mo</span></div><p>25,000 requests per month for production teams.</p><a class="button" href="${origin}/checkout/pro">Choose Pro</a></article>
        <article class="glass price-card"><span class="microcopy">Agency partner</span><h3>Agency</h3><div class="price">£199<span class="microcopy"> / mo</span></div><p>75,000 calls per month for client portfolios.</p><a class="button" href="${origin}/checkout/agency">Choose Agency</a></article>
        <article class="glass price-card"><span class="microcopy">Agent-native</span><h3>Autonomous x402</h3><div class="price">USDC</div><p>Per-call Base micropayments for autonomous agents.</p><a class="button" href="${origin}/llms.txt">Explore x402</a></article>
      </div>
    </section>

    <section id="docs" aria-labelledby="docs-title">
      <p class="eyebrow">Developer resources</p>
      <h2 id="docs-title">Built for developers and agents</h2>
      <p class="section-note">USDC payments use Base mainnet (eip155:8453). Valid Bearer API keys are also supported.</p>
      <div class="doclinks"><a href="${origin}/llms.txt">llms.txt</a><a href="${origin}/.well-known/mcp.json">MCP manifest</a><a href="${origin}/openapi.json">OpenAPI reference</a><a href="${origin}/sitemap.xml">XML sitemap</a></div>
    </section>
  </main>
  <footer><div class="wrap">AgentGuard UK · Secure input, verified business · Base USDC x402 · <a href="${origin}/bulk-check">Bulk screening</a> · <a href="${origin}/templates">n8n templates</a></div></footer>
  <script>
    const sandboxForm = document.getElementById("sandbox-form");
    const demoAction = document.getElementById("demo-action");
    const companyField = document.getElementById("company-field");
    const sanitizeField = document.getElementById("sanitize-field");
    const demoOutput = document.getElementById("demo-output");
    const demoStatus = document.getElementById("demo-status");
    const demoSubmit = document.getElementById("demo-submit");
    const syncSandboxFields = () => {
      const sanitizing = demoAction.value === "sanitize";
      companyField.hidden = sanitizing;
      sanitizeField.hidden = !sanitizing;
    };
    demoAction.addEventListener("change", syncSandboxFields);
    sandboxForm.addEventListener("submit", async (event) => {
      event.preventDefault();
      const sanitizing = demoAction.value === "sanitize";
      const endpoint = sanitizing ? "/v1/sanitize" : "/v1/verify-uk-company";
      const payload = sanitizing
        ? { text: document.getElementById("demo-text").value, strip_pii: true }
        : { company_number: document.getElementById("demo-company").value.trim() };
      demoSubmit.disabled = true;
      demoStatus.textContent = "Sending request...";
      demoOutput.textContent = "";
      try {
        const response = await fetch(endpoint, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(payload)
        });
        const responseText = await response.text();
        let result;
        try {
          result = JSON.parse(responseText);
        } catch {
          result = { error: responseText || "The API returned an empty response." };
        }
        demoOutput.textContent = JSON.stringify(result, null, 2);
        const remaining = response.headers.get("X-Free-Remaining");
        demoStatus.textContent = remaining === null
          ? (response.status === 402 ? "Daily free allowance used. Choose a paid option or retry with x402." : "HTTP " + response.status)
          : "HTTP " + response.status + " · " + remaining + " free calls remaining today";
      } catch (error) {
        demoOutput.textContent = JSON.stringify({
          error: error instanceof Error ? error.message : String(error)
        }, null, 2);
        demoStatus.textContent = "Request failed. Check your connection and try again.";
      } finally {
        demoSubmit.disabled = false;
      }
    });
  </script>
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

app.get("/audit/:audit_id", async (c) => {
  const auditId = c.req.param("audit_id");
  if (!/^[a-f0-9]{64}$/i.test(auditId)) return c.notFound();
  if (!c.env.KYB_CACHE) {
    return c.json({ error: "Audit receipt storage is not configured" }, 503);
  }

  let storedReceipt: unknown;
  try {
    storedReceipt = await c.env.KYB_CACHE.get(`audit:${auditId}`, "json");
  } catch (error) {
    console.error("Audit receipt lookup failed", error);
    return c.json({ error: "Audit receipt is temporarily unavailable" }, 503);
  }
  if (!isAuditReceipt(storedReceipt, auditId)) return c.notFound();

  const checkStatus =
    storedReceipt.company_status.toLowerCase() === "active" &&
    storedReceipt.insolvency_flag === false
      ? "PASS"
      : "REVIEW";
  const receiptResponse = {
    audit_id: storedReceipt.audit_id,
    timestamp: storedReceipt.timestamp,
    company_number: storedReceipt.company_number,
    company_status: storedReceipt.company_status,
    insolvency_flag: storedReceipt.insolvency_flag,
    sanitized: storedReceipt.sanitized,
    check_status: checkStatus,
  };
  const acceptsJson = c.req.header("Accept")?.split(",").some(
    (mediaRange) =>
      mediaRange.split(";")[0].trim().toLowerCase() === "application/json",
  );
  if (acceptsJson) {
    return c.json(receiptResponse);
  }

  const insolvencyStatus =
    storedReceipt.insolvency_flag === false
      ? "No insolvency recorded"
      : storedReceipt.insolvency_flag === true
        ? "Insolvency recorded"
        : "Status unavailable";
  return c.html(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Compliance audit receipt</title><style>
body{margin:0;min-height:100vh;display:grid;place-items:center;padding:24px;background:#0b1220;color:#edf4ff;font:16px/1.6 system-ui,sans-serif}
main{width:min(100%,600px);padding:32px;border:1px solid #25344a;border-radius:18px;background:#121d2e}
.badge{display:inline-block;padding:5px 12px;border-radius:999px;font-weight:750}.pass{background:#123a2d;color:#57e3ad}.review{background:#49351b;color:#ffd27a}
dt{color:#a9b8cb}dd{margin:0 0 14px;overflow-wrap:anywhere}
</style></head><body><main>
<span class="badge ${checkStatus === "PASS" ? "pass" : "review"}">${checkStatus}</span>
<h1>Compliance audit receipt</h1>
<dl><dt>Verified at</dt><dd>${escapeHtml(storedReceipt.timestamp)}</dd>
<dt>Company number</dt><dd>${escapeHtml(storedReceipt.company_number)}</dd>
<dt>Company status</dt><dd>${escapeHtml(storedReceipt.company_status)}</dd>
<dt>Insolvency check</dt><dd>${escapeHtml(insolvencyStatus)}</dd>
<dt>Sanitized</dt><dd>Yes</dd>
<dt>Audit ID</dt><dd>${escapeHtml(storedReceipt.audit_id)}</dd></dl>
<footer style="margin-top:24px;padding-top:18px;border-top:1px solid #25344a;color:#a9b8cb">
<p>Verified in real time against UK Companies House by KYBGuard — Run 5 free checks or get an API key at kybguard.uk</p>
<p><a href="https://kybguard.uk/">Run free checks</a> · <a href="https://kybguard.uk/#pricing">Get an API key</a></p>
</footer>
</main></body></html>`);
});

function renderContentPage(
  title: string,
  description: string,
  content: string,
  origin: string,
): string {
  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
<meta name="description" content="${escapeHtml(description)}"><meta name="theme-color" content="#0b0f19">
<title>${escapeHtml(title)} | KYBGuard</title>
<style>
:root{color-scheme:dark;--bg:#0b0f19;--panel:#121d2e;--line:#25344a;--text:#edf4fb;--muted:#a9b8cb;--emerald:#51e3ad;--cyan:#67d8f4}
*{box-sizing:border-box}html,body{margin:0;max-width:100%;overflow-x:hidden}body{background:var(--bg);color:var(--text);font:16px/1.65 system-ui,-apple-system,"Segoe UI",sans-serif}
a{color:var(--cyan);text-decoration:none}a:hover{text-decoration:underline}
.wrap{width:min(1040px,calc(100% - 32px));margin:auto}header{padding:16px 0;border-bottom:1px solid var(--line)}
nav,.navlinks,.actions,.links{display:flex;align-items:center;justify-content:space-between;gap:14px;flex-wrap:wrap}
.brand{font-weight:850;letter-spacing:.1em;color:var(--text)}.navlinks{justify-content:flex-end}
main{padding:clamp(28px,6vw,64px) 0}.eyebrow{color:var(--emerald);font-size:.8rem;font-weight:800;letter-spacing:.12em;text-transform:uppercase}
h1{font-size:clamp(2rem,6vw,3.8rem);line-height:1.08;letter-spacing:-.04em;margin:8px 0 14px}
h2{font-size:clamp(1.3rem,3vw,1.8rem);margin:30px 0 8px}p,li{color:#c3d0dd}
.panel{min-width:0;padding:clamp(18px,4vw,28px);border:1px solid var(--line);border-radius:16px;background:linear-gradient(145deg,#17263a,#101827);box-shadow:0 18px 48px #0003}
.button,button{display:inline-flex;align-items:center;justify-content:center;min-height:44px;padding:10px 15px;border:1px solid var(--line);border-radius:10px;background:#ffffff09;color:var(--text);font:inherit;font-weight:700;cursor:pointer}
.button.primary,button.primary{background:var(--emerald);color:#082218;border-color:var(--emerald)}
pre{max-width:100%;overflow:auto;white-space:pre-wrap;overflow-wrap:anywhere;padding:16px;border:1px solid var(--line);border-radius:11px;background:#070b12;color:#d9e8f4}
.muted{color:var(--muted)}footer{padding:22px 0 32px;border-top:1px solid var(--line);color:var(--muted)}
@media(max-width:680px){nav{align-items:flex-start;flex-direction:column}.navlinks{justify-content:flex-start;gap:10px}.actions{align-items:stretch;flex-direction:column}.actions .button{width:100%}}
</style></head>
<body><header><nav class="wrap"><a class="brand" href="${origin}/">KYBGUARD</a>
<div class="navlinks"><a href="${origin}/bulk-check">Bulk screening</a><a href="${origin}/templates">n8n templates</a><a href="${origin}/#pricing">Pricing</a><a href="${origin}/llms.txt">API docs</a></div>
</nav></header><main class="wrap"><article class="panel"><p class="eyebrow">KYBGuard · UK compliance tools</p>
<h1>${escapeHtml(title)}</h1><p class="muted">${escapeHtml(description)}</p>${content}
<div class="actions"><a class="button primary" href="${origin}/checkout/starter">Get an API key</a><a class="button" href="${origin}/bulk-check">Screen companies</a><a class="button" href="${origin}/templates">Browse templates</a></div>
</article></main><footer><div class="wrap">KYBGuard · <a href="${origin}/bulk-check">Bulk screening</a> · <a href="${origin}/templates">n8n templates</a> · <a href="${origin}/">Home</a></div></footer></body></html>`;
}

app.get("/bulk-check", (c) =>
  c.html(
    renderContentPage(
      "Bulk CSV UK Company Screener",
      "Screen up to 100 UK companies sequentially against Companies House and export enriched results.",
      `<p>Paste one company number per line or upload a CSV. Add a KYBGuard API key for larger batches; without one, the five free daily checks still apply.</p>
<div class="panel">
<label for="company-input">Company numbers or CSV content</label>
<textarea id="company-input" rows="9" placeholder="00445790&#10;00000006" spellcheck="false"></textarea>
<label for="csv-file">Or upload a .csv file</label><input id="csv-file" type="file" accept=".csv,text/csv">
<label for="api-key">API key (ag_... or kyb_live_...)</label>
<input id="api-key" type="password" autocomplete="off" placeholder="Paste your API key">
<div class="actions" style="margin-top:16px"><button class="primary" id="screen-button" type="submit" form="screen-form">Screen Companies</button><a class="button" href="${escapeHtml(publicOrigin(c))}/checkout/payg">Buy 1,000 Credits for £15</a></div>
<p class="muted">Your API key is used only in requests from this browser and is not saved by this page.</p>
</div>
<form id="screen-form"><progress id="screen-progress" value="0" max="1" style="width:100%;height:18px;margin-top:18px"></progress>
<p id="screen-status" role="status" aria-live="polite">Ready to screen up to 100 companies.</p></form>
<div class="actions"><h2 style="margin:0">Enriched results</h2><button id="download-csv" type="button" disabled>Download Enriched CSV</button></div>
<pre><code id="screen-results">Results will appear here as requests complete.</code></pre>
<style>
.panel label{display:block;margin:12px 0 6px;font-weight:700;color:#d5e0e9}
.panel textarea,.panel input{display:block;width:100%;max-width:100%;padding:12px;border:1px solid #25344a;border-radius:9px;background:#080e18;color:#edf4fb;font:inherit}
.panel textarea{resize:vertical;min-height:150px}.panel input[type=file]{padding:9px}
#screen-form{margin:0}#screen-status{min-height:1.5em}
.actions h2{flex:1}
</style>
<script>
const screenForm=document.getElementById("screen-form");
const input=document.getElementById("company-input");
const fileInput=document.getElementById("csv-file");
const apiKeyInput=document.getElementById("api-key");
const screenButton=document.getElementById("screen-button");
const progress=document.getElementById("screen-progress");
const statusText=document.getElementById("screen-status");
const output=document.getElementById("screen-results");
const downloadButton=document.getElementById("download-csv");
let results=[];
function parseCsv(text){
  const rows=[];let row=[];let value="";let quoted=false;
  for(let i=0;i<text.length;i++){
    const character=text[i];
    if(character==='"'){
      if(quoted&&text[i+1]==='"'){value+='"';i++}else{quoted=!quoted}
    }else if(character===","&&!quoted){row.push(value);value=""}
    else if((character==="\\n"||character==="\\r")&&!quoted){
      if(character==="\\r"&&text[i+1]==="\\n")i++;
      row.push(value);if(row.some((cell)=>cell.trim()))rows.push(row);row=[];value="";
    }else{value+=character}
  }
  if(quoted)throw new Error("The CSV has an unclosed quoted field.");
  if(value.length||row.length){row.push(value);if(row.some((cell)=>cell.trim()))rows.push(row)}
  const headers=(rows[0]||[]).map((cell)=>cell.replace(/^\\uFEFF/,"").trim().toLowerCase().replace(/[\\s-]+/g,"_"));
  const headerIndex=headers.findIndex((header)=>["company_number","companynumber","registration_number","number"].includes(header));
  const column=headerIndex<0?0:headerIndex;
  return rows.slice(headerIndex<0?0:1).map((cells)=>String(cells[column]||"").trim()).filter(Boolean);
}
fileInput.addEventListener("change",async()=>{
  const file=fileInput.files&&fileInput.files[0];if(!file)return;
  try{input.value=await file.text();statusText.textContent="Loaded "+file.name+"; review the rows and screen when ready."}
  catch{statusText.textContent="Could not read the selected CSV file."}
});
screenForm.addEventListener("submit",async(event)=>{
  event.preventDefault();let companyNumbers;
  try{companyNumbers=parseCsv(input.value)}
  catch(error){statusText.textContent=error instanceof Error?error.message:"Could not parse the input.";return}
  if(!companyNumbers.length){statusText.textContent="Enter at least one company number.";return}
  if(companyNumbers.length>100){statusText.textContent="Limit is 100 companies per batch; found "+companyNumbers.length+".";return}
  results=[];output.textContent="";downloadButton.disabled=true;screenButton.disabled=true;
  progress.max=companyNumbers.length;progress.value=0;
  const key=apiKeyInput.value.trim();let stoppedForPayment=false;
  for(let index=0;index<companyNumbers.length;index++){
    const companyNumber=companyNumbers[index];
    statusText.textContent="Screening "+(index+1)+" of "+companyNumbers.length+": "+companyNumber;
    try{
      const headers={"Content-Type":"application/json"};
      if(key)headers.Authorization="Bearer "+key;
      const response=await fetch("/v1/verify-uk-company",{method:"POST",headers,body:JSON.stringify({company_number:companyNumber})});
      const responseText=await response.text();let data;
      try{data=JSON.parse(responseText)}catch{data={error:responseText||"Invalid JSON response"}}
      results.push({
        company_number:companyNumber,company_name:data.company_name||"",status:data.status||"",
        insolvency_history:data.insolvency_history??"",verified:data.verified===true,
        http_status:response.status,error:response.ok?"":data.error||("HTTP "+response.status)
      });
      if(response.status===402){stoppedForPayment=true;progress.value=index+1;break}
    }catch(error){
      results.push({company_number:companyNumber,company_name:"",status:"",insolvency_history:"",verified:false,http_status:0,error:error instanceof Error?error.message:"Network request failed"});
    }
    progress.value=index+1;output.textContent=JSON.stringify(results,null,2);
  }
  output.textContent=JSON.stringify(results,null,2);downloadButton.disabled=results.length===0;
  screenButton.disabled=false;
  statusText.textContent=stoppedForPayment
    ?"Stopped at payment required. Add an API key or buy credits to continue; completed results are available to download."
    :"Finished "+results.length+" of "+companyNumbers.length+" company checks.";
});
function csvCell(value){
  let text=String(value??"");
  if(/^\\s*[=+\\-@]/.test(text))text="'"+text;
  return '"'+text.replace(/"/g,'""')+'"';
}
downloadButton.addEventListener("click",()=>{
  if(!results.length)return;
  const columns=["company_number","company_name","status","insolvency_history","verified","http_status","error"];
  const csv=[columns.map(csvCell).join(","),...results.map((result)=>columns.map((column)=>csvCell(result[column])).join(","))].join("\\r\\n");
  const url=URL.createObjectURL(new Blob([csv],{type:"text/csv;charset=utf-8"}));
  const link=document.createElement("a");link.href=url;link.download="kybguard-company-screening.csv";document.body.append(link);link.click();link.remove();setTimeout(()=>URL.revokeObjectURL(url),1000);
});
</script>`,
      escapeHtml(publicOrigin(c)),
    ),
  ),
);

const n8nUkKybWorkflow = {
  name: "KYBGuard UK Company Audit",
  nodes: [
    {
      parameters: {
        httpMethod: "POST",
        path: "kybguard-uk-kyb",
        responseMode: "onReceived",
        options: {},
      },
      id: "c4f4ad8e-70b4-4ba2-b9d3-77ca6a82a113",
      name: "Receive KYB request",
      type: "n8n-nodes-base.webhook",
      typeVersion: 2.1,
      position: [240, 300],
      webhookId: "kybguard-uk-kyb",
    },
    {
      parameters: {
        method: "POST",
        url: "https://api.kybguard.uk/v1/full-audit",
        sendHeaders: true,
        headerParameters: {
          parameters: [
            {
              name: "Authorization",
              value: "={{ 'Bearer ' + $env.KYBGUARD_API_KEY }}",
            },
            { name: "Content-Type", value: "application/json" },
          ],
        },
        sendBody: true,
        contentType: "json",
        specifyBody: "json",
        jsonBody:
          "={{ { company_number: $json.body.company_number, payload_text: $json.body.payload_text } }}",
        options: {},
      },
      id: "f3a198e7-2351-48fb-8d75-b093b86a8b7b",
      name: "Run KYBGuard full audit",
      type: "n8n-nodes-base.httpRequest",
      typeVersion: 4.2,
      position: [500, 300],
    },
    {
      parameters: {
        conditions: {
          options: {
            caseSensitive: false,
            leftValue: "",
            typeValidation: "strict",
            version: 2,
          },
          conditions: [
            {
              id: "check-company-status",
              leftValue: "={{ $json.company_verification.status }}",
              rightValue: "active",
              operator: { type: "string", operation: "notEquals" },
            },
            {
              id: "check-insolvency",
              leftValue: "={{ $json.company_verification.insolvency_history }}",
              rightValue: true,
              operator: { type: "boolean", operation: "equals" },
            },
          ],
          combinator: "or",
        },
        options: {},
      },
      id: "3a36a762-1ee3-4f69-87f2-63e6fbba9dc1",
      name: "Flag inactive or insolvent",
      type: "n8n-nodes-base.if",
      typeVersion: 2.2,
      position: [760, 300],
    },
  ],
  connections: {
    "Receive KYB request": {
      main: [[{ node: "Run KYBGuard full audit", type: "main", index: 0 }]],
    },
    "Run KYBGuard full audit": {
      main: [[{ node: "Flag inactive or insolvent", type: "main", index: 0 }]],
    },
  },
  active: false,
  settings: { executionOrder: "v1" },
  versionId: "f69e1f29-72bf-42e5-bb8b-b1b3cfa9d9f9",
  tags: [],
};

app.get("/templates/n8n-uk-kyb.json", (c) =>
  c.body(JSON.stringify(n8nUkKybWorkflow, null, 2), 200, {
    "Content-Type": "application/json; charset=utf-8",
    "Content-Disposition": 'attachment; filename="kybguard-n8n-uk-kyb.json"',
  }),
);

app.get("/templates", (c) =>
  c.html(
    renderContentPage(
      "No-code UK KYB workflow templates",
      "Connect n8n to UK company verification, audit receipts, and real-time compliance checks.",
      `<p>Import the ready-to-use n8n workflow, add your KYBGuard key as an environment variable, and receive a full audit for each webhook request.</p>
<h2>1. Download and import</h2><p><a class="button primary" href="/templates/n8n-uk-kyb.json">Download n8n UK KYB workflow JSON</a></p>
<p>In n8n, open <strong>Workflows → Import from File</strong> and select the downloaded JSON. The workflow adds a Webhook trigger, a KYBGuard full-audit request, and an IF node that flags inactive or insolvent companies.</p>
<h2>2. Add your API key</h2><p>Set <code>KYBGUARD_API_KEY</code> in the n8n runtime environment, then restart n8n. The HTTP Request node sends <code>Authorization: Bearer {{$env.KYBGUARD_API_KEY}}</code>. Keep this secret out of workflow exports and source control.</p>
<h2>3. Send a test request</h2><pre><code>curl -X POST https://YOUR_N8N_HOST/webhook/kybguard-uk-kyb \\
  -H 'Content-Type: application/json' \\
  --data '{"company_number":"00445790","payload_text":"Supplier onboarding review"}'</code></pre>
<p>The full audit response includes company verification, sanitized text, and a shareable audit receipt. Configure your downstream true/false branches to notify your compliance team or continue onboarding.</p>
<p class="muted">The workflow is inactive after import. Review the nodes, configure environment access in n8n, and activate it when ready.</p>`,
      escapeHtml(publicOrigin(c)),
    ),
  ),
);

const ukGuides: Record<string, { title: string; description: string; content: string }> = {
  "companies-house-mcp": {
    title: "How to Connect UK Companies House to Claude & Cursor via MCP",
    description:
      "Connect Claude or Cursor to KYBGuard's MCP tools for UK company verification and safer AI inputs.",
    content: `<p>KYBGuard exposes company verification and input sanitization as MCP tools. The local stdio bridge lets MCP-compatible clients call the API while keeping your API key in the client environment.</p>
<h2>Configure an MCP client</h2><p>Add the bridge to your Claude Desktop or Cursor MCP configuration and replace the example path with the location of your checkout.</p>
<pre><code>{
  "command": "node",
  "args": ["/path/to/agent-guard-api/mcp-server.mjs"],
  "env": {
    "AGENTGUARD_API_URL": "https://api.kybguard.uk",
    "AGENTGUARD_API_KEY": "YOUR_KYBGUARD_API_KEY"
  }
}</code></pre>
<h2>Verify a company</h2><p>Ask your client to verify a UK company by number. For beneficial ownership checks, use the deep KYB tool, which reports active directors and PSC counts alongside company status and risk flags.</p>
<p>Requests without a key can use the limited daily free sandbox; for repeatable workflows, use a paid API key or Base USDC x402 payments.</p>`,
  },
  "uk-kyb-api": {
    title: "Automated UK KYB & Beneficial Ownership (PSC) Verification API",
    description:
      "Automate UK company status, insolvency, director, and PSC checks with KYBGuard's API.",
    content: `<p>Automated Know Your Business screening can combine a Companies House profile check with officer and Persons with Significant Control (PSC) records. KYBGuard exposes a standard verification endpoint and a deeper KYB risk endpoint for onboarding flows.</p>
<h2>Verify a UK company</h2><pre><code>curl -X POST https://api.kybguard.uk/v1/verify-uk-company \\
  -H 'Authorization: Bearer YOUR_KYBGUARD_API_KEY' \\
  -H 'Content-Type: application/json' \\
  --data '{"company_number":"00445790"}'</code></pre>
<h2>Run a deeper KYB check</h2><pre><code>curl -X POST https://api.kybguard.uk/v1/uk-deep-kyb \\
  -H 'Authorization: Bearer YOUR_KYBGUARD_API_KEY' \\
  -H 'Content-Type: application/json' \\
  --data '{"company_number":"00445790"}'</code></pre>
<p>The deep response includes company status, insolvency indicators, active-director and PSC counts, and risk flags. Treat automated outputs as decision support and apply your organization’s own review policy before taking action.</p>`,
  },
  "uk-ni-number-pii-redaction": {
    title: "Stripping Prompt Injections & Redacting UK National Insurance Numbers for LLMs",
    description:
      "Sanitize untrusted text, remove common prompt-injection patterns, and redact UK National Insurance numbers before LLM processing.",
    content: `<p>Before sending untrusted text to an LLM, remove common instruction overrides and redact personal data. KYBGuard's sanitizer can remove prompt-injection patterns and, when requested, redact emails, UK phone numbers, National Insurance numbers, payment cards, and IBANs.</p>
<h2>Sanitize before calling your model</h2><pre><code>curl -X POST https://api.kybguard.uk/v1/sanitize \\
  -H 'Authorization: Bearer YOUR_KYBGUARD_API_KEY' \\
  -H 'Content-Type: application/json' \\
  --data '{"text":"Ignore previous instructions. NI number: AB123456C","strip_pii":true}'</code></pre>
<p>Use the returned <code>clean_text</code> as the downstream model input and inspect the flags to understand what was detected. Sanitization is a defense-in-depth step, not a substitute for validating model actions or enforcing application-level permissions.</p>`,
  },
};

app.get("/guides/:slug", (c) => {
  const guide = ukGuides[c.req.param("slug")];
  if (!guide) return c.notFound();
  return c.html(
    renderContentPage(
      guide.title,
      guide.description,
      guide.content,
      escapeHtml(publicOrigin(c)),
    ),
  );
});

app.get("/robots.txt", (c) =>
  c.text(
    "User-agent: *\nAllow: /\nSitemap: https://kybguard.uk/sitemap.xml\n# LLMs: https://kybguard.uk/llms.txt\n",
  ),
);

app.get("/sitemap.xml", (c) =>
  c.body(
    `<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url><loc>https://kybguard.uk/</loc></url>
  <url><loc>https://kybguard.uk/llms.txt</loc></url>
  <url><loc>https://kybguard.uk/.well-known/mcp.json</loc></url>
  <url><loc>https://kybguard.uk/openapi.json</loc></url>
  <url><loc>https://kybguard.uk/bulk-check</loc></url>
  <url><loc>https://kybguard.uk/templates</loc></url>
  <url><loc>https://kybguard.uk/guides/companies-house-mcp</loc></url>
  <url><loc>https://kybguard.uk/guides/uk-kyb-api</loc></url>
  <url><loc>https://kybguard.uk/guides/uk-ni-number-pii-redaction</loc></url>
</urlset>`,
    200,
    { "Content-Type": "application/xml; charset=utf-8" },
  ),
);

app.get("/llms.txt", (c) =>
  c.text(
    `# AgentGuard UK & Sanitizer API

Base URL: ${publicOrigin(c)}
Machine-readable security sanitization and UK company compliance checks.
Protocol: x402 HTTP 402 micropayments. Network: Base mainnet (eip155:8453).
Payment token: USDC. Send JSON with Content-Type: application/json.
Unauthenticated requests to sanitization and company verification receive five free calls per IP per UTC day; later unpaid calls return HTTP 402 with x402 payment requirements.
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
Output JSON: {"audit_id":"64-character SHA-256 hex","company_verification":{...},"sanitization":{...},"receipt_url":"https://kybguard.uk/audit/{audit_id}"}
Both checks run concurrently. A non-PII receipt is available at the receipt URL for 30 days.

## GET /audit/{audit_id}
Returns the verification receipt as JSON when Accept: application/json, otherwise as an HTML badge.

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
        "AI agent text sanitization and UK company checks with five free daily calls per IP on eligible endpoints, plus x402 USDC payments on Base. A valid Authorization: Bearer API key bypasses x402.",
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
          description: "Five unauthenticated free calls per IP per UTC day, then $0.005 USDC (5000 atomic units) on Base.",
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
          description: "Five unauthenticated free calls per IP per UTC day, then $0.02 USDC (20000 atomic units) on Base.",
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
                receipt_url: { type: "string", format: "uri" },
              },
              required: [
                "audit_id",
                "company_verification",
                "sanitization",
                "receipt_url",
              ],
            },
          ),
        },
      },
      "/audit/{audit_id}": {
        get: {
          operationId: "getAuditReceipt",
          summary: "Retrieve a compliance audit receipt",
          parameters: [
            {
              name: "audit_id",
              in: "path",
              required: true,
              schema: { type: "string", pattern: "^[a-f0-9]{64}$" },
            },
          ],
          responses: {
            "200": {
              description: "Non-PII verification receipt",
              content: {
                "application/json": { schema: { type: "object" } },
                "text/html": { schema: { type: "string" } },
              },
            },
            "404": { description: "Receipt not found or expired" },
            "503": { description: "Receipt storage is unavailable" },
          },
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
            "Sanitization and company verification allow five unauthenticated free calls per IP per UTC day. After the free quota, requests without a valid Bearer API key return HTTP 402 and a PAYMENT-REQUIRED header containing x402 requirements for exact USDC on Base (eip155:8453).",
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
  const isFreeSandboxRoute =
    c.req.method === "POST" &&
    (c.req.path === "/v1/sanitize" ||
      c.req.path === "/v1/verify-uk-company");
  const hasBearerAuthorization = /^Bearer(?:\s|$)/i.test(authorization ?? "");
  const hasPaymentHeader =
    c.req.raw.headers.has("PAYMENT-SIGNATURE") ||
    c.req.raw.headers.has("X-PAYMENT");

  if (
    isFreeSandboxRoute &&
    !hasBearerAuthorization &&
    !hasPaymentHeader &&
    c.env.KYB_CACHE
  ) {
    const ip = c.req.header("cf-connecting-ip") || "unknown";
    const day = new Date().toISOString().slice(0, 10).replace(/-/g, "_");
    const counterKey = `free_ip:${ip}:${day}`;
    let storedCount: string | null;
    try {
      storedCount = await c.env.KYB_CACHE.get(counterKey);
    } catch (error) {
      console.error("Free sandbox quota lookup failed", error);
      return c.json({ error: "Free sandbox quota is temporarily unavailable" }, 503);
    }

    if (storedCount !== null && !/^\d+$/.test(storedCount)) {
      console.error("Free sandbox quota counter contains an invalid value");
      return c.json({ error: "Free sandbox quota is temporarily unavailable" }, 503);
    }
    const count = storedCount === null ? 0 : Number(storedCount);
    if (!Number.isSafeInteger(count)) {
      console.error("Free sandbox quota counter exceeds the supported range");
      return c.json({ error: "Free sandbox quota is temporarily unavailable" }, 503);
    }
    if (count < FREE_DAILY_LIMIT) {
      const newCount = count + 1;
      try {
        await c.env.KYB_CACHE.put(counterKey, String(newCount), {
          expirationTtl: FREE_COUNTER_TTL_SECONDS,
        });
      } catch (error) {
        console.error("Free sandbox quota update failed", error);
        return c.json({ error: "Free sandbox quota is temporarily unavailable" }, 503);
      }

      c.header("X-Free-Remaining", String(FREE_DAILY_LIMIT - newCount));
      c.header("X-Upgrade-Url", FREE_UPGRADE_URL);
      return next();
    }
  }

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

  if (!c.env.KYB_CACHE) {
    return c.json({ error: "Audit receipt storage is not configured" }, 503);
  }
  const receipt: AuditReceipt = {
    audit_id: auditId,
    timestamp: checkedAt,
    company_number: companyNumber.toUpperCase(),
    company_status:
      typeof company.body.status === "string" ? company.body.status : "unknown",
    insolvency_flag:
      typeof company.body.insolvency_history === "boolean"
        ? company.body.insolvency_history
        : null,
    sanitized: true,
  };
  try {
    await c.env.KYB_CACHE.put(
      `audit:${auditId}`,
      JSON.stringify(receipt),
      { expirationTtl: AUDIT_RECEIPT_TTL_SECONDS },
    );
  } catch (error) {
    console.error("Audit receipt storage failed", error);
    return c.json({ error: "Could not store audit receipt" }, 503);
  }

  return c.json({
    audit_id: auditId,
    company_verification: company.body,
    sanitization,
    checked_at: checkedAt,
    receipt_url: `https://kybguard.uk/audit/${auditId}`,
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

function isAuditReceipt(value: unknown, auditId: string): value is AuditReceipt {
  return (
    isRecord(value) &&
    value.audit_id === auditId &&
    typeof value.timestamp === "string" &&
    typeof value.company_number === "string" &&
    typeof value.company_status === "string" &&
    (typeof value.insolvency_flag === "boolean" || value.insolvency_flag === null) &&
    value.sanitized === true
  );
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
