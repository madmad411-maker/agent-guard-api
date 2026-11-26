# AgentGuard UK & Sanitizer API

Real-time AI-agent input sanitization and UK Companies House verification, served as a Cloudflare Worker.

**Primary live API:** <https://api.kybguard.uk>

The API is also available at <https://kybguard.uk>.

**Network:** Base mainnet (`eip155:8453`)

**Payment:** USDC with x402 HTTP 402, or a valid Bearer API key stored in the `API_KEYS` KV namespace.

## Endpoints and pricing

| Endpoint | Purpose | Price per call |
| --- | --- | ---: |
| `POST /v1/sanitize` | Remove common prompt-injection content; optionally redact PII | $0.005 USDC |
| `POST /v1/verify-uk-company` | Check company status and insolvency history | $0.02 USDC |
| `POST /v1/full-audit` | Run sanitization and company verification together | $0.022 USDC |
| `POST /v1/uk-deep-kyb` | Check profile, officers, and PSC data with risk scoring | $0.15 USDC |

Payment goes to `0x74d0ff6d0912231fdd728fc5ddbeeed3bbfec92f`. An unpaid request returns `402 Payment Required` and a `PAYMENT-REQUIRED` header containing the x402 payment requirements. A valid `Authorization: Bearer <token>` whose token exists as a key in `API_KEYS` KV bypasses x402.

## Discovery

- [`/`](https://api.kybguard.uk/) — service status and endpoint list
- [`/llms.txt`](https://api.kybguard.uk/llms.txt) — agent-oriented usage documentation
- [`/.well-known/mcp.json`](https://api.kybguard.uk/.well-known/mcp.json) — tool manifest
- [`/openapi.json`](https://api.kybguard.uk/openapi.json) — OpenAPI 3.1 specification

## Request examples

All paid endpoints accept JSON with `Content-Type: application/json`.

### x402 payment flow

First request the endpoint without payment to receive the current challenge:

```sh
curl -i https://api.kybguard.uk/v1/sanitize \
  -H 'Content-Type: application/json' \
  --data '{"text":"untrusted input","strip_pii":true}'
```

The server responds with HTTP 402 and `PAYMENT-REQUIRED`. An x402-compatible client/wallet uses that challenge to construct and sign a payment payload. Send the resulting Base USDC payload in `PAYMENT-SIGNATURE` when retrying:

```sh
curl -i https://api.kybguard.uk/v1/sanitize \
  -H 'Content-Type: application/json' \
  -H 'PAYMENT-SIGNATURE: <base64-x402-payment-payload-from-your-client>' \
  --data '{"text":"untrusted input","strip_pii":true}'
```

`curl` does not create or sign the payment. Use an x402-compatible wallet/client to generate the header value; the challenge specifies the amount, network, token, and recipient.

### Bearer API key

Put a securely generated API key into the remote `API_KEYS` KV namespace as the KV key (the value can be any non-empty marker). Keep the key private and pass it in the authorization header:

```sh
export AGENTGUARD_API_KEY='<your-api-key>'

curl -i https://api.kybguard.uk/v1/sanitize \
  -H "Authorization: Bearer ${AGENTGUARD_API_KEY}" \
  -H 'Content-Type: application/json' \
  --data '{"text":"untrusted input","strip_pii":true}'
```

Other request bodies:

```sh
# Verify a UK company
curl https://api.kybguard.uk/v1/verify-uk-company \
  -H "Authorization: Bearer ${AGENTGUARD_API_KEY}" \
  -H 'Content-Type: application/json' \
  --data '{"company_number":"00445790"}'

# Full audit
curl https://api.kybguard.uk/v1/full-audit \
  -H "Authorization: Bearer ${AGENTGUARD_API_KEY}" \
  -H 'Content-Type: application/json' \
  --data '{"company_number":"00445790","payload_text":"untrusted input"}'

# Deep KYB
curl https://api.kybguard.uk/v1/uk-deep-kyb \
  -H "Authorization: Bearer ${AGENTGUARD_API_KEY}" \
  -H 'Content-Type: application/json' \
  --data '{"company_number":"00445790"}'
```

## MCP stdio bridge

The standalone `mcp-server.mjs` exposes the four API operations as MCP tools over stdio. It requires Node.js 18 or later and has no additional runtime dependencies.

1. Clone this repository and install dependencies:

   ```sh
   git clone https://github.com/madmad411-maker/agent-guard-api.git
   cd agent-guard-api
   npm ci
   ```

2. Add the server to your MCP client's configuration (Claude Desktop, Cursor, or another stdio MCP client). Replace the path with the absolute path to the checked-out file:

   ```json
   {
     "mcpServers": {
       "agentguard": {
         "command": "node",
         "args": ["/absolute/path/to/agent-guard-api/mcp-server.mjs"],
         "env": {
           "AGENTGUARD_API_URL": "https://api.kybguard.uk",
           "AGENTGUARD_API_KEY": "<your-api-key>"
         }
       }
     }
   }
   ```

   `AGENTGUARD_API_URL` is optional and defaults to `https://api.kybguard.uk`. `AGENTGUARD_API_KEY` is optional; without a valid API key, tool calls receive the x402 402 challenge. The bridge returns the HTTP status, payment challenge (if present), and response body to the MCP client; it does not sign x402 payments itself.

3. Restart or reload the MCP client. The tools are `sanitize_text`, `verify_uk_company`, `full_audit`, and `uk_deep_kyb`.

You can also run the bridge from this repository with `npm run mcp`.

## Local development and deployment

```sh
npm ci
npm run dev
npm test
npm run typecheck
```

Configure local credentials in the ignored `.dev.vars` file. GitHub Actions deploys on pushes to `main`; configure the repository secrets `CLOUDFLARE_API_TOKEN` and `COMPANIES_HOUSE_API_KEY`. The workflow resolves the account ID if `CLOUDFLARE_ACCOUNT_ID` is not set, and creates or reuses the required KV namespaces.