# kybguard-mcp

An MCP stdio server for KYBGuard's UK company verification, audit, and AI input
sanitization tools. It calls `https://api.kybguard.uk` and accepts an optional
`KYBGUARD_API_KEY` environment variable.

Without a key, the Worker applies its existing anonymous access rules: company
verification and sanitization can use the five-call daily free tier, while
other endpoints may return an x402 `402 Payment Required` response. The MCP
tools include the HTTP status and any `PAYMENT-REQUIRED` challenge in their
response.

## Run from npm

After this package is published, launch it with:

```sh
npx -y kybguard-mcp
```

Node.js 20 or later is required.

## Build from this repository

```sh
cd packages/kybguard-mcp
npm install
npm run build
node dist/index.js
```

The server communicates over standard input/output. Keep stdout reserved for
MCP messages; diagnostics are returned by the tool calls.

## Claude Desktop

Add the following to Claude Desktop's `claude_desktop_config.json`, replacing
the optional placeholder with a real KYBGuard key or omitting the `env` entry.
The exact placeholder `optional_ag_key_for_higher_limits` is ignored, so the
free-tier configuration works without edits:

```json
{
  "mcpServers": {
    "kybguard": {
      "command": "npx",
      "args": ["-y", "kybguard-mcp"],
      "env": {
        "KYBGUARD_API_KEY": "YOUR_KYBGUARD_API_KEY"
      }
    }
  }
}
```

Restart Claude Desktop after saving the configuration.

## Cursor

Create or update `.cursor/mcp.json` in your workspace with the same
`mcpServers.kybguard` entry shown above. Restart Cursor or refresh its MCP
servers after saving.

## Windsurf

Add the same stdio server configuration to Windsurf's MCP server settings:
command `npx`, arguments `["-y", "kybguard-mcp"]`, and optionally set
`KYBGUARD_API_KEY` in the server environment.

## Smithery

Publish this package to npm, then register `kybguard-mcp` as a stdio/npm server
in Smithery. Configure the start command as `npx` with arguments
`["-y", "kybguard-mcp"]`; add `KYBGUARD_API_KEY` as an optional secret in the
catalog or client configuration.

## Glama

After npm publication, submit the package as a local stdio MCP server in Glama.
Use command `npx` and arguments `["-y", "kybguard-mcp"]`, and configure
`KYBGUARD_API_KEY` as an optional secret environment variable.

This package is a local stdio server, not a hosted remote MCP endpoint. Do not
commit live API keys into a manifest or workflow file.

## Available tools

- `sanitize`: sanitize untrusted text and optionally redact PII. `strip_pii`
  defaults to `true`.
- `verify_uk_company`: verify a UK company by company number.
- `full_audit`: verify a company and sanitize supplied text, returning an audit
  receipt.
- `uk_deep_kyb`: check company status, directors, and PSC data.

All tools return the API HTTP status and response body. Non-2xx responses are
marked as MCP tool errors; payment-required responses include their x402
challenge header.
