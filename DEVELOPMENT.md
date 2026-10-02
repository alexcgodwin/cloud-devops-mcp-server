# Development

## Requirements

- Node.js 22 recommended; Node.js 20 or newer is supported.
- npm

## Local setup

```bash
npm install
npm run check
```

## Common commands

```bash
npm run dev
npm run build
npm test
npm run test:coverage
npm run check
npm run start:http
```

## Project layout

| Path | Purpose |
| --- | --- |
| `src/index.ts` | MCP v2 server factory, tool schemas, annotations and structured outputs. |
| `src/logic.ts` | Core deterministic Cloud DevOps analysis and cross-domain correlation. |
| `src/intelligence.ts` | Multi-cloud identity, Terraform/Kubernetes security and SBOM policy packs. |
| `src/http.ts` | Authenticated Streamable HTTP serving and remote-mode security controls. |
| `src/infrastructure.ts` | Opt-in Terraform validation/plan summaries and Kubernetes read-only runtime operations. |
| `tests/logic.test.ts` | Unit and edge-case tests for core decision logic and parsers. |
| `tests/intelligence.test.ts` | Policy-pack and supply-chain tests. |
| `tests/http.test.ts` | Real authenticated Streamable HTTP integration tests. |
| `tests/mcp.test.ts` | In-memory MCP client/server contract tests. |
| `docs/` | Architecture, configuration and tool reference docs. |
| `server.json` | MCP Registry-format server metadata. |
| `manifest.json` | Project capability manifest. |

## Design rules

- Keep tool logic deterministic and testable.
- Prefer raw engineering artifacts over self-reported booleans when available.
- Treat missing evidence as unknown, not false.
- Return validated structured content plus a human-readable text representation.
- Keep analysis read-only by default; isolate opt-in operational tools behind explicit enablement, allowlists and narrowly fixed commands.
- Keep credentials out of code, examples and test fixtures.
