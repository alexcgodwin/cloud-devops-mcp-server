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
```

## Project layout

| Path | Purpose |
| --- | --- |
| `src/index.ts` | MCP v2 server factory, tool schemas, annotations and structured outputs. |
| `src/logic.ts` | Deterministic Cloud DevOps analysis and artifact parsing. |
| `tests/logic.test.ts` | Unit and edge-case tests for decision logic and parsers. |
| `tests/mcp.test.ts` | In-memory MCP client/server contract tests. |
| `docs/` | Architecture, configuration and tool reference docs. |
| `server.json` | MCP Registry-format server metadata. |
| `manifest.json` | Project capability manifest. |

## Design rules

- Keep tool logic deterministic and testable.
- Prefer raw engineering artifacts over self-reported booleans when available.
- Treat missing evidence as unknown, not false.
- Return validated structured content plus a human-readable text representation.
- Keep tools read-only unless a future release explicitly introduces separately reviewed mutation tools.
- Keep credentials out of code, examples and test fixtures.
