# Development

## Requirements

- Node.js 22 or newer
- npm

## Local setup

```bash
npm install
npm run build
npm test
```

## Common commands

```bash
npm run dev
npm run build
npm test
npm run check
```

## Project layout

| Path | Purpose |
| --- | --- |
| `src/index.ts` | MCP server registration and tool schemas. |
| `src/logic.ts` | Pure Cloud DevOps decision logic. |
| `tests/logic.test.ts` | Unit tests for the decision logic. |
| `docs/` | Architecture, configuration and tool reference docs. |
| `server.json` | MCP server metadata. |
| `manifest.json` | Human-readable project manifest. |

## Design rules

- Keep tool logic deterministic and testable.
- Prefer structured JSON outputs over long prose blobs.
- Avoid mutating infrastructure or writing to external systems.
- Keep credentials out of code, examples and test fixtures.
