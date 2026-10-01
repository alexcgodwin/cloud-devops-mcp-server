# Configuration

Cloud DevOps MCP Server runs as a local stdio MCP server and is published on npm as `cloud-devops-mcp-server`.

## Recommended public configuration

Use the published npm package so clients do not depend on a local source checkout.

```json
{
  "mcpServers": {
    "cloud-devops": {
      "command": "npx",
      "args": ["-y", "cloud-devops-mcp-server@0.3.0"]
    }
  }
}
```

On Windows, use `npx.cmd` if PowerShell execution policy blocks the `npx.ps1` wrapper:

```json
{
  "mcpServers": {
    "cloud-devops": {
      "command": "npx.cmd",
      "args": ["-y", "cloud-devops-mcp-server@0.3.0"]
    }
  }
}
```

## Global install

Install once and use the binary directly:

```bash
npm install -g cloud-devops-mcp-server@0.3.0
```

Then configure the client with:

```json
{
  "mcpServers": {
    "cloud-devops": {
      "command": "cloud-devops-mcp-server"
    }
  }
}
```

## Source-development configuration

For local development, build the repository and point the client to the generated entry point:

```bash
npm install
npm run build
```

```json
{
  "mcpServers": {
    "cloud-devops-dev": {
      "command": "node",
      "args": ["/absolute/path/to/cloud-devops-mcp-server/dist/index.js"]
    }
  }
}
```

## Security

The server does not require cloud credentials for its current advisory toolset. Do not add AWS, Azure, GitHub or other credentials unless a future tool explicitly documents a read-only integration that requires them.

Keep tokens and secrets out of MCP configuration files that are committed to source control.
