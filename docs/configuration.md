# Configuration

Cloud DevOps MCP Server supports local stdio by default and optional authenticated Streamable HTTP for self-hosted remote access.

## Recommended public stdio configuration

Use the published npm package so clients do not depend on a local source checkout.

```json
{
  "mcpServers": {
    "cloud-devops": {
      "command": "npx",
      "args": ["-y", "cloud-devops-mcp-server@0.4.0"]
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
      "args": ["-y", "cloud-devops-mcp-server@0.4.0"]
    }
  }
}
```

## Global install

```bash
npm install -g cloud-devops-mcp-server@0.4.0
cloud-devops-mcp-server
```

## Authenticated Streamable HTTP

HTTP mode is explicit opt-in. Local loopback example:

```powershell
$env:CLOUD_DEVOPS_MCP_BEARER_TOKEN="<random secret with at least 32 characters>"
npm run start:http
```

Defaults:

- Host: `127.0.0.1`
- Port: `3000`
- MCP endpoint: `/mcp`
- Health endpoint: `/healthz`
- Authentication: `Authorization: Bearer <token>`

A client must send the bearer token in the Authorization header.

### Remote self-hosted mode

For a non-local bind, the server requires all of the following:

```text
CLOUD_DEVOPS_MCP_HOST=0.0.0.0
CLOUD_DEVOPS_MCP_PORT=3000
CLOUD_DEVOPS_MCP_BEARER_TOKEN=<strong random token>
CLOUD_DEVOPS_MCP_ALLOWED_HOSTS=mcp.example.com
CLOUD_DEVOPS_MCP_ALLOWED_ORIGINS=mcp.example.com
CLOUD_DEVOPS_MCP_PUBLIC_BASE_URL=https://mcp.example.com
```

The Node process listens with plain HTTP behind your infrastructure. Terminate TLS at an HTTPS reverse proxy or gateway. Non-local mode refuses to start unless `CLOUD_DEVOPS_MCP_PUBLIC_BASE_URL` is HTTPS.

Do not expose the HTTP listener directly to the public internet without TLS termination, network controls and secret rotation.

## Source-development configuration

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

The analysis tools do not require AWS, Azure, GCP, GitHub or Kubernetes credentials. Raw artifacts are analyzed in-process.

The bearer token protects only optional HTTP transport access. Keep it out of source control, logs and screenshots. Rotate it if exposed.

For multi-user or public SaaS deployments, use an OAuth/OIDC-aware gateway or future OAuth resource-server mode rather than sharing one static bearer token across users.
