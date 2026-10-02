# Configuration

Cloud DevOps MCP Server supports local stdio by default and optional authenticated Streamable HTTP for self-hosted remote access.

## Recommended public stdio configuration

Use the published npm package so clients do not depend on a local source checkout.

```json
{
  "mcpServers": {
    "cloud-devops": {
      "command": "npx",
      "args": ["-y", "cloud-devops-mcp-server@0.6.0"]
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
      "args": ["-y", "cloud-devops-mcp-server@0.6.0"]
    }
  }
}
```

## Global install

```bash
npm install -g cloud-devops-mcp-server@0.6.0
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

## Controlled Git/GitHub execution (v0.5)

Execution is disabled by default. Enable it only for trusted local repositories:

```powershell
$env:CLOUD_DEVOPS_MCP_EXECUTION_ENABLED="true"
$env:CLOUD_DEVOPS_MCP_ALLOWED_REPOSITORIES="C:\path\to\repo"
$env:CLOUD_DEVOPS_MCP_ALLOWED_GITHUB_REPOSITORIES="owner/repo"
$env:CLOUD_DEVOPS_MCP_GITHUB_TOKEN="<fine-grained token>"
```

Optional controls: protected branches, allowed branch prefixes, remotes, workflows and audit-log path. Force-push is not implemented. Pulls are fast-forward only. Commits stage only explicitly named paths. PR merge requires passing checks plus `confirm: "MERGE"`; workflow dispatch requires an allowlisted workflow plus `confirm: "TRIGGER"`.

## Terraform and Kubernetes operations (v0.6)

A second opt-in gate exposes six infrastructure operations:

```text
CLOUD_DEVOPS_MCP_INFRASTRUCTURE_OPERATIONS_ENABLED=true
CLOUD_DEVOPS_MCP_ALLOWED_REPOSITORIES=/absolute/path/to/repo
CLOUD_DEVOPS_MCP_ALLOWED_KUBE_CONTEXTS=dev-cluster,prod-cluster
CLOUD_DEVOPS_MCP_ALLOWED_KUBE_NAMESPACES=default,platform
```

The Terraform layer provides check-only formatting, `terraform validate -json`, and a plan summary using `-refresh=false`, `-lock=false`, and no apply capability. Full plan JSON is not returned.

The Kubernetes layer allows only configured contexts, namespaces and resource types. It returns bounded metadata/status summaries and rollout status. Secrets are excluded by default, and there are no apply, patch, delete, exec, port-forward or shell tools.
