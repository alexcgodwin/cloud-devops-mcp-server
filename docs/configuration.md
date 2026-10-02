# Configuration

Cloud DevOps MCP Server supports local stdio by default and optional authenticated Streamable HTTP for self-hosted remote access.

## Recommended public stdio configuration

Use the published npm package so clients do not depend on a local source checkout.

```json
{
  "mcpServers": {
    "cloud-devops": {
      "command": "npx",
      "args": ["-y", "cloud-devops-mcp-server@0.9.0"]
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
      "args": ["-y", "cloud-devops-mcp-server@0.9.0"]
    }
  }
}
```

## Global install

```bash
npm install -g cloud-devops-mcp-server@0.9.0
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

## Live multi-cloud inventory and observability (v0.7)

The live cloud layer is disabled by default and uses existing local cloud CLI authentication. It does not accept credentials through MCP tool arguments.

```text
CLOUD_DEVOPS_MCP_CLOUD_INVENTORY_ENABLED=true
CLOUD_DEVOPS_MCP_ALLOWED_AWS_ACCOUNTS=123456789012
CLOUD_DEVOPS_MCP_ALLOWED_AWS_REGIONS=ca-central-1
CLOUD_DEVOPS_MCP_ALLOWED_AWS_PROFILES=prod-readonly
CLOUD_DEVOPS_MCP_ALLOWED_AZURE_SUBSCRIPTIONS=00000000-0000-0000-0000-000000000000
CLOUD_DEVOPS_MCP_ALLOWED_GCP_PROJECTS=my-project-id
```

Provider requirements:

- AWS: AWS CLI authenticated with a read-only principal. The server verifies the caller account with STS before AWS live reads.
- Azure: Azure CLI authenticated to an explicitly allowlisted subscription.
- GCP: gcloud authenticated to an explicitly allowlisted project.

The v0.7 cloud tools can verify identity, summarize bounded resource inventory, list managed Kubernetes clusters, summarize observability configuration, surface limited FinOps waste signals, and compare expected resource identifiers with live inventory.

AWS general inventory uses the Resource Groups Tagging API and therefore represents tagged resources. Untagged AWS resources can be absent from inventory and drift results. GCP general inventory requires Cloud Asset Inventory access for the configured identity.

No cloud create, update, delete, start, stop, resize, attach, detach, policy mutation or deployment command is exposed. Resource results are bounded, and cloud credentials/tokens are never returned.

## Production observability intelligence (v0.8)

The production-observability plane is disabled by default. Enable it only for trusted, explicitly allowlisted targets:

```text
CLOUD_DEVOPS_MCP_OBSERVABILITY_ENABLED=true
CLOUD_DEVOPS_MCP_ALLOWED_PROMETHEUS_URLS=https://prometheus.example.com
CLOUD_DEVOPS_MCP_PROMETHEUS_BEARER_TOKEN=<optional bearer token>
CLOUD_DEVOPS_MCP_ALLOWED_GRAFANA_URLS=https://grafana.example.com
CLOUD_DEVOPS_MCP_GRAFANA_TOKEN=<optional service-account token>
CLOUD_DEVOPS_MCP_ALLOWED_CLOUDWATCH_LOG_GROUPS=/aws/eks/prod
```

CloudWatch Logs reuses the AWS account, region and optional profile allowlists from the live-cloud plane. Kubernetes health reuses `CLOUD_DEVOPS_MCP_ALLOWED_KUBE_CONTEXTS` and `CLOUD_DEVOPS_MCP_ALLOWED_KUBE_NAMESPACES`. GitHub Actions diagnosis reuses `CLOUD_DEVOPS_MCP_ALLOWED_GITHUB_REPOSITORIES` and the host-side `CLOUD_DEVOPS_MCP_GITHUB_TOKEN`.

Prometheus and Grafana endpoints must use HTTPS unless they are loopback addresses. Query windows, returned series, rows, pods, jobs and log evidence are bounded. Tokens are never accepted as MCP arguments or returned in tool output. The same gate also exposes six supplied-evidence intelligence tools for cloud health, deployment/incident correlation, observability coverage, FinOps correlation, cross-runtime drift and operations briefs. These analysis tools make no external calls. This plane does not expose alert mutation, workflow reruns, Kubernetes mutation or arbitrary shell execution.

## Distributed tracing and SLO intelligence (v0.9)

The tracing plane is disabled by default and uses a separate feature gate:

```text
CLOUD_DEVOPS_MCP_TRACING_ENABLED=true
CLOUD_DEVOPS_MCP_ALLOWED_TEMPO_URLS=https://tempo.example.com
CLOUD_DEVOPS_MCP_TEMPO_BEARER_TOKEN=<optional bearer token>
CLOUD_DEVOPS_MCP_ALLOWED_JAEGER_URLS=https://jaeger.example.com
CLOUD_DEVOPS_MCP_JAEGER_BEARER_TOKEN=<optional bearer token>
```

Tempo and Jaeger URLs are exact allowlists. Remote URLs must use HTTPS; plain HTTP is accepted only for loopback development addresses. Credentials are read from host environment variables and are never passed as MCP tool arguments.

`trace_search` caps each query window at six hours and returns at most 100 trace summaries. Tempo searches can use bounded TraceQL. Jaeger searches use the stable v3 JSON/HTTP trace-summary API. `trace_summary` retrieves one trace by a 64-bit or 128-bit hexadecimal trace ID and normalizes up to 5,000 OpenTelemetry-style spans.

The remaining tracing tools operate only on caller-supplied normalized evidence and do not make external calls. The plane exposes no OTLP ingestion, trace deletion, sampling-policy changes, backend storage mutation or arbitrary tracing API access.
