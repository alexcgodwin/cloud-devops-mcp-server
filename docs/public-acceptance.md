# Public Release Acceptance

Release: `cloud-devops-mcp-server@0.8.1`
Date: 2026-10-02

This acceptance record was verified against the repository quality gate, the publicly published npm package and the official MCP Registry publication workflow.

## Release status

| Check | Result |
| --- | --- |
| GitHub release | v0.8.1 published |
| npm exact version | 0.8.1 publicly available |
| npm latest dist-tag | 0.8.1 |
| npm trusted publish | GitHub Actions OIDC with provenance |
| Clean npm install audit | 0 vulnerabilities |
| MCP Registry schema validation | Pass |
| MCP Registry authentication | GitHub Actions OIDC |
| MCP Registry publication | Successfully published version 0.8.1 |
| Repository quality gate | 79 of 79 tests pass |
| Statement coverage | 85.58% |
| Branch coverage | 72.17% |
| Function coverage | 85.58% |
| Line coverage | 88.97% |
| Production dependency audit | 0 vulnerabilities |

## Clean public-install acceptance

A fresh temporary directory installed:

```powershell
npm.cmd install --ignore-scripts cloud-devops-mcp-server@0.8.1 @modelcontextprotocol/client@2.2.0
```

The clean installation completed with zero reported vulnerabilities. A real MCP client then spawned the npm-installed server over stdio and verified the following tool surfaces:

| Configuration | Tool count | Result |
| --- | ---: | --- |
| Default analysis | 12 | Pass |
| Production observability + operations intelligence enabled | 24 | Pass |
| All optional capability planes enabled | 46 | Pass |

The clean-install client also confirmed all six v0.8.1 operations-intelligence tools were present.
## v0.8.1 operations-intelligence acceptance

The v0.8.1 completion patch adds six read-only intelligence tools behind the existing observability feature gate:

- `assess_cloud_health`
- `correlate_deployment_incident`
- `assess_observability_coverage`
- `analyze_finops_waste`
- `detect_configuration_drift`
- `generate_operations_brief`

### Cloud health

`assess_cloud_health` combines supplied cloud alarm state, service metrics, logs, Kubernetes health, CI/CD state, SLO status, configuration drift and FinOps findings into a deterministic 0-100 service-health score.

Automated tests cover both critical multi-signal degradation and healthy evidence.

### Deployment and incident correlation

`correlate_deployment_incident` builds a bounded post-deployment timeline from supplied metrics, logs, alerts and Kubernetes evidence.

The tool reports whether the temporal relationship is `strong`, `possible` or `insufficient-evidence`. It deliberately does not declare root cause from timing alone and recommends baseline comparison and version validation before causation is assigned.

### Observability coverage

`assess_observability_coverage` measures whether a service has:

- Metrics
- Logs
- Alerts
- Dashboards
- SLOs
- Distributed tracing
- Deployment markers
- An on-call runbook

It returns a coverage score, maturity level, exact gaps and recommended actions.
### FinOps correlation

`analyze_finops_waste` correlates bounded cloud waste findings with supplied Terraform ownership and Kubernetes utilization evidence.

Terraform-managed findings are directed back through Terraform as the source of truth. Low-utilization workload findings recommend validation across a representative utilization window before any rightsizing decision.

The tool does not delete, resize, stop or otherwise mutate resources.

### Cross-runtime drift

`detect_configuration_drift` compares supplied expected and live identifiers across:

- Cloud resources
- Kubernetes workloads

It reports missing expected resources and unexpected live resources separately for each domain. It does not reconcile drift.

### Operations brief

`generate_operations_brief` combines normalized health, incident, deployment, SLO, drift and FinOps summaries into one concise operational view containing:

- Overall status
- Headline
- Highlights
- Risks
- Next actions

## Existing v0.8 production observability acceptance

The v0.8 line continues to expose six bounded live/read tools when `CLOUD_DEVOPS_MCP_OBSERVABILITY_ENABLED=true`:

- `prometheus_query`
- `grafana_alert_summary`
- `cloudwatch_logs_query`
- `kubernetes_health_summary`
- `github_actions_failure_diagnosis`
- `correlate_incident_signals`

Together with the six v0.8.1 intelligence tools, this capability plane exposes twelve optional tools and brings the all-enabled server surface to 46 tools.
## Security boundary

The v0.8.1 patch preserves the existing fail-closed design.

Default analysis remains credential-free and read-only. Live observability access requires explicit enablement plus the relevant endpoint/resource allowlists. Provider and service credentials remain host-managed and are not accepted as ordinary MCP tool arguments.

The server continues to expose no unrestricted:

- Generic shell execution
- Force-push
- Terraform apply or destroy
- Kubernetes apply, patch, edit, delete or exec
- Cloud create, update or delete operations
- Alert configuration mutation

Higher-impact Git/GitHub operations remain separately gated by the controlled-execution layer and its existing repository, branch, remote and workflow restrictions.

## Distribution verification

The release workflow verified and published the exact `0.8.1` metadata from the release tag.

npm publication completed through GitHub Actions OIDC and produced a provenance statement. The workflow then waited until `cloud-devops-mcp-server@0.8.1` was publicly readable from the npm registry.

The pinned MCP Registry publisher passed checksum verification and validated `server.json` against `https://registry.modelcontextprotocol.io`. GitHub OIDC login succeeded, followed by:

```text
Successfully published
Server io.github.alexcgodwin/cloud-devops-mcp-server version 0.8.1
```

## Final acceptance

`cloud-devops-mcp-server@0.8.1` passes repository CI, coverage thresholds, production dependency audit, npm publication, clean public installation, real MCP stdio tool discovery and official MCP Registry publication.

This record supersedes the v0.7.0 public-acceptance record for the current release.
