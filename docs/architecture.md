# Architecture

Cloud DevOps MCP Server v0.10 is an MCP v2 server built on the 2026-07-28 protocol line. Stdio is the default local transport. Authenticated Streamable HTTP is optional for self-hosted remote access.

## Runtime planes

The server has seven separated capability planes:

1. **Analysis plane** - twelve evidence-backed tools exposed by default. They parse caller-supplied evidence and remain read-only.
2. **Controlled Git/GitHub execution plane** - optional guarded Git and GitHub operations.
3. **Infrastructure operations plane** - optional Terraform validation/plan summaries and Kubernetes read-only runtime inspection.
4. **Live multi-cloud read plane** - optional AWS, Azure and GCP inventory, managed Kubernetes, observability, FinOps and drift signals.
5. **Production observability and operations-intelligence plane** - optional bounded Prometheus, Grafana, CloudWatch Logs, Kubernetes health and GitHub Actions failure diagnostics plus cross-signal correlation, cloud-health scoring, deployment correlation, coverage assessment, FinOps correlation, cross-runtime drift analysis and operations briefs.
6. **Distributed tracing and SLO-intelligence plane** - optional bounded Grafana Tempo and Jaeger v3 trace reads plus service dependency mapping, tracing coverage, multi-window SLO burn-rate analysis and trace/SLO incident correlation.
7. **OpsChugex commercial intelligence gateway** - optional authenticated forwarding of bounded multi-domain incident evidence to the private OpsChugex root-cause engine. The public server contains the contract and transport guardrails, not the proprietary ranking logic.

Each operational plane has its own explicit environment gate. The live cloud plane does not accept provider credentials as MCP arguments; it relies on the host's existing cloud CLI authentication plus scope allowlists.

```mermaid
flowchart TD
  Client["MCP client"] --> Server["Cloud DevOps MCP server"]
  Server --> Analysis["Default analysis plane"]
  Server --> GitOps["Opt-in Git/GitHub plane"]
  Server --> Infra["Opt-in Terraform/Kubernetes plane"]
  Server --> Cloud["Opt-in live multi-cloud read plane"]
  Server --> Trace["Opt-in tracing + SLO plane"]
  Server --> OpsCore["Opt-in OpsChugex root-cause gateway"]

  Analysis --> Logic["Deterministic analyzers + policy packs"]
  GitOps --> GitGuards["Repo / branch / remote / workflow guards"]
  Infra --> InfraGuards["Repo / context / namespace / resource guards"]
  Cloud --> CloudGuards["Account / region / subscription / project guards"]
  Trace --> TraceGuards["Tempo / Jaeger endpoint + time-window guards"]
  OpsCore --> OpsGuards["Configured HTTPS endpoint + host-side bearer token"]
  OpsGuards --> PrivateCore["Private OpsChugex commercial intelligence core"]

  CloudGuards --> AWS["AWS CLI fixed read commands"]
  CloudGuards --> Azure["Azure CLI fixed read commands"]
  CloudGuards --> GCP["gcloud fixed read commands"]
```

## Analysis layers

`src/logic.ts` covers Terraform change risk, incident response, CI/CD readiness, SLOs, AWS IAM, Kubernetes readiness, GitHub Actions and cross-domain release correlation.

`src/intelligence.ts` covers AWS/Azure/GCP identity policy packs, Terraform security, Kubernetes security and SBOM/software supply-chain analysis.

Missing evidence is treated as unknown rather than silently converted into a failed control.

## Controlled execution layer

`src/execution.ts` uses fixed Git subcommands and allowlisted GitHub API operations. It exposes no generic command runner, no force-push, blocks direct mutation of protected branches, stages only selected files, requires passing checks before merge and requires exact confirmation strings for higher-impact GitHub actions.

## Infrastructure operations layer

`src/infrastructure.ts` provides check-only Terraform formatting, `terraform validate -json`, non-apply plan summaries, allowlisted Kubernetes metadata/status reads and bounded rollout checks.

It deliberately exposes no Terraform apply/destroy/state mutation and no Kubernetes apply/create/patch/edit/delete/exec/cp/port-forward surface.

## Live multi-cloud read layer

`src/cloud.ts` uses only fixed provider CLI command shapes.

AWS controls:

- Explicit account and region allowlists.
- Optional profile allowlist.
- STS caller-account verification before AWS resource reads.
- Bounded inventory through Resource Groups Tagging API.
- EKS cluster listing.
- CloudWatch alarm summaries.
- FinOps signals from available EBS volumes and unassociated Elastic IPs.

Azure controls:

- Explicit subscription allowlist.
- Azure Resource Manager resource inventory.
- AKS cluster listing.
- Metric-alert summaries.
- FinOps signals from unattached disks and unassociated public IPs.

GCP controls:

- Explicit project allowlist.
- Cloud Asset Inventory search.
- GKE cluster listing.
- Logging-sink summaries.
- FinOps signals from unused persistent disks and reserved static IPs.

Live inventory is normalized to bounded metadata. Provider tokens, keys and full arbitrary provider responses are not returned. The drift tool reports differences only; it has no reconciliation path.

## Production observability plane

`src/observability.ts` provides fixed, read-only integrations for Prometheus-compatible query APIs, Grafana alert APIs, AWS CloudWatch Logs Insights, allowlisted Kubernetes pod health and GitHub Actions run diagnostics. It also includes deterministic correlation across metrics, logs, alerts, Kubernetes and CI/CD evidence.

`src/operations-intelligence.ts` adds supplied-evidence analysis for cloud health, post-deployment incident timelines, observability coverage, FinOps/Terraform ownership correlation, cloud/Kubernetes drift and concise operations briefs. These tools do not query or mutate external systems.

Remote observability endpoints must be exactly allowlisted and use HTTPS unless they are loopback addresses. AWS accounts/regions/log groups, Kubernetes contexts/namespaces and GitHub repositories are separately allowlisted. Query windows and result sizes are bounded, sensitive token patterns are redacted, and host-side credentials are never returned.

## Distributed tracing and SLO-intelligence plane

`src/tracing.ts` provides bounded read access to Grafana Tempo and the stable Jaeger v3 JSON/HTTP query API. It can search traces, retrieve one trace by ID and normalize OpenTelemetry-style resource/span data into bounded summaries. It also provides local analysis for service dependency maps, tracing instrumentation coverage, multi-window SLO burn rates and trace/SLO incident correlation.

The tracing plane is disabled by default and requires `CLOUD_DEVOPS_MCP_TRACING_ENABLED=true`. Tempo and Jaeger base URLs must be explicitly allowlisted and use HTTPS unless they are loopback addresses. Bearer tokens are host-managed environment variables and are never accepted as MCP tool arguments. Trace searches are capped at six-hour windows and 100 summaries; trace normalization is bounded to 5,000 spans.

The plane exposes no OTLP ingestion, trace deletion, sampling-policy mutation, storage mutation or arbitrary backend API access. Correlation reports evidence strength and deliberately does not assign root cause.

## Audit and redaction

Operational layers write JSONL audit records to `CLOUD_DEVOPS_MCP_AUDIT_LOG` or the operating-system temporary directory. Known token/access-key patterns are redacted before audit detail is written.

## Release supply chain

Releases run the quality gate, publish npm through GitHub Actions OIDC with provenance, wait for public npm availability, verify the pinned MCP Registry publisher by SHA-256, authenticate to the MCP Registry with GitHub OIDC and publish the matching `server.json`.

## HTTP security boundary

HTTP mode requires explicit opt-in, bearer authentication, timing-safe comparison, Host/Origin validation and an HTTPS public base URL for non-local binding.

## Safety boundary

Default analysis remains read-only and credential-free. Optional cloud/infrastructure access must be explicitly enabled and allowlisted.

The server intentionally does not provide generic shell execution, force-push, Terraform apply/destroy, Kubernetes mutation, or cloud resource mutation tools.
