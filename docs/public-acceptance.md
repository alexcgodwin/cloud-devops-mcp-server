# Public Release Acceptance

Release: `cloud-devops-mcp-server@0.9.0`
Date: 2026-10-02

This acceptance record was verified against repository CI, the publicly published npm package, a clean npm installation, a real MCP stdio client and the official MCP Registry publication workflow.

## Release status

| Check | Result |
| --- | --- |
| GitHub release | v0.9.0 published |
| npm exact version | 0.9.0 publicly available |
| npm latest dist-tag | 0.9.0 |
| npm trusted publish | GitHub Actions OIDC with provenance |
| Clean npm install audit | 0 vulnerabilities |
| MCP Registry schema validation | Pass |
| MCP Registry authentication | GitHub Actions OIDC |
| MCP Registry publication | Successfully published version 0.9.0 |
| Repository quality gate | 91 of 91 tests pass |
| Statement coverage | 85.75% |
| Branch coverage | 71.86% |
| Function coverage | 85.29% |
| Line coverage | 89.22% |
| Production dependency audit | 0 vulnerabilities |

## Clean public-install acceptance

A fresh temporary directory installed:

```powershell
npm.cmd install --ignore-scripts cloud-devops-mcp-server@0.9.0 @modelcontextprotocol/client@2.2.0
```

The clean installation completed with zero reported vulnerabilities. A real MCP client spawned the npm-installed package over stdio and verified:

| Configuration | Tool count | Result |
| --- | ---: | --- |
| Default analysis | 12 | Pass |
| v0.9 tracing/SLO plane enabled | 18 | Pass |
| v0.8 observability + v0.9 tracing enabled | 30 | Pass |
| All optional capability planes enabled | 52 | Pass |

The client confirmed all six v0.9 tools were present.
## v0.9 distributed tracing and SLO acceptance

The v0.9 tracing plane is disabled by default and exposes six tools only when `CLOUD_DEVOPS_MCP_TRACING_ENABLED=true`:

- `trace_search`
- `trace_summary`
- `trace_dependency_map`
- `assess_tracing_coverage`
- `analyze_slo_burn_rate`
- `correlate_trace_slo_incident`

### Trace search

`trace_search` supports two explicitly allowlisted tracing backends:

- Grafana Tempo through its HTTP search API, with bounded TraceQL support.
- Jaeger through the stable v3 JSON/HTTP trace-summary API.

Search windows are limited to six hours and result counts are capped at 100. Tempo and Jaeger credentials remain host-side and are never accepted as MCP tool arguments.

### Trace summary

`trace_summary` retrieves one 64-bit or 128-bit hexadecimal trace ID from an allowlisted Tempo or Jaeger endpoint.

The server normalizes OpenTelemetry-style resource/span data and returns bounded summaries covering:

- Services
- Operations
- Error spans
- Root spans
- End-to-end duration
- Slow spans

Trace normalization is capped at 5,000 spans.

### Dependency mapping

`trace_dependency_map` builds service-to-service edges from caller-supplied parent/child span relationships and reports:

- Call count
- Error count
- Error rate
- Average child-span duration

It makes no external calls.
### Tracing coverage

`assess_tracing_coverage` checks explicit evidence for:

- Inbound/server spans
- Outbound/client spans
- Database spans
- Messaging spans
- Error status
- `service.name`
- Environment resource metadata
- Deployment/service version metadata
- Trace-log correlation
- Documented sampling policy

It returns a deterministic coverage score, maturity level, exact gaps and recommended actions.

### SLO burn rate

`analyze_slo_burn_rate` calculates short- and long-window error-budget burn from explicit request counts and a supplied SLO target.

It returns:

- Error rate for each window
- Burn rate for each window
- Combined burn rate
- Severity
- Estimated time to consume a 30-day error budget at the observed maximum rate
- Recommended next actions

The tool does not query monitoring systems or trigger remediation.

### Trace/SLO incident correlation

`correlate_trace_slo_incident` combines representative trace evidence with:

- SLO burn severity
- Dependency edges
- Optional deployment timing

It reports correlation strength, evidence domains and problematic dependencies.

The tool deliberately does not rank or declare root cause. Root-cause ranking remains outside the v0.9 scope.

## Security boundary

The v0.9 plane uses a separate fail-closed gate and explicit endpoint allowlists.

Remote Tempo and Jaeger URLs must use HTTPS. Plain HTTP is accepted only for loopback development addresses. Bearer tokens are read from host environment variables and are never returned in tool output.

The tracing plane exposes no:

- OTLP ingestion
- Trace deletion
- Sampling-policy mutation
- Backend storage mutation
- Arbitrary tracing-backend API access
- Generic shell execution

All six v0.9 tools are marked read-only and non-destructive.
## Distribution verification

The release workflow published the exact `0.9.0` metadata from the GitHub release tag.

npm publication completed through GitHub Actions OIDC with signed provenance. The workflow waited until `cloud-devops-mcp-server@0.9.0` was publicly readable, then validated `server.json` with the pinned MCP Registry publisher.

The release log recorded:

```text
cloud-devops-mcp-server@0.9.0 is publicly available.
server.json is valid
Successfully published
Server io.github.alexcgodwin/cloud-devops-mcp-server version 0.9.0
```

## Final acceptance

`cloud-devops-mcp-server@0.9.0` passes repository CI, automated tests, coverage thresholds, production dependency audit, npm trusted publication, clean public installation, real MCP stdio tool discovery and official MCP Registry publication.

The v0.9 release adds distributed tracing and SLO intelligence while preserving the server's bounded, fail-closed and non-destructive operational model.

This record supersedes the v0.8.1 public-acceptance record for the current release.
