# Changelog

## 0.13.0 - Advanced FinOps Intelligence Gateway

- Added opt-in `analyze_advanced_finops` for bounded cloud-cost, utilization and Kubernetes allocation evidence.
- Added a separate fail-closed FinOps feature gate so the other OpsChugex commercial gateways remain independently controlled.
- Added host-configured HTTPS FinOps endpoint validation and reuse of the host-side OpsChugex bearer token without exposing endpoint or credential arguments to MCP callers.
- Added request bounds of 5,000 cloud resources and 5,000 Kubernetes workloads.
- Kept proprietary savings factors, anomaly thresholds, prioritization, confidence logic and cloud/Kubernetes deduplication inside the private OpsChugex core.
- Kept FinOps read-only: no resizing, resource termination, commitment purchase, Kubernetes mutation, storage-tier change or billing action.
- Added dedicated gateway tests including real MCP handler execution.
- Verification: 111/111 tests pass; coverage 85.76% statements, 72.10% branches, 85.71% functions, 89.12% lines; production dependency audit reports 0 vulnerabilities.

## 0.12.0 - Cloud Security Posture Intelligence Gateway

- Added opt-in `assess_cloud_security_posture` for bounded cloud asset, identity, secret and network-reachability evidence.
- Added a separate fail-closed security feature gate so root-cause and governance behavior remain independently controlled.
- Added host-configured HTTPS security endpoint validation and reuse of the host-side OpsChugex bearer token without exposing endpoint or credential arguments to MCP callers.
- Added request bounds of 3,000 assets, 3,000 identities, 2,000 secret findings and 10,000 network edges.
- Kept proprietary misconfiguration rules, severity thresholds, security scoring and attack-path correlation inside the private OpsChugex core.
- Kept security posture read-only: no credential rotation, IAM mutation, network changes, encryption changes or infrastructure remediation.
- Added dedicated gateway tests including real MCP handler execution.
- Verification: 106/106 tests pass; coverage 85.71% statements, 72.10% branches, 85.49% functions, 89.10% lines; production dependency audit reports 0 vulnerabilities.

## 0.11.0 - Policy & Governance Engine Gateway

- Added opt-in `assess_governance_policy` for bounded resource evidence and time-bounded governance exceptions.
- Added a separate fail-closed governance feature gate so v0.10 root-cause behavior remains backward compatible.
- Added host-configured HTTPS governance endpoint validation and reused the host-side OpsChugex bearer token without exposing endpoint or credential arguments to MCP callers.
- Added request bounds of 2,000 resources and 500 exceptions.
- Kept all proprietary development/staging/production/regulated profiles, control rules, scoring weights, exception-processing logic and enforcement capability inside the private OpsChugex core.
- Kept governance read-only: no tags, IAM, networking, encryption, backup, Terraform, Kubernetes or cloud resources are mutated.
- Added dedicated gateway and real MCP handler execution tests.
- Verification: 101/101 tests pass; coverage 85.68% statements, 72.02% branches, 85.30% functions, 89.08% lines; production dependency audit reports 0 vulnerabilities.

## 0.10.0 - Automated Root-Cause Intelligence

- Added opt-in `diagnose_root_cause` for evidence-ranked probable causes across metrics, logs, traces, Kubernetes, cloud, Terraform and CI/CD evidence.
- Added a strict public/private boundary: the public MIT repository contains only the MCP contract and guarded HTTPS client; proprietary ranking, weighting and commercial correlation logic remain in the private OpsChugex core.
- Added supporting and contradicting evidence IDs, evidence-strength scoring, confidence labels, limitations and recommended next checks.
- Added fail-closed commercial configuration with a host-configured endpoint, HTTPS requirement for remote targets and a host-side bearer token of at least 32 characters.
- Kept root-cause intelligence read-only: v0.10 does not remediate incidents or mutate cloud, Kubernetes, Terraform, CI/CD or observability state.
- Added dedicated gateway tests and updated architecture, configuration, security and tool documentation.
- Verification: 95/95 tests pass; coverage 85.65% statements, 71.94% branches, 85.10% functions, 89.12% lines; production dependency audit reports 0 vulnerabilities.

## 0.9.0 - Distributed Tracing and SLO Intelligence

- Added `trace_search` for bounded Grafana Tempo TraceQL and Jaeger v3 trace-summary searches against explicitly allowlisted endpoints.
- Added `trace_summary` for normalized OpenTelemetry-style trace summaries from Tempo and Jaeger v3.
- Added `trace_dependency_map` to derive service-to-service call edges, error rates and average child-span duration from supplied span relationships.
- Added `assess_tracing_coverage` for instrumentation, resource attributes, trace-log correlation and sampling-policy coverage.
- Added `analyze_slo_burn_rate` for short/long-window request-failure burn analysis and error-budget exhaustion estimates.
- Added `correlate_trace_slo_incident` for trace, SLO, dependency and deployment-timing correlation without root-cause ranking.
- Added a separate fail-closed tracing feature gate with HTTPS endpoint allowlists, host-side bearer tokens, bounded search windows and audit logging.
- Preserved the non-destructive design: no OTLP ingestion, trace deletion, sampling mutation, storage mutation or arbitrary tracing-backend API access.
- Verification: 91/91 tests pass; coverage 85.75% statements, 71.86% branches, 85.29% functions, 89.22% lines; production dependency audit reports 0 vulnerabilities.

## 0.8.1 - Operations Intelligence Completion

- Added `assess_cloud_health` to combine cloud alarms, metrics, logs, Kubernetes health, CI/CD, SLO and drift evidence into one bounded health assessment.
- Added `correlate_deployment_incident` with a post-deployment evidence timeline that reports correlation strength without claiming root cause.
- Added `assess_observability_coverage` for metrics, logs, alerts, dashboards, SLOs, tracing, deployment markers and runbooks.
- Added `analyze_finops_waste` to correlate cloud waste signals with Terraform ownership and Kubernetes utilization evidence.
- Added `detect_configuration_drift` for combined cloud-resource and Kubernetes-workload drift analysis.
- Added `generate_operations_brief` for concise service health, incident, SLO, drift and FinOps summaries.
- Preserved the v0.8 fail-closed observability gate and read-only/non-destructive boundary.
- Verification: 79/79 tests pass; coverage 85.58% statements, 72.17% branches, 85.58% functions, 88.97% lines; production dependency audit reports 0 vulnerabilities.

## 0.8.0 - Production Observability Intelligence

- Added an opt-in, read-only production-observability plane.
- Added bounded Prometheus instant/range queries and Grafana alert summaries.
- Added allowlisted CloudWatch Logs Insights querying and Kubernetes pod-health summaries.
- Added GitHub Actions failure diagnosis with bounded, redacted log evidence.
- Added deterministic cross-signal incident correlation across metrics, logs, alerts, Kubernetes and CI/CD.
- Added fail-closed endpoint/resource allowlists, host-side credentials and audit logging for the new integrations.
- Added automated observability tests and v0.8 configuration/architecture documentation.

All notable changes to Cloud DevOps MCP Server will be documented in this file.

The format follows Keep a Changelog, and this project uses semantic versioning.

## 0.7.0 - Live Multi-Cloud Observability and Inventory

- Added an opt-in live AWS/Azure/GCP read plane backed by fixed provider CLI commands.
- Added cloud identity verification and explicit AWS account/region/profile, Azure subscription and GCP project allowlists.
- Added bounded normalized cloud inventory summaries and managed Kubernetes cluster discovery for EKS, AKS and GKE.
- Added observability configuration summaries for CloudWatch alarms, Azure metric alerts and GCP logging sinks.
- Added FinOps signals for unattached/unused storage and unassociated/reserved static public IP resources.
- Added expected-vs-live resource drift comparison with no reconciliation or mutation path.
- Cloud credentials remain host-managed and are never accepted through tool arguments or returned in MCP responses.
- No cloud create/update/delete/start/stop/resize/attach/detach/policy mutation operations are exposed.
- Verification: 57/57 tests pass; coverage 84.71% statements, 70.70% branches, 85.75% functions, 88.08% lines; production dependency audit reports 0 vulnerabilities.

## 0.6.0 - Infrastructure Validation and Runtime Read Layer

- Added opt-in Terraform format checking, JSON validation and non-apply plan summaries.
- Added allowlisted Kubernetes current-context, resource metadata/status and rollout-status inspection.
- Terraform planning defaults to no refresh, no state lock and no apply capability; full plan JSON is never returned.
- Kubernetes operations require context, namespace and resource allowlists; secrets and mutation commands are excluded.
- Added deterministic command-runner injection for test coverage without cloud credentials or live clusters.
- Added automatic MCP Registry publishing through GitHub Actions OIDC for future releases.
- Verification: 49/49 tests pass; coverage 83.03% statements, 71.23% branches, 85.42% functions, 86.64% lines; production dependency audit reports 0 vulnerabilities.

## 0.5.0 - Controlled Execution Gateway

- Added opt-in allowlisted Git operations: status, fetch, fast-forward-only pull, branch creation, selected-file commit and push.
- Added GitHub pull request creation/status, CI-gated merge and allowlisted workflow dispatch.
- Added protected-branch blocking, no-force-push design, repository/remote/branch/workflow allowlists, dry-run support and JSONL audit logging.
- Preserved the existing twelve analysis tools as the default read-only surface when execution is disabled.
- Verification: 43/43 tests pass; coverage 85.17% statements, 73.46% branches, 88.23% functions, 88.96% lines; production audit reports 0 vulnerabilities.

## [0.4.0] - 2026-10-01

### Added

- AWS, Azure and GCP identity policy packs through `review_cloud_identity_policy`.
- Deeper Terraform security analysis for destructive stateful changes, sensitive public ports, public data services, encryption, deletion protection, S3 public-access controls and IAM wildcards.
- Kubernetes security-policy analysis for privileged containers, host namespaces, hostPath, Linux capabilities, default service-account tokens, hostPort, seccomp, read-only root filesystems and NetworkPolicy.
- CycloneDX and SPDX SBOM parsing plus software supply-chain correlation across CI action pinning, container image immutability, artifact signing and build provenance.
- Optional bearer-authenticated Streamable HTTP serving through the MCP v2 HTTP handler.
- Host/Origin validation, minimum bearer-token length and HTTPS reverse-proxy requirements for non-local HTTP binding.
- End-to-end authenticated Streamable HTTP client tests.
- Four new public MCP tools, bringing the tool count to twelve.

### Changed

- Runtime, package, manifest and Registry metadata advanced to 0.4.0.
- Local stdio remains the default transport; remote HTTP is explicit opt-in.
- Security and architecture documentation now cover the authenticated HTTP trust boundary.

## [0.3.1] - 2026-10-01

### Fixed

- Shortened the MCP Registry description to satisfy the official 100-character limit.
- Added automated metadata consistency checks for package, manifest and Registry versions.
- Added CI coverage for Registry name/package identity and the eight-tool manifest.
- Public installation examples now point to 0.3.1.

## [0.3.0] - 2026-10-01

### Added

- New `assess_cloud_change_bundle` MCP tool for cross-domain release analysis.
- Correlation across Terraform, AWS IAM, Kubernetes and GitHub Actions evidence.
- Domain risk summaries, correlated finding IDs, change-path sequencing and combined release gates.
- Correlation rules for public exposure, privileged production delivery, mutable supply chains, public-plus-privilege blast radius, root-capable public workloads and high-risk IAM changes inside Terraform.
- Multi-domain confidence and uncertainty aggregation.
- Contract coverage for all eight MCP tools.

### Changed

- MCP server runtime version advanced to 0.3.0.
- Registry and npm metadata now declare version 0.3.0.
- Public installation examples point to the 0.3.0 package.
- Roadmap now focuses on deeper policy packs, provenance and authenticated remote transport rather than cross-tool correlation.

## [0.2.1] - 2026-10-01

### Fixed

- Normalized the npm executable path so package installation exposes the `cloud-devops-mcp-server` CLI correctly.
- Normalized npm repository metadata before publication.
- Added the official MCP Registry npm package declaration with stdio transport.

## [0.2.0] - 2026-10-01

### Added

- MCP TypeScript SDK v2 support for the 2026-07-28 protocol line.
- Validated structured tool outputs with output schemas.
- Read-only, non-destructive and idempotent tool annotations.
- Direct Terraform plan JSON evidence parsing.
- Direct AWS IAM policy JSON parsing with wildcard and privilege-escalation detection.
- Direct multi-document Kubernetes YAML parsing.
- Direct GitHub Actions workflow YAML parsing.
- Evidence, uncertainty and assessment-confidence fields.
- MCP client/server contract tests and enforced coverage thresholds.
- Production dependency audit in the CI quality gate.

### Changed

- Missing optional controls are now reported as unknown instead of being treated as failed.
- CI actions are pinned to immutable commit SHAs and workflow token permissions are read-only.
- Registry metadata now uses an io.github.alexcgodwin namespace.
- Corrected the Terraform README example score from 60/high to 78/critical.
- Release version advanced to 0.2.0 for the new backward-compatible capabilities.

## [0.1.0] - 2026-10-01

### Added

- Initial Cloud DevOps MCP server.
- Terraform and infrastructure change risk assessment tool.
- Incident runbook generation tool.
- CI/CD pipeline readiness review tool.
- SLO error budget estimation tool.
- AWS IAM policy review tool.
- Kubernetes deployment readiness review tool.
- GitHub Actions workflow review tool.
- CI workflow, tests, security policy and contribution guide.
