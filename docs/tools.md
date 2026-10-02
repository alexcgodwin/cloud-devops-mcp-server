# Tools

## `assess_cloud_change_bundle`

Correlates evidence from Terraform, AWS IAM, Kubernetes and GitHub Actions into one release-risk assessment. It preserves each domain's individual score, then adds cross-domain findings when controls combine into a larger change path.

Current correlation rules include:

- Public infrastructure exposure plus public Kubernetes exposure.
- Privilege-escalating IAM plus insufficiently protected production delivery.
- Mutable GitHub Actions references plus mutable Kubernetes image tags.
- Public exposure plus wildcard or privilege-escalating IAM.
- Public reachability plus root-capable Kubernetes workloads.
- Terraform IAM changes plus high-risk IAM policy evidence.
- Stateful Terraform changes without an explicit rollback or forward-fix plan.

The output includes a combined risk score, risk level, confidence, domain summaries, correlated finding IDs, change-path sequences, uncertainties, a release gate and deduplicated remediation actions.

Use it for:

- Multi-file pull request review.
- Production change-advisory preparation.
- Release risk summaries spanning infrastructure, identity, runtime and delivery.
- Explaining why individually acceptable changes become risky when deployed together.

At least two evidence domains are required.

## `assess_terraform_change`

Scores deployment risk from infrastructure change characteristics or raw Terraform plan JSON. Raw plans produce rule-tagged evidence and automatically derive resource classes, IAM changes, public exposure and stateful-resource changes.

Use it for:

- Terraform pull request review.
- Production deployment planning.
- Release gate recommendations.

## `build_incident_runbook`

Builds a practical incident response runbook for a service, symptom, environment and severity.

Use it for:

- On-call preparation.
- War room checklists.
- Service-specific response planning.

## `review_cicd_pipeline`

Reviews delivery readiness and suggests missing CI/CD controls.

Use it for:

- Pipeline maturity review.
- Production readiness checks.
- Safer release process design.

## `estimate_slo_error_budget`

Calculates remaining downtime and optional failed-request budget for an SLO window.

Use it for:

- SLO status review.
- Error budget planning.
- Reliability reporting.

## `review_iam_policy`

Reviews IAM policies for wildcard access, privilege-escalation paths, missing conditions and production blast radius. Supply raw IAM policy JSON to derive actions, resources and escalation evidence automatically.

Use it for:

- IAM pull request review.
- Least-privilege checks.
- Production permission-set review.

## `review_kubernetes_deployment`

Reviews Kubernetes workload controls such as probes, replicas, resource requests, resource limits, disruption budgets, image tags, security context and public exposure. Multi-document Kubernetes YAML can be parsed directly.

Use it for:

- Kubernetes production readiness.
- EKS workload review.
- Helm or manifest review.

## `review_github_actions_workflow`

Reviews GitHub Actions workflows for action pinning, token permissions, production protections, secret guardrails and deployment concurrency. Raw workflow YAML can be parsed directly; repository-side settings that cannot be proven from YAML remain explicitly unknown.

Use it for:

- CI/CD security review.
- Production deployment workflow review.
- Release gate hardening.


## `review_cloud_identity_policy`

Applies provider-specific identity policy packs to raw JSON.

Supported packs:

- `aws-identity-v1`
- `azure-identity-v1`
- `gcp-identity-v1`

Examples of detected risk include administrative wildcards, `iam:PassRole`, broad Azure RBAC roles, role-assignment mutation, GCP Owner/Editor, service-account token creation and public IAM principals.

Use it for:

- Multi-cloud IAM/RBAC pull request review.
- Privilege-escalation screening.
- Production access-policy review.
- Comparing identity posture across AWS, Azure and GCP.

## `review_terraform_security`

Performs a deeper security-focused Terraform plan review than the general change-risk tool.

Current rules cover:

- Destructive stateful changes.
- Resource replacement.
- Public CIDRs.
- Sensitive ports exposed publicly.
- Public data services.
- Encryption disabled.
- Deletion protection disabled.
- S3 public-access-block weakening.
- IAM wildcard signals.

Use it for security review of `terraform show -json` plan output before apply.

## `review_kubernetes_security`

Applies Kubernetes workload security controls to multi-document YAML.

Current rules cover:

- Privileged containers.
- `allowPrivilegeEscalation`.
- Root execution.
- Host network/PID/IPC namespaces.
- `hostPath` storage.
- Dangerous Linux capabilities.
- `hostPort`.
- Default service-account token use.
- Missing seccomp.
- Missing read-only root filesystem.
- Public Service/Ingress without NetworkPolicy in the supplied bundle.

Use it alongside `review_kubernetes_deployment`: the deployment tool focuses on operational readiness, while this tool focuses on workload security posture.

## `review_software_supply_chain`

Parses CycloneDX or SPDX JSON and correlates software inventory with delivery and runtime evidence.

It measures:

- Version coverage.
- Hash/checksum coverage.
- Package URL coverage.
- License metadata coverage.

Optional correlation inputs:

- GitHub Actions workflow YAML.
- Kubernetes manifest YAML.
- Artifact signing status.
- Build provenance status.

Cross-domain rules detect mutable CI action references combined with mutable runtime images, and SBOMs that are not cryptographically tied to a signed/provenanced artifact.

## Optional v0.6 infrastructure operations

These tools appear only when `CLOUD_DEVOPS_MCP_INFRASTRUCTURE_OPERATIONS_ENABLED=true`.

### `terraform_fmt_check`

Runs `terraform fmt -check -recursive -diff` inside an allowlisted repository. It reports formatting drift without rewriting files.

### `terraform_validate`

Runs `terraform validate -json` and returns bounded validation diagnostics. It does not initialize providers or change infrastructure.

### `terraform_plan_summary`

Creates a temporary plan with refresh disabled and returns only action counts such as create, update, delete and replace. It never runs `terraform apply` and does not return full plan JSON.

### `kubectl_current_context`

Reads the current kubectl context and requires it to be explicitly allowlisted.

### `kubectl_get_resources`

Reads bounded metadata/status for allowlisted resources, contexts and namespaces. Secrets are not included in the default resource allowlist.

### `kubectl_rollout_status`

Reads rollout readiness for an allowlisted Deployment, StatefulSet or DaemonSet with watch disabled and a bounded timeout.

## Optional v0.7 live multi-cloud tools

These tools appear only when `CLOUD_DEVOPS_MCP_CLOUD_INVENTORY_ENABLED=true`.

### `cloud_whoami`

Verifies the active allowlisted scope before live reads. AWS returns the STS caller ARN/account, Azure returns the active subscription identity, and GCP returns the active authenticated account. Tokens and credentials are never returned.

### `cloud_inventory_summary`

Returns bounded normalized resource metadata from:

- AWS Resource Groups Tagging API (tagged resources; untagged resources may be absent).
- Azure Resource Manager.
- GCP Cloud Asset Inventory.

The response contains identifiers, names, types, locations and type counts. It does not return arbitrary provider payloads.

### `cloud_kubernetes_clusters`

Lists managed Kubernetes control planes from EKS, AKS or GKE without changing cluster state.

### `cloud_observability_summary`

Summarizes configured CloudWatch alarms, Azure metric alerts or GCP logging sinks.

### `cloud_finops_signals`

Surfaces bounded waste signals without making cost-saving changes:

- AWS available EBS volumes and unassociated Elastic IPs.
- Azure unattached managed disks and unassociated public IPs.
- GCP persistent disks with no users and reserved static addresses.

### `cloud_drift_compare`

Compares caller-supplied expected resource identifiers with the bounded live inventory and reports missing expected or unexpected live resources. It never reconciles drift.

## Optional v0.8 production observability and operations intelligence

These tools appear only when `CLOUD_DEVOPS_MCP_OBSERVABILITY_ENABLED=true`.

### Live/read tools

- `prometheus_query` runs bounded instant or range PromQL against an allowlisted endpoint.
- `grafana_alert_summary` returns bounded Grafana managed-alert and active-alert summaries.
- `cloudwatch_logs_query` runs bounded CloudWatch Logs Insights queries against allowlisted log groups.
- `kubernetes_health_summary` summarizes pod readiness, restart and unhealthy states.
- `github_actions_failure_diagnosis` classifies failed jobs using bounded, redacted job-log evidence.
- `correlate_incident_signals` relates metrics, logs, alerts, Kubernetes and CI/CD evidence.

### Supplied-evidence intelligence tools

- `assess_cloud_health` produces a deterministic 0-100 health score and recommended actions from normalized operational evidence.
- `correlate_deployment_incident` builds a post-deployment timeline and reports strong, possible or insufficient evidence of a deployment relationship without assigning root cause.
- `assess_observability_coverage` measures coverage across metrics, logs, alerts, dashboards, SLOs, tracing, deployment markers and an on-call runbook.
- `analyze_finops_waste` links cloud waste signals to Terraform ownership and identifies low-utilization Kubernetes workloads from caller-supplied usage data.
- `detect_configuration_drift` compares expected and live cloud resources plus Kubernetes workloads without reconciling them.
- `generate_operations_brief` summarizes service health, incidents, deployments, SLO status, drift and FinOps findings into one operator-facing brief.

The six intelligence tools make no external calls and remain read-only. Live integrations retain the same endpoint, account, log-group, cluster, namespace and repository allowlists described in the configuration guide.

## Optional v0.9 distributed tracing and SLO intelligence

These tools appear only when `CLOUD_DEVOPS_MCP_TRACING_ENABLED=true`.

### `trace_search`

Searches an explicitly allowlisted Grafana Tempo or Jaeger backend over a bounded time window and returns normalized trace summaries. Tempo supports bounded TraceQL. Jaeger uses the stable v3 JSON/HTTP trace-summary API.

### `trace_summary`

Retrieves one trace by 64-bit or 128-bit hexadecimal trace ID from an allowlisted Tempo or Jaeger backend and summarizes service names, operations, error spans, root spans, duration and slow spans from OpenTelemetry-style trace data.

### `trace_dependency_map`

Builds caller-to-callee service edges from supplied parent/child span relationships and reports call counts, error counts, error rates and average child-span duration.

### `assess_tracing_coverage`

Assesses tracing coverage for inbound requests, outbound dependencies, databases, messaging, span error status, service/environment/version attributes, trace-log correlation and documented sampling policy.

### `analyze_slo_burn_rate`

Calculates short- and long-window request-failure burn rates against a supplied SLO target, classifies the current burn signal and estimates the time required to consume a 30-day error budget if the observed maximum rate persists.

### `correlate_trace_slo_incident`

Correlates representative trace evidence with SLO burn, dependency edges and optional deployment timing. It reports evidence strength and problematic dependencies without assigning or ranking a root cause.

The live trace tools are bounded and read-only. The analysis tools make no external calls. No v0.9 tool ingests traces, mutates sampling, deletes telemetry or changes tracing-backend state.

## Optional v0.10 OpsChugex root-cause intelligence

This tool appears only when `CLOUD_DEVOPS_MCP_OPSCHUGEX_INTELLIGENCE_ENABLED=true`.

### `diagnose_root_cause`

Accepts bounded incident evidence from metrics, logs, traces, Kubernetes, cloud, Terraform and CI/CD and forwards it to the host-configured private OpsChugex intelligence service. The response contains evidence-ranked probable causes, supporting and contradicting evidence IDs, evidence-strength scores, limitations and recommended next checks.

The public MCP does not contain the ranking algorithm, does not accept endpoint URLs or credentials as tool arguments, and does not remediate the incident. Evidence scores are not statistical probabilities and should not be treated as proof of causation.

## Optional v0.11 OpsChugex policy and governance intelligence

This tool appears only when `CLOUD_DEVOPS_MCP_OPSCHUGEX_GOVERNANCE_ENABLED=true`.

### `assess_governance_policy`

Accepts bounded factual resource evidence plus optional owner-attributed, time-bounded governance exceptions and forwards them to the host-configured private OpsChugex policy service.

The returned assessment contains:

- the selected governance profile
- `pass`, `review`, or `block`
- a governance score
- control findings and severities
- whether an approved exception was applied
- evidence gaps
- expired exception identifiers
- a concise summary

The public MCP does not contain the private profile rules, policy thresholds, scoring weights or exception-evaluation algorithm. The tool is read-only and does not modify tags, IAM, network configuration, encryption, backups, Terraform, Kubernetes or cloud resources.

## Optional v0.12 OpsChugex cloud security posture intelligence

This tool appears only when `CLOUD_DEVOPS_MCP_OPSCHUGEX_SECURITY_ENABLED=true`.

### `assess_cloud_security_posture`

Accepts bounded factual evidence for cloud assets, identities, secret exposures and network reachability and forwards it to the host-configured private OpsChugex security service.

The returned assessment contains:

- security score and risk level
- ordered security findings
- critical-finding count
- correlated attack paths
- explicit evidence gaps
- recommended next actions

The public MCP does not contain the private detection thresholds, severity rules, scoring algorithm or attack-path correlation logic. The tool is read-only and does not rotate credentials, change IAM, modify network controls, alter encryption settings or remediate infrastructure.

## Optional v0.13 OpsChugex advanced FinOps intelligence

This tool appears only when `CLOUD_DEVOPS_MCP_OPSCHUGEX_FINOPS_ENABLED=true`.

### `analyze_advanced_finops`

Accepts bounded factual cloud-cost, utilization and Kubernetes allocation evidence and forwards it to the host-configured private OpsChugex FinOps service.

The returned assessment contains:

- analyzed monthly and annual cost
- low/high estimated savings ranges
- savings percentages
- ordered optimization opportunities
- cost anomaly count
- confidence and priority
- Kubernetes/cloud cost correlations
- double-count prevention indicators
- evidence gaps and a concise summary

The public MCP does not contain the private savings factors, anomaly thresholds, prioritization, confidence or portfolio-deduplication algorithm. The tool is read-only and does not resize, terminate, purchase commitments, mutate Kubernetes, change storage tiers or perform billing actions.
