# Tools

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
