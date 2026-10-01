# Demo

This page shows practical examples of what Cloud DevOps MCP Server returns to an MCP client.

## Terraform change risk

Input:

```json
{
  "changedResources": ["network", "iam", "kubernetes"],
  "includesIamChanges": true,
  "includesPublicIngress": true,
  "modifiesStatefulResources": false,
  "hasRollbackPlan": true,
  "hasPeerReview": true,
  "hasTerraformPlan": true
}
```

Output:

```json
{
  "riskScore": 78,
  "riskLevel": "critical",
  "changedResources": ["network", "iam", "kubernetes"],
  "recommendedReleasePath": "Change-advisory review, maintenance window and staged execution are recommended."
}
```

## Incident runbook

Input:

```json
{
  "service": "payments-api",
  "environment": "production",
  "severity": "sev2",
  "symptom": "Elevated 5xx errors after deployment",
  "signals": ["error rate above 8%", "latency p95 above 2s", "new release deployed 20 minutes ago"]
}
```

Output excerpt:

```json
{
  "title": "payments-api SEV2 incident runbook",
  "firstFifteenMinutes": [
    "Acknowledge the incident and assign an incident commander.",
    "Confirm customer impact, affected regions, affected services and start time.",
    "Open dashboards for traffic, errors, latency, saturation, deployments and infrastructure events.",
    "Freeze non-essential deployments until impact is understood."
  ],
  "communication": [
    "Post an incident update every 15 minutes until the service is stable.",
    "Keep customer-facing updates short, factual and time-stamped.",
    "Separate investigation detail from executive summary."
  ]
}
```

## CI/CD readiness

Input:

```json
{
  "pipelineName": "prod-api-release",
  "deploymentStrategy": "canary",
  "environments": ["dev", "staging", "production"],
  "hasAutomatedTests": true,
  "hasSecurityScan": true,
  "hasRollback": true,
  "hasArtifactVersioning": true,
  "hasManualApprovalForProduction": true
}
```

Output:

```json
{
  "pipelineName": "prod-api-release",
  "readinessScore": 100,
  "readinessLevel": "production-ready",
  "deploymentStrategy": "canary",
  "strengths": [
    "Automated tests are present.",
    "Security scanning is part of the delivery path.",
    "Rollback is defined.",
    "Artifacts are traceable."
  ]
}
```

## SLO error budget

Input:

```json
{
  "sloTargetPercent": 99.9,
  "periodDays": 30,
  "observedDowntimeMinutes": 18,
  "requestVolume": 5000000,
  "failedRequests": 1200
}
```

Output:

```json
{
  "sloTargetPercent": 99.9,
  "periodDays": 30,
  "allowedDowntimeMinutes": 43.2,
  "observedDowntimeMinutes": 18,
  "remainingDowntimeMinutes": 25.2,
  "budgetStatus": "within-budget",
  "allowedFailedRequests": 4999,
  "failedRequests": 1200,
  "remainingFailedRequests": 3799
}
```

## IAM policy review

Input:

```json
{
  "policyName": "prod-admin-helper",
  "environment": "production",
  "allowedActions": ["iam:PassRole", "sts:AssumeRole", "s3:*"],
  "allowedResources": ["*"],
  "hasConditionBlocks": false,
  "isAttachedToHumanUser": true
}
```

Output excerpt:

```json
{
  "policyName": "prod-admin-helper",
  "riskScore": 100,
  "riskLevel": "critical",
  "findings": [
    "Policy allows wildcard resources.",
    "Policy includes actions commonly used in privilege-escalation paths."
  ]
}
```

## Kubernetes deployment review

Input:

```json
{
  "workloadName": "checkout-api",
  "environment": "production",
  "replicaCount": 3,
  "hasReadinessProbe": true,
  "hasLivenessProbe": true,
  "hasResourceRequests": true,
  "hasResourceLimits": true,
  "hasPodDisruptionBudget": true,
  "usesLatestImageTag": false,
  "runsAsRoot": false,
  "exposesPublicService": false
}
```

Output excerpt:

```json
{
  "workloadName": "checkout-api",
  "readinessScore": 100,
  "readinessLevel": "production-ready",
  "findings": []
}
```

## GitHub Actions workflow review

Input:

```json
{
  "workflowName": "deploy-production",
  "runsOnPullRequestTarget": false,
  "usesPinnedActions": true,
  "hasLeastPrivilegePermissions": true,
  "usesEnvironmentProtection": true,
  "hasConcurrencyControl": true,
  "hasSecretScanning": true,
  "deploysToProduction": true
}
```

Output excerpt:

```json
{
  "workflowName": "deploy-production",
  "readinessScore": 100,
  "readinessLevel": "production-ready",
  "findings": []
}
```
