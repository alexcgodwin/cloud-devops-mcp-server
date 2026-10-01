# Demo

This page shows practical examples of what Cloud DevOps MCP Server returns to an MCP client.

## Cross-domain cloud change bundle

Input excerpt:

```json
{
  "changeName": "payments-production-release",
  "environment": "production",
  "terraform": {
    "changedResources": ["network", "iam", "kubernetes"],
    "includesIamChanges": true,
    "includesPublicIngress": true,
    "hasRollbackPlan": true,
    "hasPeerReview": true,
    "hasTerraformPlan": true
  },
  "iamPolicies": [
    {
      "policyName": "payments-deployer",
      "actions": ["iam:PassRole"],
      "resources": ["*"],
      "hasConditionBlocks": false,
      "usedByProduction": true
    }
  ],
  "kubernetesWorkloads": [
    {
      "workloadName": "payments-api",
      "namespace": "production",
      "replicas": 2,
      "hasReadinessProbe": true,
      "hasLivenessProbe": true,
      "hasResourceRequests": true,
      "hasResourceLimits": true,
      "hasPodDisruptionBudget": true,
      "usesLatestTag": false,
      "runsAsRoot": false,
      "exposesPublicService": true
    }
  ],
  "githubWorkflows": [
    {
      "workflowName": "deploy-production",
      "triggers": ["push"],
      "deploysToProduction": true,
      "usesPinnedActions": true,
      "hasLeastPrivilegePermissions": true,
      "hasSecretScanning": true,
      "hasDependencyCaching": true,
      "hasEnvironmentProtection": false,
      "hasConcurrencyControl": true
    }
  ]
}
```

Output excerpt:

```json
{
  "bundleRiskLevel": "critical",
  "releaseGate": "hold-for-remediation",
  "suppliedDomains": [
    "terraform",
    "iam",
    "kubernetes",
    "github_actions"
  ],
  "correlatedFindings": [
    {
      "ruleId": "BUNDLE-PUBLIC-EXPOSURE",
      "severity": "critical",
      "domains": ["terraform", "kubernetes"]
    },
    {
      "ruleId": "BUNDLE-PRIVILEGED-PROD-DELIVERY",
      "severity": "critical",
      "domains": ["iam", "github_actions"]
    }
  ]
}
```

The bundle tool does not replace the individual reviewers. It reuses their evidence and then evaluates combinations that increase release risk across layers.

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

Output excerpt:

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
  "signals": [
    "error rate above 8%",
    "latency p95 above 2s",
    "new release deployed 20 minutes ago"
  ]
}
```

Output excerpt:

```json
{
  "title": "payments-api SEV2 incident runbook",
  "firstFifteenMinutes": [
    "Acknowledge the incident and assign an incident commander.",
    "Confirm customer impact, affected regions, affected services and start time."
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

Output excerpt:

```json
{
  "pipelineName": "prod-api-release",
  "readinessScore": 100,
  "readinessLevel": "production-ready",
  "deploymentStrategy": "canary"
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

Output excerpt:

```json
{
  "allowedDowntimeMinutes": 43.2,
  "remainingDowntimeMinutes": 25.2,
  "budgetStatus": "within-budget",
  "allowedFailedRequests": 4999,
  "remainingFailedRequests": 3799
}
```

## IAM policy review

Input:

```json
{
  "policyName": "prod-admin-helper",
  "actions": ["iam:PassRole", "sts:AssumeRole", "s3:*"],
  "resources": ["*"],
  "hasConditionBlocks": false,
  "usedByProduction": true
}
```

Output excerpt:

```json
{
  "policyName": "prod-admin-helper",
  "riskLevel": "critical",
  "findings": [
    "Replace wildcard actions with the smallest explicit action set required by the workload.",
    "Scope wildcard resource patterns to the narrowest ARNs supported by each action.",
    "Review privilege-escalation paths such as iam:PassRole, sts:AssumeRole, policy attachment and access-key creation."
  ]
}
```

## Kubernetes deployment review

Input:

```json
{
  "workloadName": "checkout-api",
  "namespace": "production",
  "replicas": 3,
  "hasReadinessProbe": true,
  "hasLivenessProbe": true,
  "hasResourceRequests": true,
  "hasResourceLimits": true,
  "hasPodDisruptionBudget": true,
  "usesLatestTag": false,
  "runsAsRoot": false,
  "exposesPublicService": false
}
```

Output excerpt:

```json
{
  "workloadName": "checkout-api",
  "namespace": "production",
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
  "triggers": ["push"],
  "deploysToProduction": true,
  "usesPinnedActions": true,
  "hasLeastPrivilegePermissions": true,
  "hasSecretScanning": true,
  "hasDependencyCaching": true,
  "hasEnvironmentProtection": true,
  "hasConcurrencyControl": true
}
```

Output excerpt:

```json
{
  "workflowName": "deploy-production",
  "workflowScore": 100,
  "readinessLevel": "production-ready",
  "findings": []
}
```
