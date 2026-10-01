export type ChangedResource =
  | "network"
  | "iam"
  | "database"
  | "kubernetes"
  | "compute"
  | "observability"
  | "ci_cd"
  | "dns";

export type RiskLevel = "low" | "medium" | "high" | "critical";

export interface TerraformChangeInput {
  changedResources: ChangedResource[];
  includesIamChanges?: boolean;
  includesPublicIngress?: boolean;
  modifiesStatefulResources?: boolean;
  hasRollbackPlan?: boolean;
  hasPeerReview?: boolean;
  hasTerraformPlan?: boolean;
}

export interface IncidentRunbookInput {
  service: string;
  environment: "dev" | "staging" | "production";
  severity: "sev1" | "sev2" | "sev3" | "sev4";
  symptom: string;
  signals?: string[];
}

export interface PipelineReviewInput {
  pipelineName: string;
  deploymentStrategy: "rolling" | "blue_green" | "canary" | "recreate" | "manual";
  environments: string[];
  hasAutomatedTests?: boolean;
  hasSecurityScan?: boolean;
  hasRollback?: boolean;
  hasArtifactVersioning?: boolean;
  hasManualApprovalForProduction?: boolean;
}

export interface SloBudgetInput {
  sloTargetPercent: number;
  periodDays: number;
  observedDowntimeMinutes: number;
  requestVolume?: number;
  failedRequests?: number;
}

export interface IamPolicyReviewInput {
  policyName: string;
  actions: string[];
  resources: string[];
  hasWildcardActions?: boolean;
  hasWildcardResources?: boolean;
  allowsPrivilegeEscalationActions?: boolean;
  hasConditionBlocks?: boolean;
  usedByProduction?: boolean;
}

export interface KubernetesDeploymentReviewInput {
  workloadName: string;
  namespace: string;
  replicas: number;
  hasReadinessProbe?: boolean;
  hasLivenessProbe?: boolean;
  hasResourceRequests?: boolean;
  hasResourceLimits?: boolean;
  hasPodDisruptionBudget?: boolean;
  usesLatestTag?: boolean;
  runsAsRoot?: boolean;
  exposesPublicService?: boolean;
}

export interface GitHubWorkflowReviewInput {
  workflowName: string;
  triggers: string[];
  deploysToProduction?: boolean;
  usesPinnedActions?: boolean;
  hasLeastPrivilegePermissions?: boolean;
  hasSecretScanning?: boolean;
  hasDependencyCaching?: boolean;
  hasEnvironmentProtection?: boolean;
  hasConcurrencyControl?: boolean;
}

const resourceWeights: Record<ChangedResource, number> = {
  network: 16,
  iam: 18,
  database: 20,
  kubernetes: 14,
  compute: 8,
  observability: 5,
  ci_cd: 7,
  dns: 17
};

function riskLevel(score: number): RiskLevel {
  if (score >= 75) return "critical";
  if (score >= 50) return "high";
  if (score >= 25) return "medium";
  return "low";
}

export function assessTerraformChange(input: TerraformChangeInput) {
  const changedResources = Array.from(new Set(input.changedResources));
  let score = changedResources.reduce((total, resource) => total + resourceWeights[resource], 0);

  if (input.includesIamChanges) score += 12;
  if (input.includesPublicIngress) score += 18;
  if (input.modifiesStatefulResources) score += 18;
  if (!input.hasRollbackPlan) score += 12;
  if (!input.hasPeerReview) score += 10;
  if (!input.hasTerraformPlan) score += 16;

  const riskScore = Math.min(score, 100);
  const checklist = [
    "Confirm Terraform plan output has been reviewed against expected resource drift.",
    "Validate provider versions, module versions and state backend configuration.",
    "Check that monitoring, logging and rollback paths are ready before apply."
  ];

  if (input.includesIamChanges || changedResources.includes("iam")) {
    checklist.push("Review IAM changes for least privilege, privilege escalation and service-account blast radius.");
  }

  if (input.includesPublicIngress || changedResources.includes("network")) {
    checklist.push("Validate public ingress, security groups, network ACLs, DNS and TLS paths.");
  }

  if (input.modifiesStatefulResources || changedResources.includes("database")) {
    checklist.push("Confirm backup, restore, migration and data rollback procedures before deployment.");
  }

  if (!input.hasRollbackPlan) {
    checklist.push("Add a rollback or forward-fix plan with an owner, trigger condition and validation step.");
  }

  return {
    riskScore,
    riskLevel: riskLevel(riskScore),
    changedResources,
    checklist,
    recommendedReleasePath:
      riskScore >= 75
        ? "Change-advisory review, maintenance window and staged execution are recommended."
        : riskScore >= 50
          ? "Use staged rollout, peer review and post-apply validation before broad release."
          : riskScore >= 25
            ? "Proceed with standard review, automated checks and rollback readiness."
            : "Low-risk change. Keep normal review, plan output and validation evidence."
  };
}

export function buildIncidentRunbook(input: IncidentRunbookInput) {
  const normalizedSignals = input.signals?.filter(Boolean) ?? [];
  const isProduction = input.environment === "production";
  const urgent = input.severity === "sev1" || input.severity === "sev2";

  return {
    title: `${input.service} ${input.severity.toUpperCase()} incident runbook`,
    context: {
      service: input.service,
      environment: input.environment,
      symptom: input.symptom,
      signals: normalizedSignals
    },
    firstFifteenMinutes: [
      "Acknowledge the incident and assign an incident commander.",
      "Confirm customer impact, affected regions, affected services and start time.",
      "Open dashboards for traffic, errors, latency, saturation, deployments and infrastructure events.",
      "Freeze non-essential deployments until impact is understood."
    ],
    triageSteps: [
      "Compare current metrics with the last known healthy baseline.",
      "Check recent deployments, infrastructure changes, secrets rotation and dependency status.",
      "Inspect logs for error-rate shifts, throttling, connection failures and authorization failures.",
      "Validate cloud control-plane health, DNS, certificates and network paths.",
      "Decide whether rollback, traffic shift, scale-out or dependency failover is the safest action."
    ],
    communication: urgent
      ? [
          "Post an incident update every 15 minutes until the service is stable.",
          "Keep customer-facing updates short, factual and time-stamped.",
          "Separate investigation detail from executive summary."
        ]
      : [
          "Post an internal update when impact is confirmed.",
          "Document the owner, current hypothesis and next checkpoint."
        ],
    mitigation: [
      isProduction ? "Prefer reversible mitigation before risky repair in production." : "Use the lower environment to reproduce and validate the fix.",
      "Rollback the most recent risky change if evidence points to deployment regression.",
      "Scale capacity or shed non-critical load if saturation is confirmed.",
      "Escalate to dependency owners when third-party, network or platform evidence is clear."
    ],
    rcaEvidence: [
      "Incident timeline with detection, acknowledgement, mitigation and recovery times.",
      "Dashboards, logs, traces and cloud activity events used for decisions.",
      "Customer impact summary and affected transaction path.",
      "Corrective actions with owners, due dates and verification method."
    ]
  };
}

export function reviewPipeline(input: PipelineReviewInput) {
  let score = 0;
  const findings: string[] = [];

  if (input.hasAutomatedTests) score += 25;
  else findings.push("Add automated unit, integration or smoke tests before deployment.");

  if (input.hasSecurityScan) score += 20;
  else findings.push("Add dependency, container or static security scanning to the pipeline.");

  if (input.hasRollback) score += 20;
  else findings.push("Define a rollback path and prove it with at least one validation scenario.");

  if (input.hasArtifactVersioning) score += 15;
  else findings.push("Version build artifacts so every deployment can be traced back to a commit.");

  if (input.deploymentStrategy === "canary" || input.deploymentStrategy === "blue_green") score += 15;
  if (input.deploymentStrategy === "rolling") score += 10;
  if (input.deploymentStrategy === "recreate") findings.push("Avoid recreate deployments for production services that require availability.");
  if (input.deploymentStrategy === "manual") findings.push("Manual deployment should be replaced with an audited, repeatable pipeline.");

  if (input.environments.length >= 3) score += 5;
  if (input.hasManualApprovalForProduction) score += 5;

  const readinessScore = Math.min(score, 100);

  return {
    pipelineName: input.pipelineName,
    readinessScore,
    readinessLevel: readinessScore >= 85 ? "production-ready" : readinessScore >= 65 ? "needs-hardening" : "not-ready",
    deploymentStrategy: input.deploymentStrategy,
    strengths: [
      input.hasAutomatedTests ? "Automated tests are present." : undefined,
      input.hasSecurityScan ? "Security scanning is part of the delivery path." : undefined,
      input.hasRollback ? "Rollback is defined." : undefined,
      input.hasArtifactVersioning ? "Artifacts are traceable." : undefined
    ].filter(Boolean),
    findings,
    recommendedGates: [
      "Build must be reproducible from source control.",
      "Deployment must publish version, commit SHA and environment evidence.",
      "Production release must include health checks and rollback validation.",
      "Pipeline must fail closed when tests, scans or policy checks fail."
    ]
  };
}

export function estimateSloBudget(input: SloBudgetInput) {
  if (input.sloTargetPercent <= 0 || input.sloTargetPercent >= 100) {
    throw new Error("sloTargetPercent must be greater than 0 and less than 100.");
  }

  if (input.periodDays <= 0) {
    throw new Error("periodDays must be greater than 0.");
  }

  const totalMinutes = input.periodDays * 24 * 60;
  const allowedDowntimeMinutes = totalMinutes * (1 - input.sloTargetPercent / 100);
  const remainingDowntimeMinutes = allowedDowntimeMinutes - input.observedDowntimeMinutes;

  const result: Record<string, unknown> = {
    sloTargetPercent: input.sloTargetPercent,
    periodDays: input.periodDays,
    allowedDowntimeMinutes: Number(allowedDowntimeMinutes.toFixed(2)),
    observedDowntimeMinutes: input.observedDowntimeMinutes,
    remainingDowntimeMinutes: Number(remainingDowntimeMinutes.toFixed(2)),
    budgetStatus: remainingDowntimeMinutes >= 0 ? "within-budget" : "exhausted"
  };

  if (input.requestVolume !== undefined && input.failedRequests !== undefined) {
    const allowedFailedRequests = input.requestVolume * (1 - input.sloTargetPercent / 100);
    result.allowedFailedRequests = Math.floor(allowedFailedRequests);
    result.failedRequests = input.failedRequests;
    result.remainingFailedRequests = Math.floor(allowedFailedRequests - input.failedRequests);
  }

  return result;
}

export function reviewIamPolicy(input: IamPolicyReviewInput) {
  let riskScore = 0;
  const findings: string[] = [];
  const strengths: string[] = [];

  if (input.hasWildcardActions || input.actions.some((action) => action.includes("*"))) {
    riskScore += 28;
    findings.push("Replace wildcard actions with the smallest explicit action set required by the workload.");
  } else {
    strengths.push("Actions are explicitly scoped.");
  }

  if (input.hasWildcardResources || input.resources.some((resource) => resource === "*" || resource.endsWith(":*"))) {
    riskScore += 24;
    findings.push("Scope resources to specific ARNs or controlled resource patterns instead of broad wildcards.");
  } else {
    strengths.push("Resources are explicitly scoped.");
  }

  if (input.allowsPrivilegeEscalationActions) {
    riskScore += 26;
    findings.push("Review privilege-escalation paths such as iam:PassRole, sts:AssumeRole, policy attachment and access-key creation.");
  }

  if (!input.hasConditionBlocks) {
    riskScore += 12;
    findings.push("Add condition blocks for account, region, source identity, resource tags or network boundaries where possible.");
  } else {
    strengths.push("Condition blocks are present.");
  }

  if (input.usedByProduction) {
    riskScore += 10;
  }

  const boundedRiskScore = Math.min(riskScore, 100);

  return {
    policyName: input.policyName,
    riskScore: boundedRiskScore,
    riskLevel: riskLevel(boundedRiskScore),
    strengths,
    findings,
    recommendedControls: [
      "Use least privilege and remove unused permissions after access analysis.",
      "Prefer role-based access with short-lived credentials over long-lived keys.",
      "Require peer review for IAM changes and attach evidence to the change record.",
      "Validate CloudTrail, Access Analyzer or equivalent evidence before production rollout."
    ]
  };
}

export function reviewKubernetesDeployment(input: KubernetesDeploymentReviewInput) {
  let readinessScore = 100;
  const findings: string[] = [];
  const strengths: string[] = [];

  if (input.replicas < 2) {
    readinessScore -= 18;
    findings.push("Run at least two replicas for production workloads that need availability.");
  } else {
    strengths.push("Replica count supports basic availability.");
  }

  if (!input.hasReadinessProbe) {
    readinessScore -= 16;
    findings.push("Add a readiness probe so traffic only reaches pods that can serve requests.");
  } else {
    strengths.push("Readiness probe is present.");
  }

  if (!input.hasLivenessProbe) {
    readinessScore -= 10;
    findings.push("Add a liveness probe to recover stuck application processes.");
  }

  if (!input.hasResourceRequests) {
    readinessScore -= 14;
    findings.push("Add CPU and memory requests so the scheduler can place pods safely.");
  }

  if (!input.hasResourceLimits) {
    readinessScore -= 10;
    findings.push("Add resource limits to reduce noisy-neighbor and runaway-memory risk.");
  }

  if (!input.hasPodDisruptionBudget) {
    readinessScore -= 12;
    findings.push("Add a PodDisruptionBudget for safer node maintenance and voluntary disruptions.");
  }

  if (input.usesLatestTag) {
    readinessScore -= 12;
    findings.push("Avoid the latest image tag. Use immutable image tags or digests for traceable rollbacks.");
  }

  if (input.runsAsRoot) {
    readinessScore -= 12;
    findings.push("Run containers as a non-root user and enforce a restricted security context.");
  }

  if (input.exposesPublicService) {
    readinessScore -= 8;
    findings.push("Validate public exposure, ingress rules, TLS, WAF or network policy before rollout.");
  }

  const boundedReadinessScore = Math.max(readinessScore, 0);

  return {
    workloadName: input.workloadName,
    namespace: input.namespace,
    readinessScore: boundedReadinessScore,
    readinessLevel:
      boundedReadinessScore >= 85 ? "production-ready" : boundedReadinessScore >= 65 ? "needs-hardening" : "not-ready",
    strengths,
    findings,
    recommendedControls: [
      "Deploy with health checks, resource controls and immutable images.",
      "Require rollout monitoring for errors, latency, saturation and restart loops.",
      "Keep rollback instructions tied to the deployed image or Helm release.",
      "Use network policy and least-privilege service accounts for production namespaces."
    ]
  };
}

export function reviewGitHubActionsWorkflow(input: GitHubWorkflowReviewInput) {
  let score = 100;
  const findings: string[] = [];
  const strengths: string[] = [];

  if (input.triggers.includes("pull_request_target")) {
    score -= 18;
    findings.push("Avoid pull_request_target for untrusted code unless the workflow is tightly constrained.");
  }

  if (!input.usesPinnedActions) {
    score -= 16;
    findings.push("Pin third-party actions to commit SHAs or trusted release tags to reduce supply-chain risk.");
  } else {
    strengths.push("Actions are pinned or version controlled.");
  }

  if (!input.hasLeastPrivilegePermissions) {
    score -= 18;
    findings.push("Set explicit least-privilege GITHUB_TOKEN permissions instead of relying on defaults.");
  } else {
    strengths.push("Workflow permissions are explicitly scoped.");
  }

  if (!input.hasSecretScanning) {
    score -= 10;
    findings.push("Add secret scanning or a pre-deploy guard for accidental credential exposure.");
  }

  if (!input.hasDependencyCaching) {
    score -= 6;
    findings.push("Add dependency caching where safe to improve repeatability and build speed.");
  }

  if (input.deploysToProduction && !input.hasEnvironmentProtection) {
    score -= 18;
    findings.push("Use protected environments, required reviewers or deployment approvals for production.");
  }

  if (input.deploysToProduction && !input.hasConcurrencyControl) {
    score -= 10;
    findings.push("Add concurrency controls to prevent overlapping production deployments.");
  }

  const workflowScore = Math.max(score, 0);

  return {
    workflowName: input.workflowName,
    workflowScore,
    readinessLevel: workflowScore >= 85 ? "production-ready" : workflowScore >= 65 ? "needs-hardening" : "not-ready",
    strengths,
    findings,
    recommendedControls: [
      "Pin actions, scope token permissions and protect production environments.",
      "Publish build provenance such as commit SHA, artifact version and deployment environment.",
      "Fail closed when tests, security checks or policy gates fail.",
      "Keep secrets in managed secret stores and rotate credentials used by workflows."
    ]
  };
}
