import { parseAllDocuments, parse as parseYaml } from "yaml";

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
export type ReadinessLevel = "production-ready" | "needs-review" | "needs-hardening" | "not-ready";
export type AssessmentConfidence = "high" | "medium" | "low";

export interface EvidenceItem {
  source: string;
  ruleId: string;
  detail: string;
}

export interface TerraformChangeInput {
  changedResources?: ChangedResource[];
  terraformPlanJson?: string;
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
  actions?: string[];
  resources?: string[];
  policyJson?: string;
  hasWildcardActions?: boolean;
  hasWildcardResources?: boolean;
  allowsPrivilegeEscalationActions?: boolean;
  hasConditionBlocks?: boolean;
  usedByProduction?: boolean;
}

export interface KubernetesDeploymentReviewInput {
  workloadName?: string;
  namespace?: string;
  replicas?: number;
  manifestYaml?: string;
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
  workflowYaml?: string;
  triggers?: string[];
  deploysToProduction?: boolean;
  usesPinnedActions?: boolean;
  hasLeastPrivilegePermissions?: boolean;
  hasSecretScanning?: boolean;
  hasDependencyCaching?: boolean;
  hasEnvironmentProtection?: boolean;
  hasConcurrencyControl?: boolean;
}

export interface CloudChangeBundleInput {
  changeName: string;
  environment: "dev" | "staging" | "production";
  terraform?: TerraformChangeInput;
  iamPolicies?: IamPolicyReviewInput[];
  kubernetesWorkloads?: KubernetesDeploymentReviewInput[];
  githubWorkflows?: GitHubWorkflowReviewInput[];
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

const privilegeEscalationActions = [
  "iam:passrole",
  "sts:assumerole",
  "iam:attachrolepolicy",
  "iam:attachuserpolicy",
  "iam:attachgrouppolicy",
  "iam:putrolepolicy",
  "iam:putuserpolicy",
  "iam:putgrouppolicy",
  "iam:createaccesskey",
  "iam:updateassumerolepolicy"
];

function riskLevel(score: number): RiskLevel {
  if (score >= 75) return "critical";
  if (score >= 50) return "high";
  if (score >= 25) return "medium";
  return "low";
}

function confidence(known: number, total: number): AssessmentConfidence {
  const ratio = total === 0 ? 1 : known / total;
  if (ratio >= 0.8) return "high";
  if (ratio >= 0.5) return "medium";
  return "low";
}

function readinessLevel(score: number, uncertainties: string[]): ReadinessLevel {
  if (score < 65) return "not-ready";
  if (score < 85) return "needs-hardening";
  return uncertainties.length > 0 ? "needs-review" : "production-ready";
}

function asStrings(value: unknown): string[] {
  if (typeof value === "string") return [value];
  if (Array.isArray(value)) return value.filter((item): item is string => typeof item === "string");
  return [];
}

function parseJsonObject(input: string, label: string): Record<string, unknown> {
  let parsed: unknown;
  try {
    parsed = JSON.parse(input);
  } catch {
    throw new Error(`${label} must be valid JSON.`);
  }
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
    throw new Error(`${label} must be a JSON object.`);
  }
  return parsed as Record<string, unknown>;
}

function classifyTerraformResource(type: string): ChangedResource | undefined {
  const value = type.toLowerCase();
  if (/(_iam_|role_assignment|project_iam|service_account_iam)/.test(value)) return "iam";
  if (/(route53|dns_)/.test(value)) return "dns";
  if (/(rds|dynamodb|cosmos|sql_|database|db_instance|db_cluster|postgres|mysql)/.test(value)) return "database";
  if (/(kubernetes_|helm_release|eks_|kubernetes_cluster|container_cluster)/.test(value)) return "kubernetes";
  if (/(vpc|subnet|security_group|network_acl|firewall|route_table|load_balancer|application_gateway|network_security_group|nat_gateway)/.test(value)) return "network";
  if (/(cloudwatch|log_analytics|monitor_|grafana|prometheus|observability)/.test(value)) return "observability";
  if (/(codepipeline|codebuild|github_|gitlab_|pipeline)/.test(value)) return "ci_cd";
  if (/(instance|lambda|function|app_service|container_service|virtual_machine|autoscaling)/.test(value)) return "compute";
  return undefined;
}

function analyzeTerraformPlan(planJson: string) {
  const plan = parseJsonObject(planJson, "terraformPlanJson");
  const resourceChanges = Array.isArray(plan.resource_changes) ? plan.resource_changes : [];
  const changedResources = new Set<ChangedResource>();
  const evidence: EvidenceItem[] = [];
  let includesIamChanges = false;
  let includesPublicIngress = false;
  let modifiesStatefulResources = false;

  for (const raw of resourceChanges) {
    if (typeof raw !== "object" || raw === null) continue;
    const item = raw as Record<string, unknown>;
    const type = typeof item.type === "string" ? item.type : "";
    const resourceClass = classifyTerraformResource(type);
    if (resourceClass) changedResources.add(resourceClass);
    if (resourceClass === "iam") includesIamChanges = true;

    const change = typeof item.change === "object" && item.change !== null
      ? item.change as Record<string, unknown>
      : {};
    const actions = asStrings(change.actions);
    if (actions.length === 0 || actions.every((action) => action === "no-op" || action === "read")) continue;

    const address = typeof item.address === "string" ? item.address : type || "unknown resource";
    const afterText = JSON.stringify(change.after ?? {}).toLowerCase();

    if (
      afterText.includes("0.0.0.0/0") ||
      afterText.includes("::/0") ||
      /"publicly_accessible"\s*:\s*true/.test(afterText) ||
      /"public_network_access_enabled"\s*:\s*true/.test(afterText)
    ) {
      includesPublicIngress = true;
      evidence.push({
        source: "terraform-plan",
        ruleId: "TF-PUBLIC-INGRESS",
        detail: `${address} contains public network exposure indicators.`
      });
    }

    if (
      resourceClass === "database" ||
      /(ebs|efs|volume|disk|storage|bucket|s3_|sqs|queue|kafka|redis|elasticache)/.test(type.toLowerCase())
    ) {
      modifiesStatefulResources = true;
      evidence.push({
        source: "terraform-plan",
        ruleId: "TF-STATEFUL",
        detail: `${address} changes a stateful or persistent resource.`
      });
    }

    if (resourceClass) {
      evidence.push({
        source: "terraform-plan",
        ruleId: "TF-RESOURCE-CLASS",
        detail: `${address} classified as ${resourceClass}.`
      });
    }
  }

  return {
    changedResources: [...changedResources],
    includesIamChanges,
    includesPublicIngress,
    modifiesStatefulResources,
    evidence
  };
}

export function assessTerraformChange(input: TerraformChangeInput) {
  if ((!input.changedResources || input.changedResources.length === 0) && !input.terraformPlanJson) {
    throw new Error("Provide changedResources or terraformPlanJson.");
  }

  const derived = input.terraformPlanJson ? analyzeTerraformPlan(input.terraformPlanJson) : undefined;
  const changedResources = Array.from(new Set([
    ...(input.changedResources ?? []),
    ...(derived?.changedResources ?? [])
  ]));

  const includesIamChanges = derived?.includesIamChanges || input.includesIamChanges === true;
  const includesPublicIngress = derived?.includesPublicIngress || input.includesPublicIngress === true;
  const modifiesStatefulResources = derived?.modifiesStatefulResources || input.modifiesStatefulResources === true;
  const hasTerraformPlan = input.terraformPlanJson ? true : input.hasTerraformPlan;

  let score = changedResources.reduce((total, resource) => total + resourceWeights[resource], 0);
  if (includesIamChanges) score += 12;
  if (includesPublicIngress) score += 18;
  if (modifiesStatefulResources) score += 18;
  if (input.hasRollbackPlan === false) score += 12;
  if (input.hasPeerReview === false) score += 10;
  if (hasTerraformPlan === false) score += 16;

  const uncertainties: string[] = [];
  if (input.hasRollbackPlan === undefined) uncertainties.push("Rollback or forward-fix plan was not stated.");
  if (input.hasPeerReview === undefined) uncertainties.push("Peer-review status was not stated.");
  if (hasTerraformPlan === undefined) uncertainties.push("Terraform plan or equivalent preview evidence was not stated.");

  const checklist = [
    "Confirm Terraform plan output has been reviewed against expected resource drift.",
    "Validate provider versions, module versions and state backend configuration.",
    "Check that monitoring, logging and rollback paths are ready before apply."
  ];

  if (includesIamChanges || changedResources.includes("iam")) {
    checklist.push("Review IAM changes for least privilege, privilege escalation and service-account blast radius.");
  }
  if (includesPublicIngress || changedResources.includes("network")) {
    checklist.push("Validate public ingress, security groups, network ACLs, DNS and TLS paths.");
  }
  if (modifiesStatefulResources || changedResources.includes("database")) {
    checklist.push("Confirm backup, restore, migration and data rollback procedures before deployment.");
  }
  if (input.hasRollbackPlan === false) {
    checklist.push("Add a rollback or forward-fix plan with an owner, trigger condition and validation step.");
  }

  const riskScore = Math.min(score, 100);
  return {
    riskScore,
    riskLevel: riskLevel(riskScore),
    changedResources,
    evidence: derived?.evidence ?? [],
    uncertainties,
    assessmentConfidence: confidence(3 - uncertainties.length, 3),
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
  const normalizedSignals = input.signals?.map((signal) => signal.trim()).filter(Boolean) ?? [];
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
  let score = 100;
  const findings: string[] = [];
  const strengths: string[] = [];
  const uncertainties: string[] = [];

  const checks: Array<[boolean | undefined, number, string, string]> = [
    [input.hasAutomatedTests, 25, "Add automated unit, integration or smoke tests before deployment.", "Automated tests are present."],
    [input.hasSecurityScan, 20, "Add dependency, container or static security scanning to the pipeline.", "Security scanning is part of the delivery path."],
    [input.hasRollback, 20, "Define a rollback path and prove it with at least one validation scenario.", "Rollback is defined."],
    [input.hasArtifactVersioning, 15, "Version build artifacts so every deployment can be traced back to a commit.", "Artifacts are traceable."]
  ];

  for (const [value, penalty, finding, strength] of checks) {
    if (value === true) strengths.push(strength);
    else if (value === false) {
      score -= penalty;
      findings.push(finding);
    } else {
      uncertainties.push(finding.replace(/^Add |^Define |^Version /, "Evidence not provided: "));
    }
  }

  if (input.deploymentStrategy === "canary" || input.deploymentStrategy === "blue_green") strengths.push("Progressive deployment strategy is configured.");
  if (input.deploymentStrategy === "rolling") score -= 5;
  if (input.deploymentStrategy === "recreate") {
    score -= 20;
    findings.push("Avoid recreate deployments for production services that require availability.");
  }
  if (input.deploymentStrategy === "manual") {
    score -= 30;
    findings.push("Manual deployment should be replaced with an audited, repeatable pipeline.");
  }

  if (input.environments.length < 2) {
    score -= 10;
    findings.push("Use at least one pre-production environment before production promotion.");
  }

  if (input.hasManualApprovalForProduction === false) {
    score -= 5;
    findings.push("Add controlled production promotion or approval for high-impact releases.");
  } else if (input.hasManualApprovalForProduction === undefined) {
    uncertainties.push("Production approval or controlled-promotion status was not stated.");
  }

  const readinessScore = Math.max(0, Math.min(score, 100));
  return {
    pipelineName: input.pipelineName,
    readinessScore,
    readinessLevel: readinessLevel(readinessScore, uncertainties),
    assessmentConfidence: confidence(5 - uncertainties.length, 5),
    deploymentStrategy: input.deploymentStrategy,
    strengths,
    findings,
    uncertainties,
    recommendedGates: [
      "Build must be reproducible from source control.",
      "Deployment must publish version, commit SHA and environment evidence.",
      "Production release must include health checks and rollback validation.",
      "Pipeline must fail closed when tests, scans or policy checks fail."
    ]
  };
}

export function estimateSloBudget(input: SloBudgetInput) {
  if ((input.requestVolume === undefined) !== (input.failedRequests === undefined)) {
    throw new Error("requestVolume and failedRequests must be provided together.");
  }
  if (input.requestVolume !== undefined && input.failedRequests !== undefined && input.failedRequests > input.requestVolume) {
    throw new Error("failedRequests cannot exceed requestVolume.");
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

function analyzeIamPolicy(policyJson: string) {
  const policy = parseJsonObject(policyJson, "policyJson");
  const statements = Array.isArray(policy.Statement) ? policy.Statement : policy.Statement ? [policy.Statement] : [];
  const actions: string[] = [];
  const resources: string[] = [];
  const evidence: EvidenceItem[] = [];
  let hasConditionBlocks = false;
  let usesNotAction = false;
  let usesNotResource = false;

  for (const raw of statements) {
    if (typeof raw !== "object" || raw === null) continue;
    const statement = raw as Record<string, unknown>;
    actions.push(...asStrings(statement.Action));
    resources.push(...asStrings(statement.Resource));
    if (statement.Condition && typeof statement.Condition === "object") hasConditionBlocks = true;
    if (statement.NotAction !== undefined) usesNotAction = true;
    if (statement.NotResource !== undefined) usesNotResource = true;
  }

  const normalizedActions = actions.map((action) => action.toLowerCase());
  const wildcardActions = usesNotAction || normalizedActions.some((action) => action === "*" || action.includes("*"));
  const wildcardResources = usesNotResource || resources.some((resource) => resource.includes("*"));
  const escalationActions = actions.filter((action) => {
    const value = action.toLowerCase();
    return privilegeEscalationActions.some((candidate) => value === candidate) ||
      /^iam:(attach|put|create|update).*/.test(value);
  });

  if (wildcardActions) evidence.push({ source: "iam-policy", ruleId: "IAM-WILDCARD-ACTION", detail: "Policy contains wildcard or NotAction semantics." });
  if (wildcardResources) evidence.push({ source: "iam-policy", ruleId: "IAM-WILDCARD-RESOURCE", detail: "Policy contains wildcard or NotResource resource scope." });
  if (escalationActions.length > 0) evidence.push({
    source: "iam-policy",
    ruleId: "IAM-PRIV-ESC",
    detail: `Potential privilege-escalation actions: ${escalationActions.join(", ")}.`
  });

  return { actions, resources, wildcardActions, wildcardResources, hasConditionBlocks, escalationActions, evidence };
}

export function reviewIamPolicy(input: IamPolicyReviewInput) {
  const derived = input.policyJson ? analyzeIamPolicy(input.policyJson) : undefined;
  const actions = Array.from(new Set([...(input.actions ?? []), ...(derived?.actions ?? [])]));
  const resources = Array.from(new Set([...(input.resources ?? []), ...(derived?.resources ?? [])]));
  if (actions.length === 0 || resources.length === 0) {
    throw new Error("Provide actions/resources or policyJson with IAM statements.");
  }

  const inferredWildcardActions = actions.some((action) => action === "*" || action.includes("*"));
  const inferredWildcardResources = resources.some((resource) => resource.includes("*"));
  const inferredPrivilegeEscalation = actions.some((action) => {
    const value = action.toLowerCase();
    return privilegeEscalationActions.some((candidate) => value === candidate) ||
      /^iam:(attach|put|create|update).*/.test(value);
  });

  const wildcardActions = derived?.wildcardActions ?? input.hasWildcardActions ?? inferredWildcardActions;
  const wildcardResources = derived?.wildcardResources ?? input.hasWildcardResources ?? inferredWildcardResources;
  const allowsPrivilegeEscalationActions = derived
    ? derived.escalationActions.length > 0
    : input.allowsPrivilegeEscalationActions ?? inferredPrivilegeEscalation;
  const hasConditionBlocks = derived?.hasConditionBlocks ?? input.hasConditionBlocks;

  let riskScore = 0;
  const findings: string[] = [];
  const strengths: string[] = [];
  const uncertainties: string[] = [];

  if (wildcardActions === true) {
    riskScore += 28;
    findings.push("Replace wildcard actions with the smallest explicit action set required by the workload.");
  } else if (wildcardActions === false) strengths.push("Actions are explicitly scoped.");
  else uncertainties.push("Wildcard-action status is unknown.");

  if (wildcardResources === true) {
    riskScore += 24;
    findings.push("Scope wildcard resource patterns to the narrowest ARNs supported by each action.");
  } else if (wildcardResources === false) strengths.push("Resources are explicitly scoped.");
  else uncertainties.push("Wildcard-resource status is unknown.");

  if (allowsPrivilegeEscalationActions === true) {
    riskScore += 26;
    findings.push("Review privilege-escalation paths such as iam:PassRole, sts:AssumeRole, policy attachment and access-key creation.");
  } else if (allowsPrivilegeEscalationActions === undefined) {
    uncertainties.push("Privilege-escalation action analysis was not provided.");
  }

  if (hasConditionBlocks === false) {
    riskScore += 12;
    findings.push("Add condition blocks for account, region, source identity, resource tags or network boundaries where possible.");
  } else if (hasConditionBlocks === true) strengths.push("Condition blocks are present.");
  else uncertainties.push("Condition-block usage is unknown.");

  if (input.usedByProduction === true) riskScore += 10;
  else if (input.usedByProduction === undefined) uncertainties.push("Production usage was not stated.");

  const boundedRiskScore = Math.min(riskScore, 100);
  return {
    policyName: input.policyName,
    riskScore: boundedRiskScore,
    riskLevel: riskLevel(boundedRiskScore),
    assessmentConfidence: confidence(5 - uncertainties.length, 5),
    actions,
    resources,
    strengths,
    findings,
    uncertainties,
    evidence: derived?.evidence ?? [],
    recommendedControls: [
      "Use least privilege and remove unused permissions after access analysis.",
      "Prefer role-based access with short-lived credentials over long-lived keys.",
      "Require peer review for IAM changes and attach evidence to the change record.",
      "Validate CloudTrail, Access Analyzer or equivalent evidence before production rollout."
    ]
  };
}

function analyzeKubernetesManifest(manifestYaml: string) {
  const docs = parseAllDocuments(manifestYaml).map((document) => document.toJSON()).filter(Boolean) as Array<Record<string, any>>;
  const workload = docs.find((doc) => ["Deployment", "StatefulSet", "DaemonSet"].includes(doc.kind));
  if (!workload) throw new Error("manifestYaml must include a Deployment, StatefulSet or DaemonSet.");

  const podSpec = workload.spec?.template?.spec ?? {};
  const containers = Array.isArray(podSpec.containers) ? podSpec.containers : [];
  const replicas = typeof workload.spec?.replicas === "number"
    ? workload.spec.replicas
    : workload.kind === "DaemonSet" ? undefined : 1;

  const everyContainer = (predicate: (container: any) => boolean): boolean | undefined =>
    containers.length > 0 ? containers.every(predicate) : undefined;

  const hasReadinessProbe = everyContainer((container) => Boolean(container.readinessProbe));
  const hasLivenessProbe = everyContainer((container) => Boolean(container.livenessProbe));
  const hasResourceRequests = everyContainer((container) => Boolean(container.resources?.requests?.cpu && container.resources?.requests?.memory));
  const hasResourceLimits = everyContainer((container) => Boolean(container.resources?.limits?.cpu && container.resources?.limits?.memory));
  const usesLatestTag = containers.length > 0
    ? containers.some((container: any) => {
        const image = typeof container.image === "string" ? container.image : "";
        if (!image || image.includes("@sha256:")) return false;
        const lastSlash = image.lastIndexOf("/");
        const lastColon = image.lastIndexOf(":");
        return lastColon <= lastSlash || image.endsWith(":latest");
      })
    : undefined;

  const securityContexts = containers.map((container: any) => container.securityContext ?? {});
  let runsAsRoot: boolean | undefined;
  if (securityContexts.some((ctx: any) => ctx.runAsUser === 0 || ctx.runAsNonRoot === false) || podSpec.securityContext?.runAsUser === 0) {
    runsAsRoot = true;
  } else if (
    podSpec.securityContext?.runAsNonRoot === true ||
    securityContexts.length > 0 && securityContexts.every((ctx: any) => ctx.runAsNonRoot === true || (typeof ctx.runAsUser === "number" && ctx.runAsUser > 0))
  ) {
    runsAsRoot = false;
  }

  const hasPodDisruptionBudget = docs.some((doc) => doc.kind === "PodDisruptionBudget");
  const exposesPublicService = docs.some((doc) =>
    doc.kind === "Ingress" ||
    (doc.kind === "Service" && ["LoadBalancer", "NodePort"].includes(doc.spec?.type))
  );

  const metadata = workload.metadata ?? {};
  const evidence: EvidenceItem[] = [
    {
      source: "kubernetes-manifest",
      ruleId: "K8S-WORKLOAD",
      detail: `${workload.kind} ${metadata.name ?? "unnamed"} parsed from manifest.`
    }
  ];

  if (exposesPublicService) evidence.push({ source: "kubernetes-manifest", ruleId: "K8S-PUBLIC", detail: "Manifest includes an Ingress or externally exposed Service." });
  if (usesLatestTag) evidence.push({ source: "kubernetes-manifest", ruleId: "K8S-MUTABLE-IMAGE", detail: "At least one container uses latest or an implicit latest tag." });
  if (runsAsRoot === true) evidence.push({ source: "kubernetes-manifest", ruleId: "K8S-ROOT", detail: "A workload security context permits or explicitly uses root." });

  return {
    workloadName: metadata.name as string | undefined,
    namespace: metadata.namespace as string | undefined,
    replicas,
    hasReadinessProbe,
    hasLivenessProbe,
    hasResourceRequests,
    hasResourceLimits,
    hasPodDisruptionBudget,
    usesLatestTag,
    runsAsRoot,
    exposesPublicService,
    evidence
  };
}

export function reviewKubernetesDeployment(input: KubernetesDeploymentReviewInput) {
  const derived = input.manifestYaml ? analyzeKubernetesManifest(input.manifestYaml) : undefined;
  const workloadName = derived?.workloadName ?? input.workloadName;
  const namespace = derived?.namespace ?? input.namespace ?? "default";
  if (!workloadName) throw new Error("Provide workloadName or manifestYaml with workload metadata.name.");

  const values = {
    replicas: derived?.replicas ?? input.replicas,
    hasReadinessProbe: derived?.hasReadinessProbe ?? input.hasReadinessProbe,
    hasLivenessProbe: derived?.hasLivenessProbe ?? input.hasLivenessProbe,
    hasResourceRequests: derived?.hasResourceRequests ?? input.hasResourceRequests,
    hasResourceLimits: derived?.hasResourceLimits ?? input.hasResourceLimits,
    hasPodDisruptionBudget: derived?.hasPodDisruptionBudget ?? input.hasPodDisruptionBudget,
    usesLatestTag: derived?.usesLatestTag ?? input.usesLatestTag,
    runsAsRoot: derived?.runsAsRoot ?? input.runsAsRoot,
    exposesPublicService: derived?.exposesPublicService ?? input.exposesPublicService
  };

  let score = 100;
  const findings: string[] = [];
  const strengths: string[] = [];
  const uncertainties: string[] = [];

  if (values.replicas === undefined) uncertainties.push("Replica count could not be determined.");
  else if (values.replicas < 2) {
    score -= 18;
    findings.push("Run at least two replicas for production workloads that need availability.");
  } else strengths.push("Replica count supports basic availability.");

  const booleanChecks: Array<[keyof typeof values, number, string, string]> = [
    ["hasReadinessProbe", 16, "Add a readiness probe so traffic only reaches pods that can serve requests.", "Readiness probe is present."],
    ["hasLivenessProbe", 10, "Add a liveness probe to recover stuck application processes.", "Liveness probe is present."],
    ["hasResourceRequests", 14, "Add CPU and memory requests so the scheduler can place pods safely.", "CPU and memory requests are present."],
    ["hasResourceLimits", 10, "Add resource limits to reduce noisy-neighbor and runaway-memory risk.", "CPU and memory limits are present."],
    ["hasPodDisruptionBudget", 12, "Add a PodDisruptionBudget for safer node maintenance and voluntary disruptions.", "PodDisruptionBudget is present."]
  ];

  for (const [key, penalty, finding, strength] of booleanChecks) {
    const value = values[key];
    if (value === true) strengths.push(strength);
    else if (value === false) {
      score -= penalty;
      findings.push(finding);
    } else uncertainties.push(`${String(key)} could not be determined.`);
  }

  if (values.usesLatestTag === true) {
    score -= 12;
    findings.push("Avoid latest or implicit-latest image tags. Use immutable image tags or digests.");
  } else if (values.usesLatestTag === undefined) uncertainties.push("Image mutability could not be determined.");

  if (values.runsAsRoot === true) {
    score -= 12;
    findings.push("Run containers as a non-root user and enforce a restricted security context.");
  } else if (values.runsAsRoot === undefined) uncertainties.push("Non-root enforcement could not be determined.");

  if (values.exposesPublicService === true) {
    score -= 8;
    findings.push("Validate public exposure, ingress rules, TLS, WAF or network policy before rollout.");
  } else if (values.exposesPublicService === undefined) uncertainties.push("Public exposure could not be determined.");

  const readinessScore = Math.max(score, 0);
  return {
    workloadName,
    namespace,
    readinessScore,
    readinessLevel: readinessLevel(readinessScore, uncertainties),
    assessmentConfidence: confidence(9 - uncertainties.length, 9),
    strengths,
    findings,
    uncertainties,
    evidence: derived?.evidence ?? [],
    recommendedControls: [
      "Deploy with health checks, resource controls and immutable images.",
      "Require rollout monitoring for errors, latency, saturation and restart loops.",
      "Keep rollback instructions tied to the deployed image or Helm release.",
      "Use network policy and least-privilege service accounts for production namespaces."
    ]
  };
}

function analyzeGitHubWorkflow(workflowYaml: string) {
  let workflow: any;
  try {
    workflow = parseYaml(workflowYaml);
  } catch {
    throw new Error("workflowYaml must be valid YAML.");
  }
  if (!workflow || typeof workflow !== "object") throw new Error("workflowYaml must contain a workflow object.");

  const onValue = workflow.on;
  const triggers = typeof onValue === "string"
    ? [onValue]
    : Array.isArray(onValue)
      ? onValue.filter((item): item is string => typeof item === "string")
      : onValue && typeof onValue === "object"
        ? Object.keys(onValue)
        : [];

  const jobs = workflow.jobs && typeof workflow.jobs === "object" ? Object.values(workflow.jobs) as any[] : [];
  const uses: string[] = [];
  const serialized = JSON.stringify(workflow).toLowerCase();

  for (const job of jobs) {
    if (!job || typeof job !== "object") continue;
    for (const step of Array.isArray(job.steps) ? job.steps : []) {
      if (step && typeof step.uses === "string") uses.push(step.uses);
    }
  }

  const externalActions = uses.filter((value) => !value.startsWith("./") && !value.startsWith("docker://"));
  const usesPinnedActions = externalActions.length > 0
    ? externalActions.every((value) => /@[0-9a-f]{40}$/i.test(value))
    : undefined;

  const permissions = workflow.permissions;
  const hasLeastPrivilegePermissions =
    permissions === "read-all" ||
    (permissions && typeof permissions === "object" && !Object.values(permissions).some((value) => value === "write"));

  const hasDependencyCaching = /actions\/cache@|cache\s*":|cache\s*:/.test(serialized);
  const hasSecretScanning = /(gitleaks|trufflehog|secret[-_ ]?scan)/.test(serialized);
  const hasConcurrencyControl = Boolean(workflow.concurrency || jobs.some((job) => job?.concurrency));
  const deploysToProduction = jobs.some((job) => {
    const environment = typeof job?.environment === "string" ? job.environment : job?.environment?.name;
    return typeof environment === "string" && /prod/i.test(environment);
  });

  const evidence: EvidenceItem[] = [];
  if (externalActions.length > 0) evidence.push({
    source: "github-workflow",
    ruleId: "GHA-ACTIONS",
    detail: `External actions found: ${externalActions.join(", ")}.`
  });
  if (triggers.includes("pull_request_target")) evidence.push({
    source: "github-workflow",
    ruleId: "GHA-PR-TARGET",
    detail: "Workflow uses pull_request_target."
  });

  return {
    triggers,
    deploysToProduction,
    usesPinnedActions,
    hasLeastPrivilegePermissions: Boolean(hasLeastPrivilegePermissions),
    hasSecretScanning,
    hasDependencyCaching,
    hasConcurrencyControl,
    evidence
  };
}

export function reviewGitHubActionsWorkflow(input: GitHubWorkflowReviewInput) {
  const derived = input.workflowYaml ? analyzeGitHubWorkflow(input.workflowYaml) : undefined;
  const triggers = Array.from(new Set([...(input.triggers ?? []), ...(derived?.triggers ?? [])]));
  if (triggers.length === 0) throw new Error("Provide triggers or workflowYaml with an on: section.");

  const values = {
    deploysToProduction: derived?.deploysToProduction ?? input.deploysToProduction,
    usesPinnedActions: derived?.usesPinnedActions ?? input.usesPinnedActions,
    hasLeastPrivilegePermissions: derived?.hasLeastPrivilegePermissions ?? input.hasLeastPrivilegePermissions,
    hasSecretScanning: derived?.hasSecretScanning ?? input.hasSecretScanning,
    hasDependencyCaching: derived?.hasDependencyCaching ?? input.hasDependencyCaching,
    hasEnvironmentProtection: input.hasEnvironmentProtection,
    hasConcurrencyControl: derived?.hasConcurrencyControl ?? input.hasConcurrencyControl
  };

  let score = 100;
  const findings: string[] = [];
  const strengths: string[] = [];
  const uncertainties: string[] = [];

  if (triggers.includes("pull_request_target")) {
    score -= 18;
    findings.push("Avoid pull_request_target for untrusted code unless the workflow is tightly constrained.");
  }

  const checks: Array<[keyof typeof values, number, string, string]> = [
    ["usesPinnedActions", 16, "Pin third-party actions to full commit SHAs to reduce supply-chain risk.", "External actions are pinned to immutable commit SHAs."],
    ["hasLeastPrivilegePermissions", 18, "Set explicit least-privilege GITHUB_TOKEN permissions instead of relying on defaults.", "Workflow permissions are explicitly scoped."],
    ["hasSecretScanning", 10, "Add secret scanning or a pre-deploy guard for accidental credential exposure.", "Secret scanning is present."],
    ["hasDependencyCaching", 6, "Add dependency caching where safe to improve repeatability and build speed.", "Dependency caching is configured."]
  ];

  for (const [key, penalty, finding, strength] of checks) {
    const value = values[key];
    if (value === true) strengths.push(strength);
    else if (value === false) {
      score -= penalty;
      findings.push(finding);
    } else uncertainties.push(`${String(key)} could not be determined.`);
  }

  if (values.deploysToProduction === true) {
    if (values.hasEnvironmentProtection === false) {
      score -= 18;
      findings.push("Use protected environments, required reviewers or deployment approvals for production.");
    } else if (values.hasEnvironmentProtection === undefined) {
      uncertainties.push("Repository environment-protection settings cannot be proven from workflow YAML alone.");
    }
    if (values.hasConcurrencyControl === false) {
      score -= 10;
      findings.push("Add concurrency controls to prevent overlapping production deployments.");
    } else if (values.hasConcurrencyControl === undefined) {
      uncertainties.push("Production concurrency controls could not be determined.");
    }
  }

  const workflowScore = Math.max(score, 0);
  return {
    workflowName: input.workflowName,
    workflowScore,
    readinessLevel: readinessLevel(workflowScore, uncertainties),
    assessmentConfidence: confidence(7 - uncertainties.length, 7),
    triggers,
    strengths,
    findings,
    uncertainties,
    evidence: derived?.evidence ?? [],
    recommendedControls: [
      "Pin actions, scope token permissions and protect production environments.",
      "Publish build provenance such as commit SHA, artifact version and deployment environment.",
      "Fail closed when tests, security checks or policy gates fail.",
      "Keep secrets in managed secret stores and rotate credentials used by workflows."
    ]
  };
}


type CorrelatedSeverity = "medium" | "high" | "critical";

interface CorrelatedFinding {
  ruleId: string;
  severity: CorrelatedSeverity;
  title: string;
  domains: string[];
  evidence: string[];
  remediation: string[];
}

interface ChangePath {
  pathId: string;
  severity: CorrelatedSeverity;
  sequence: string[];
  impact: string;
}

function confidenceValue(value: AssessmentConfidence): number {
  if (value === "high") return 1;
  if (value === "medium") return 0.65;
  return 0.3;
}

function confidenceFromAverage(value: number): AssessmentConfidence {
  if (value >= 0.8) return "high";
  if (value >= 0.5) return "medium";
  return "low";
}

function evidenceDetails(items: EvidenceItem[], fallback: string): string[] {
  return items.length > 0 ? items.map((item) => `${item.ruleId}: ${item.detail}`) : [fallback];
}

export function assessCloudChangeBundle(input: CloudChangeBundleInput) {
  const suppliedDomains = [
    input.terraform ? "terraform" : undefined,
    input.iamPolicies?.length ? "iam" : undefined,
    input.kubernetesWorkloads?.length ? "kubernetes" : undefined,
    input.githubWorkflows?.length ? "github_actions" : undefined
  ].filter((value): value is string => Boolean(value));

  if (suppliedDomains.length < 2) {
    throw new Error("Provide evidence from at least two domains: Terraform, IAM, Kubernetes or GitHub Actions.");
  }

  const terraform = input.terraform ? assessTerraformChange(input.terraform) : undefined;
  const iam = (input.iamPolicies ?? []).map((policy) => ({
    input: policy,
    result: reviewIamPolicy(policy),
    derived: policy.policyJson ? analyzeIamPolicy(policy.policyJson) : undefined
  }));
  const kubernetes = (input.kubernetesWorkloads ?? []).map((workload) => ({
    input: workload,
    result: reviewKubernetesDeployment(workload),
    derived: workload.manifestYaml ? analyzeKubernetesManifest(workload.manifestYaml) : undefined
  }));
  const github = (input.githubWorkflows ?? []).map((workflow) => ({
    input: workflow,
    result: reviewGitHubActionsWorkflow(workflow),
    derived: workflow.workflowYaml ? analyzeGitHubWorkflow(workflow.workflowYaml) : undefined
  }));

  const terraformDerived = input.terraform?.terraformPlanJson
    ? analyzeTerraformPlan(input.terraform.terraformPlanJson)
    : undefined;

  const terraformPublic =
    terraformDerived?.includesPublicIngress === true ||
    input.terraform?.includesPublicIngress === true;
  const terraformStateful =
    terraformDerived?.modifiesStatefulResources === true ||
    input.terraform?.modifiesStatefulResources === true;
  const terraformIam =
    terraformDerived?.includesIamChanges === true ||
    input.terraform?.includesIamChanges === true ||
    input.terraform?.changedResources?.includes("iam") === true;

  const iamEscalation = iam.some(({ input: policy, derived }) => {
    if (derived?.escalationActions.length) return true;
    if (policy.allowsPrivilegeEscalationActions === true) return true;
    return (policy.actions ?? []).some((action) => {
      const value = action.toLowerCase();
      return privilegeEscalationActions.some((candidate) => value === candidate) ||
        /^iam:(attach|put|create|update).*/.test(value);
    });
  });

  const iamWildcard = iam.some(({ input: policy, derived }) =>
    derived?.wildcardActions === true ||
    derived?.wildcardResources === true ||
    policy.hasWildcardActions === true ||
    policy.hasWildcardResources === true ||
    (policy.actions ?? []).some((action) => action.includes("*")) ||
    (policy.resources ?? []).some((resource) => resource.includes("*"))
  );

  const kubernetesPublic = kubernetes.some(({ input: workload, derived }) =>
    derived?.exposesPublicService === true || workload.exposesPublicService === true
  );
  const kubernetesMutableImage = kubernetes.some(({ input: workload, derived }) =>
    derived?.usesLatestTag === true || workload.usesLatestTag === true
  );
  const kubernetesRoot = kubernetes.some(({ input: workload, derived }) =>
    derived?.runsAsRoot === true || workload.runsAsRoot === true
  );

  const githubProduction = github.some(({ input: workflow, derived }) =>
    derived?.deploysToProduction === true || workflow.deploysToProduction === true
  );
  const githubPrTarget = github.some(({ input: workflow, derived }) =>
    derived?.triggers.includes("pull_request_target") === true ||
    workflow.triggers?.includes("pull_request_target") === true
  );
  const githubUnpinned = github.some(({ input: workflow, derived }) =>
    derived?.usesPinnedActions === false || workflow.usesPinnedActions === false
  );
  const githubUnprotected = github.some(({ input: workflow }) =>
    workflow.deploysToProduction === true && workflow.hasEnvironmentProtection === false
  ) || github.some(({ result }) =>
    result.findings.some((finding) => finding.includes("protected environments"))
  );

  const domainSummary: Array<{
    domain: string;
    riskScore: number;
    riskLevel: RiskLevel;
    evidenceCount: number;
    uncertaintyCount: number;
  }> = [];
  const domainConfidenceValues: number[] = [];

  if (terraform) {
    domainSummary.push({
      domain: "terraform",
      riskScore: terraform.riskScore,
      riskLevel: terraform.riskLevel,
      evidenceCount: terraform.evidence.length,
      uncertaintyCount: terraform.uncertainties.length
    });
    domainConfidenceValues.push(confidenceValue(terraform.assessmentConfidence));
  }

  if (iam.length > 0) {
    const riskScore = Math.max(...iam.map(({ result }) => result.riskScore));
    const evidenceCount = iam.reduce((total, { result }) => total + result.evidence.length, 0);
    const uncertaintyCount = iam.reduce((total, { result }) => total + result.uncertainties.length, 0);
    domainSummary.push({
      domain: "iam",
      riskScore,
      riskLevel: riskLevel(riskScore),
      evidenceCount,
      uncertaintyCount
    });
    domainConfidenceValues.push(
      iam.reduce((total, { result }) => total + confidenceValue(result.assessmentConfidence), 0) / iam.length
    );
  }

  if (kubernetes.length > 0) {
    const riskScore = Math.max(...kubernetes.map(({ result }) => 100 - result.readinessScore));
    const evidenceCount = kubernetes.reduce((total, { result }) => total + result.evidence.length, 0);
    const uncertaintyCount = kubernetes.reduce((total, { result }) => total + result.uncertainties.length, 0);
    domainSummary.push({
      domain: "kubernetes",
      riskScore,
      riskLevel: riskLevel(riskScore),
      evidenceCount,
      uncertaintyCount
    });
    domainConfidenceValues.push(
      kubernetes.reduce((total, { result }) => total + confidenceValue(result.assessmentConfidence), 0) / kubernetes.length
    );
  }

  if (github.length > 0) {
    const riskScore = Math.max(...github.map(({ result }) => 100 - result.workflowScore));
    const evidenceCount = github.reduce((total, { result }) => total + result.evidence.length, 0);
    const uncertaintyCount = github.reduce((total, { result }) => total + result.uncertainties.length, 0);
    domainSummary.push({
      domain: "github_actions",
      riskScore,
      riskLevel: riskLevel(riskScore),
      evidenceCount,
      uncertaintyCount
    });
    domainConfidenceValues.push(
      github.reduce((total, { result }) => total + confidenceValue(result.assessmentConfidence), 0) / github.length
    );
  }

  const findings: CorrelatedFinding[] = [];
  const paths: ChangePath[] = [];
  let correlationBonus = 0;

  const addFinding = (
    finding: CorrelatedFinding,
    bonus: number,
    sequence: string[],
    impact: string
  ) => {
    findings.push(finding);
    correlationBonus += bonus;
    paths.push({
      pathId: finding.ruleId,
      severity: finding.severity,
      sequence,
      impact
    });
  };

  if (terraformPublic && kubernetesPublic) {
    addFinding(
      {
        ruleId: "BUNDLE-PUBLIC-EXPOSURE",
        severity: "critical",
        title: "Infrastructure and workload layers both introduce public exposure",
        domains: ["terraform", "kubernetes"],
        evidence: [
          ...evidenceDetails(terraform?.evidence.filter((item) => item.ruleId === "TF-PUBLIC-INGRESS") ?? [], "Terraform inputs indicate public ingress."),
          ...kubernetes.flatMap(({ result }) => evidenceDetails(result.evidence.filter((item) => item.ruleId === "K8S-PUBLIC"), "Kubernetes inputs indicate a public Service or Ingress."))
        ],
        remediation: [
          "Confirm whether public exposure is required at both layers.",
          "Restrict CIDRs, listeners and service exposure to the minimum necessary path.",
          "Require TLS, authentication and network-policy validation before release."
        ]
      },
      18,
      ["Terraform network exposure", "Kubernetes public Service/Ingress", "Application workload"],
      "The same change can expose the workload through both infrastructure and cluster networking controls."
    );
  }

  if (iamEscalation && githubProduction && (githubUnprotected || githubPrTarget)) {
    addFinding(
      {
        ruleId: "BUNDLE-PRIVILEGED-PROD-DELIVERY",
        severity: "critical",
        title: "Production delivery path intersects with privilege-escalating IAM capability",
        domains: ["iam", "github_actions"],
        evidence: [
          ...iam.flatMap(({ result }) => evidenceDetails(result.evidence.filter((item) => item.ruleId === "IAM-PRIV-ESC"), "IAM inputs include privilege-escalation-capable actions.")),
          ...github.flatMap(({ result }) => result.findings.filter((finding) =>
            finding.includes("protected environments") || finding.includes("pull_request_target")
          ))
        ],
        remediation: [
          "Remove or isolate privilege-escalation permissions from deployment identities.",
          "Require protected production environments and trusted deployment triggers.",
          "Separate build identity from deployment identity and use short-lived credentials."
        ]
      },
      24,
      ["GitHub Actions production workflow", "Deployment identity", "Privilege-escalating IAM capability", "Production resources"],
      "A compromised or insufficiently protected delivery path could have an enlarged authorization blast radius."
    );
  }

  if (githubUnpinned && kubernetesMutableImage) {
    addFinding(
      {
        ruleId: "BUNDLE-MUTABLE-SUPPLY-CHAIN",
        severity: "high",
        title: "Mutable CI dependencies and mutable runtime images appear in the same release path",
        domains: ["github_actions", "kubernetes"],
        evidence: [
          ...github.flatMap(({ result }) => result.findings.filter((finding) => finding.includes("full commit SHAs"))),
          ...kubernetes.flatMap(({ result }) => evidenceDetails(result.evidence.filter((item) => item.ruleId === "K8S-MUTABLE-IMAGE"), "Kubernetes inputs indicate a mutable image tag."))
        ],
        remediation: [
          "Pin external GitHub Actions to immutable full commit SHAs.",
          "Deploy container images by digest or immutable version tag.",
          "Record commit-to-artifact-to-image provenance for every production release."
        ]
      },
      16,
      ["Mutable GitHub Action reference", "Build/release workflow", "Mutable container image", "Kubernetes runtime"],
      "Two mutable supply-chain points make release reproduction and integrity verification weaker."
    );
  }

  if ((terraformPublic || kubernetesPublic) && (iamEscalation || iamWildcard)) {
    addFinding(
      {
        ruleId: "BUNDLE-PUBLIC-PRIVILEGE-BLAST-RADIUS",
        severity: "critical",
        title: "Public exposure overlaps with broad or privilege-escalating IAM",
        domains: ["terraform", "iam", "kubernetes"].filter((domain) =>
          domain !== "terraform" || Boolean(terraform)
        ),
        evidence: [
          terraformPublic ? "Terraform evidence indicates public network exposure." : "Kubernetes evidence indicates public workload exposure.",
          iamEscalation ? "IAM evidence includes privilege-escalation-capable permissions." : "IAM evidence includes wildcard scope."
        ],
        remediation: [
          "Reduce public exposure and IAM scope before the same release reaches production.",
          "Use separate identities and network boundaries for internet-facing workloads.",
          "Add explicit compensating controls and approval evidence if exposure is intentional."
        ]
      },
      18,
      ["Public entry point", "Internet-facing workload", "Broad or escalating IAM permissions"],
      "An exposed workload combined with excessive authorization increases the potential impact of a workload compromise."
    );
  }

  if (kubernetesRoot && (terraformPublic || kubernetesPublic)) {
    addFinding(
      {
        ruleId: "BUNDLE-PUBLIC-ROOT-WORKLOAD",
        severity: "high",
        title: "Publicly reachable workload can run with root-level container context",
        domains: ["kubernetes", ...(terraformPublic ? ["terraform"] : [])],
        evidence: [
          ...kubernetes.flatMap(({ result }) => evidenceDetails(result.evidence.filter((item) => item.ruleId === "K8S-ROOT"), "Kubernetes inputs indicate root execution.")),
          terraformPublic ? "Terraform inputs indicate public ingress." : "Kubernetes inputs indicate public exposure."
        ],
        remediation: [
          "Enforce runAsNonRoot and a restricted security context.",
          "Drop unnecessary Linux capabilities and use read-only root filesystems where possible.",
          "Reduce external reachability until the workload security context is hardened."
        ]
      },
      14,
      ["Public entry point", "Kubernetes workload", "Root-capable container context"],
      "Internet reachability combined with root execution increases runtime blast radius."
    );
  }

  if (terraformIam && iam.some(({ result }) => result.riskScore >= 50)) {
    addFinding(
      {
        ruleId: "BUNDLE-IAC-IAM-HIGH-RISK",
        severity: "high",
        title: "The infrastructure change modifies IAM while supplied IAM policy evidence is high risk",
        domains: ["terraform", "iam"],
        evidence: [
          "Terraform change set includes IAM resources.",
          ...iam.filter(({ result }) => result.riskScore >= 50).flatMap(({ result }) => result.findings)
        ],
        remediation: [
          "Require focused IAM peer review before applying the Terraform change.",
          "Use policy simulation or access analysis to prove the required permission set.",
          "Split unrelated IAM changes from infrastructure rollout where practical."
        ]
      },
      12,
      ["Terraform IAM change", "High-risk IAM policy", "Deployment identity or workload permissions"],
      "The same change set can introduce both authorization changes and the infrastructure that consumes them."
    );
  }

  if (terraformStateful && input.terraform?.hasRollbackPlan === false) {
    addFinding(
      {
        ruleId: "BUNDLE-STATEFUL-NO-ROLLBACK",
        severity: "high",
        title: "Stateful infrastructure changes lack an explicit rollback or forward-fix plan",
        domains: ["terraform"],
        evidence: [
          ...evidenceDetails(terraform?.evidence.filter((item) => item.ruleId === "TF-STATEFUL") ?? [], "Terraform inputs indicate stateful-resource modification."),
          "Rollback plan is explicitly marked absent."
        ],
        remediation: [
          "Document restore, migration reversal or forward-fix procedures before apply.",
          "Confirm backup integrity and recovery time expectations.",
          "Define an owner and measurable rollback trigger."
        ]
      },
      12,
      ["Stateful Terraform change", "Deployment", "Potential data migration or persistence impact"],
      "A stateful change without a tested recovery path can turn a deployment failure into a prolonged data or availability incident."
    );
  }

  const domainRisks = domainSummary.map((domain) => domain.riskScore);
  const maxDomainRisk = Math.max(...domainRisks);
  const averageDomainRisk = domainRisks.reduce((total, value) => total + value, 0) / domainRisks.length;
  const baseRiskScore = Math.round(maxDomainRisk * 0.6 + averageDomainRisk * 0.4);
  const correlationAdjustment = Math.min(correlationBonus, 40);
  const environmentRiskAdjustment = input.environment === "production" ? 5 : input.environment === "staging" ? 2 : 0;
  const bundleRiskScore = Math.min(
    100,
    baseRiskScore + correlationAdjustment + environmentRiskAdjustment
  );

  const allUncertainties = [
    ...(terraform?.uncertainties.map((value) => `terraform: ${value}`) ?? []),
    ...iam.flatMap(({ result, input: policy }) => result.uncertainties.map((value) => `iam/${policy.policyName}: ${value}`)),
    ...kubernetes.flatMap(({ result }) => result.uncertainties.map((value) => `kubernetes/${result.workloadName}: ${value}`)),
    ...github.flatMap(({ result, input: workflow }) => result.uncertainties.map((value) => `github_actions/${workflow.workflowName}: ${value}`))
  ];

  const averageConfidence = domainConfidenceValues.reduce((total, value) => total + value, 0) /
    domainConfidenceValues.length;
  const assessmentConfidence = confidenceFromAverage(averageConfidence);

  const releaseGate =
    bundleRiskScore >= 75
      ? "hold-for-remediation"
      : bundleRiskScore >= 50
        ? "change-advisory-review"
        : bundleRiskScore >= 25
          ? "staged-release"
          : "standard-review";

  const recommendedActions = Array.from(new Set([
    ...findings.flatMap((finding) => finding.remediation),
    ...(bundleRiskScore >= 75
      ? ["Do not broadly release until critical correlated findings are remediated or explicitly accepted by accountable owners."]
      : []),
    ...(allUncertainties.length > 0
      ? ["Resolve unknown controls with artifact or repository evidence before treating the bundle assessment as complete."]
      : [])
  ]));

  return {
    changeName: input.changeName,
    environment: input.environment,
    bundleRiskScore,
    bundleRiskLevel: riskLevel(bundleRiskScore),
    baseRiskScore,
    correlationAdjustment,
    environmentRiskAdjustment,
    assessmentConfidence,
    suppliedDomains,
    domainSummary,
    correlatedFindingCount: findings.length,
    correlatedFindings: findings,
    changePaths: paths,
    uncertainties: allUncertainties,
    releaseGate,
    recommendedActions
  };
}
