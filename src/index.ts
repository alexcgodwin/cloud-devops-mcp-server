#!/usr/bin/env node
import { pathToFileURL } from "node:url";
import { McpServer } from "@modelcontextprotocol/server";
import { serveStdio } from "@modelcontextprotocol/server/stdio";
import * as z from "zod/v4";
import {
  assessCloudChangeBundle,
  assessTerraformChange,
  buildIncidentRunbook,
  estimateSloBudget,
  reviewGitHubActionsWorkflow,
  reviewIamPolicy,
  reviewKubernetesDeployment,
  reviewPipeline
} from "./logic.js";
import {
  reviewCloudIdentityPolicy,
  reviewKubernetesSecurity,
  reviewSoftwareSupplyChain,
  reviewTerraformSecurity
} from "./intelligence.js";
import {
  gitCommit,
  gitCreateBranch,
  gitFetch,
  gitPullFfOnly,
  gitPush,
  gitStatus,
  githubCheckPullRequest,
  githubCreatePullRequest,
  githubMergePullRequest,
  githubTriggerWorkflow
} from "./execution.js";
import {
  kubectlCurrentContext,
  kubectlGetResources,
  kubectlRolloutStatus,
  terraformFmtCheck,
  terraformPlanSummary,
  terraformValidate
} from "./infrastructure.js";
import {
  cloudDriftCompare,
  cloudFinOpsSignals,
  cloudInventorySummary,
  cloudKubernetesClusters,
  cloudObservabilitySummary,
  cloudWhoAmI
} from "./cloud.js";

const VERSION = "0.7.0";

const evidenceSchema = z.object({
  source: z.string(),
  ruleId: z.string(),
  detail: z.string()
});

const confidenceSchema = z.enum(["high", "medium", "low"]);
const readinessSchema = z.enum(["production-ready", "needs-review", "needs-hardening", "not-ready"]);
const riskSchema = z.enum(["low", "medium", "high", "critical"]);
const correlatedSeveritySchema = z.enum(["medium", "high", "critical"]);
const domainSummarySchema = z.object({
  domain: z.string(),
  riskScore: z.number(),
  riskLevel: riskSchema,
  evidenceCount: z.number(),
  uncertaintyCount: z.number()
});
const correlatedFindingSchema = z.object({
  ruleId: z.string(),
  severity: correlatedSeveritySchema,
  title: z.string(),
  domains: z.array(z.string()),
  evidence: z.array(z.string()),
  remediation: z.array(z.string())
});
const changePathSchema = z.object({
  pathId: z.string(),
  severity: correlatedSeveritySchema,
  sequence: z.array(z.string()),
  impact: z.string()
});
const securityFindingSchema = z.object({
  ruleId: z.string(),
  severity: z.enum(["medium", "high", "critical"]),
  title: z.string(),
  evidence: z.array(z.string()),
  remediation: z.array(z.string())
});
const securitySummaryShape = {
  riskScore: z.number(),
  riskLevel: riskSchema,
  findingCount: z.number(),
  criticalFindings: z.number(),
  highFindings: z.number(),
  mediumFindings: z.number(),
  assessmentConfidence: confidenceSchema
} as const;

const readOnlyAnnotations = {
  readOnlyHint: true,
  destructiveHint: false,
  idempotentHint: true,
  openWorldHint: false
} as const;

function toolResult(payload: Record<string, unknown>) {
  return {
    content: [{ type: "text" as const, text: JSON.stringify(payload, null, 2) }],
    structuredContent: payload
  };
}

export function createServer() {
  const server = new McpServer(
    { name: "cloud-devops-mcp-server", version: VERSION },
    {
      instructions:
        "Use the narrowest Cloud DevOps tool that matches the evidence and decision. Analysis tools are read-only by default: assess_terraform_change evaluates release/change risk and governance; review_terraform_security inspects Terraform plan security; review_kubernetes_deployment evaluates reliability/readiness; review_kubernetes_security evaluates workload hardening; review_cicd_pipeline covers generic delivery controls; review_github_actions_workflow covers GitHub Actions YAML; review_iam_policy is AWS IAM focused; review_cloud_identity_policy applies provider-specific AWS/Azure/GCP identity policy packs. Controlled Git/GitHub execution tools appear only when explicitly enabled and are restricted by repository, branch, remote and workflow allowlists. Prefer raw artifacts when available and treat missing evidence as unknown, not as a failed control."
    }
  );

  server.registerTool(
    "assess_terraform_change",
    {
      title: "Assess Terraform Change",
      description: "Evaluate Terraform/IaC release risk using plan evidence plus change-governance facts such as rollback, peer review and stateful impact. Use this for overall change/release decisions; for security-only inspection of a raw Terraform plan, use review_terraform_security. It analyzes supplied evidence only and never applies a plan, changes infrastructure, or writes Terraform state.",
      annotations: readOnlyAnnotations,
      inputSchema: z.object({
        changedResources: z
          .array(z.enum(["network", "iam", "database", "kubernetes", "compute", "observability", "ci_cd", "dns"]))
          .min(1)
          .optional()
          .describe("Infrastructure resource classes changed by the pull request or deployment."),
        terraformPlanJson: z.string().min(2).optional().describe("Optional raw Terraform plan JSON. When supplied, the server derives resource classes and evidence."),
        includesIamChanges: z.boolean().optional().describe("Whether the change adds, removes or modifies IAM permissions, roles or policies."),
        includesPublicIngress: z.boolean().optional().describe("Whether the change introduces or modifies internet-accessible ingress or public network exposure."),
        modifiesStatefulResources: z.boolean().optional().describe("Whether databases, persistent volumes or other stateful resources are changed or replaced."),
        hasRollbackPlan: z.boolean().optional().describe("Whether a documented rollback or recovery path exists for this change."),
        hasPeerReview: z.boolean().optional().describe("Whether another qualified reviewer has reviewed the proposed change."),
        hasTerraformPlan: z.boolean().optional().describe("Whether a Terraform plan artifact was generated and reviewed for this change.")
      }).refine((value) => Boolean(value.terraformPlanJson || value.changedResources?.length), {
        message: "Provide changedResources or terraformPlanJson."
      }),
      outputSchema: z.object({
        riskScore: z.number(),
        riskLevel: riskSchema,
        changedResources: z.array(z.string()),
        evidence: z.array(evidenceSchema),
        uncertainties: z.array(z.string()),
        assessmentConfidence: confidenceSchema,
        checklist: z.array(z.string()),
        recommendedReleasePath: z.string()
      })
    },
    async (input) => toolResult(assessTerraformChange(input))
  );

  server.registerTool(
    "assess_cloud_change_bundle",
    {
      title: "Assess Cloud Change Bundle",
      description: "Correlate evidence from at least two domains (Terraform, IAM, Kubernetes, GitHub Actions) into one deployment-risk assessment and identify cross-domain change paths. Use domain-specific review tools when only one evidence domain is available. It analyzes caller-supplied artifacts only and does not query providers, clusters, GitHub, or deploy changes.",
      annotations: readOnlyAnnotations,
      inputSchema: z.object({
        changeName: z.string().min(2).describe("Name or identifier for the cloud change bundle being assessed."),
        environment: z.enum(["dev", "staging", "production"]).describe("Target deployment environment; production increases the consequence of correlated risk."),
        terraform: z.object({
          changedResources: z
            .array(z.enum(["network", "iam", "database", "kubernetes", "compute", "observability", "ci_cd", "dns"]))
            .min(1)
            .optional()
            .describe("Terraform resource classes changed when raw plan JSON is not supplied."),
          terraformPlanJson: z.string().min(2).optional().describe("Optional raw Terraform plan JSON used to derive change evidence."),
          includesIamChanges: z.boolean().optional().describe("Whether Terraform changes identity or access-management resources."),
          includesPublicIngress: z.boolean().optional().describe("Whether Terraform introduces or changes public ingress."),
          modifiesStatefulResources: z.boolean().optional().describe("Whether Terraform changes stateful resources such as databases or persistent storage."),
          hasRollbackPlan: z.boolean().optional().describe("Whether the Terraform change has a documented rollback or recovery plan."),
          hasPeerReview: z.boolean().optional().describe("Whether the Terraform change has peer-review evidence."),
          hasTerraformPlan: z.boolean().optional().describe("Whether a Terraform plan artifact exists and was reviewed.")
        }).refine((value) => Boolean(value.terraformPlanJson || value.changedResources?.length), {
          message: "Terraform evidence requires changedResources or terraformPlanJson."
        }).optional().describe("Optional Terraform evidence domain. Supply this plus at least one other domain for cross-domain assessment."),
        iamPolicies: z.array(z.object({
          policyName: z.string().min(2).describe("Name of the IAM policy represented by this evidence item."),
          actions: z.array(z.string()).min(1).optional().describe("Explicit IAM actions when raw policy JSON is not supplied."),
          resources: z.array(z.string()).min(1).optional().describe("Explicit IAM resource ARNs or resource patterns when raw policy JSON is not supplied."),
          policyJson: z.string().min(2).optional().describe("Optional raw AWS IAM policy JSON used to derive identity-risk evidence."),
          hasWildcardActions: z.boolean().optional().describe("Whether the policy allows wildcard actions such as * or service:* patterns."),
          hasWildcardResources: z.boolean().optional().describe("Whether the policy grants access to wildcard resources."),
          allowsPrivilegeEscalationActions: z.boolean().optional().describe("Whether the policy permits actions commonly associated with privilege escalation."),
          hasConditionBlocks: z.boolean().optional().describe("Whether policy statements include IAM Condition constraints."),
          usedByProduction: z.boolean().optional().describe("Whether the policy is attached to or used by production workloads or identities.")
        }).refine((value) => Boolean(value.policyJson || (value.actions?.length && value.resources?.length)), {
          message: "Each IAM policy requires policyJson or both actions and resources."
        })).max(10).optional().describe("Optional IAM evidence domain with up to 10 policies; combine with at least one other domain."),
        kubernetesWorkloads: z.array(z.object({
          workloadName: z.string().min(2).optional().describe("Kubernetes workload name when raw manifest YAML is not the only identifier."),
          namespace: z.string().min(1).optional().describe("Kubernetes namespace containing the workload."),
          replicas: z.number().int().min(0).optional().describe("Configured replica count used for availability assessment."),
          manifestYaml: z.string().min(2).optional().describe("Optional raw Kubernetes YAML used to derive workload evidence."),
          hasReadinessProbe: z.boolean().optional().describe("Whether workload containers define readiness probes."),
          hasLivenessProbe: z.boolean().optional().describe("Whether workload containers define liveness probes."),
          hasResourceRequests: z.boolean().optional().describe("Whether workload containers define CPU or memory requests."),
          hasResourceLimits: z.boolean().optional().describe("Whether workload containers define CPU or memory limits."),
          hasPodDisruptionBudget: z.boolean().optional().describe("Whether disruption protection is provided by a PodDisruptionBudget."),
          usesLatestTag: z.boolean().optional().describe("Whether any workload image uses the mutable latest tag."),
          runsAsRoot: z.boolean().optional().describe("Whether the workload is configured to run containers as root."),
          exposesPublicService: z.boolean().optional().describe("Whether the workload is exposed through a public Service or ingress path.")
        }).refine((value) => Boolean(value.manifestYaml || value.workloadName), {
          message: "Each Kubernetes workload requires workloadName or manifestYaml."
        })).max(10).optional().describe("Optional Kubernetes evidence domain with up to 10 workloads; combine with at least one other domain."),
        githubWorkflows: z.array(z.object({
          workflowName: z.string().min(2).describe("Name of the GitHub Actions workflow represented by this evidence item."),
          workflowYaml: z.string().min(2).optional().describe("Optional raw GitHub Actions workflow YAML used to derive CI/CD evidence."),
          triggers: z.array(z.string()).min(1).optional().describe("Workflow trigger events when raw workflow YAML is not supplied."),
          deploysToProduction: z.boolean().optional().describe("Whether the workflow can deploy changes to production."),
          usesPinnedActions: z.boolean().optional().describe("Whether third-party actions are pinned to immutable commit SHAs."),
          hasLeastPrivilegePermissions: z.boolean().optional().describe("Whether GITHUB_TOKEN permissions are explicitly restricted to least privilege."),
          hasSecretScanning: z.boolean().optional().describe("Whether the delivery process includes secret-detection controls."),
          hasDependencyCaching: z.boolean().optional().describe("Whether dependency caching is configured for repeatable efficient builds."),
          hasEnvironmentProtection: z.boolean().optional().describe("Whether protected GitHub environments or equivalent approval controls guard deployments."),
          hasConcurrencyControl: z.boolean().optional().describe("Whether concurrency settings prevent overlapping or conflicting deployment runs.")
        }).refine((value) => Boolean(value.workflowYaml || value.triggers?.length), {
          message: "Each GitHub Actions workflow requires workflowYaml or triggers."
        })).max(10).optional().describe("Optional GitHub Actions evidence domain with up to 10 workflows; combine with at least one other domain.")
      }).refine((value) => {
        const domains = [
          Boolean(value.terraform),
          Boolean(value.iamPolicies?.length),
          Boolean(value.kubernetesWorkloads?.length),
          Boolean(value.githubWorkflows?.length)
        ].filter(Boolean).length;
        return domains >= 2;
      }, {
        message: "Provide evidence from at least two domains."
      }),
      outputSchema: z.object({
        changeName: z.string(),
        environment: z.string(),
        bundleRiskScore: z.number(),
        bundleRiskLevel: riskSchema,
        baseRiskScore: z.number(),
        correlationAdjustment: z.number(),
        environmentRiskAdjustment: z.number(),
        assessmentConfidence: confidenceSchema,
        suppliedDomains: z.array(z.string()),
        domainSummary: z.array(domainSummarySchema),
        correlatedFindingCount: z.number(),
        correlatedFindings: z.array(correlatedFindingSchema),
        changePaths: z.array(changePathSchema),
        uncertainties: z.array(z.string()),
        releaseGate: z.enum(["hold-for-remediation", "change-advisory-review", "staged-release", "standard-review"]),
        recommendedActions: z.array(z.string())
      })
    },
    async (input) => toolResult(assessCloudChangeBundle(input))
  );

  server.registerTool(
    "build_incident_runbook",
    {
      title: "Build Incident Runbook",
      description: "Generate a practical incident-response runbook from a known service symptom, severity, environment and optional signals. Use this to structure response actions and evidence collection; do not use it to fetch or diagnose from live telemetry. It does not execute remediation or make changes to the service.",
      annotations: readOnlyAnnotations,
      inputSchema: z.object({
        service: z.string().min(2).describe("Service or application name affected by the incident."),
        environment: z.enum(["dev", "staging", "production"]).describe("Environment where the symptom is occurring."),
        severity: z.enum(["sev1", "sev2", "sev3", "sev4"]).describe("Incident severity used to scale response urgency and communications."),
        symptom: z.string().min(5).describe("Observed user-facing or operational symptom to build the runbook around."),
        signals: z.array(z.string()).optional().describe("Optional known alerts, metrics, logs or traces that should guide triage.")
      }),
      outputSchema: z.object({
        title: z.string(),
        context: z.object({
          service: z.string(),
          environment: z.string(),
          symptom: z.string(),
          signals: z.array(z.string())
        }),
        firstFifteenMinutes: z.array(z.string()),
        triageSteps: z.array(z.string()),
        communication: z.array(z.string()),
        mitigation: z.array(z.string()),
        rcaEvidence: z.array(z.string())
      })
    },
    async (input) => toolResult(buildIncidentRunbook(input))
  );

  server.registerTool(
    "review_cicd_pipeline",
    {
      title: "Review CI/CD Pipeline",
      description: "Evaluate generic CI/CD production-readiness controls from structured pipeline facts, separating missing evidence from failed controls. Use this for platform-agnostic delivery process review; for raw GitHub Actions YAML, use review_github_actions_workflow. It is analysis-only and does not trigger builds, deployments, approvals, or pipeline changes.",
      annotations: readOnlyAnnotations,
      inputSchema: z.object({
        pipelineName: z.string().min(2).describe("Human-readable name of the CI/CD pipeline being reviewed."),
        deploymentStrategy: z.enum(["rolling", "blue_green", "canary", "recreate", "manual"]).describe("Primary deployment strategy used to release changes."),
        environments: z.array(z.string()).min(1).describe("Deployment environments handled by the pipeline, for example dev, staging and production."),
        hasAutomatedTests: z.boolean().optional().describe("Whether automated tests run as a release gate."),
        hasSecurityScan: z.boolean().optional().describe("Whether the pipeline performs automated security scanning before deployment."),
        hasRollback: z.boolean().optional().describe("Whether the pipeline has a defined rollback or recovery mechanism."),
        hasArtifactVersioning: z.boolean().optional().describe("Whether build artifacts are immutable and versioned for traceability."),
        hasManualApprovalForProduction: z.boolean().optional().describe("Whether production deployment requires an explicit human approval gate.")
      }),
      outputSchema: z.object({
        pipelineName: z.string(),
        readinessScore: z.number(),
        readinessLevel: readinessSchema,
        assessmentConfidence: confidenceSchema,
        deploymentStrategy: z.string(),
        strengths: z.array(z.string()),
        findings: z.array(z.string()),
        uncertainties: z.array(z.string()),
        recommendedGates: z.array(z.string())
      })
    },
    async (input) => toolResult(reviewPipeline(input))
  );

  server.registerTool(
    "estimate_slo_error_budget",
    {
      title: "Estimate SLO Error Budget",
      description: "Calculate remaining SLO downtime budget and, when request counts are supplied, remaining failed-request budget for a fixed period. Use this as a deterministic budget calculator; do not use it to fetch monitoring data or forecast reliability. It performs no external calls and changes no service state.",
      annotations: readOnlyAnnotations,
      inputSchema: z.object({
        sloTargetPercent: z.number().gt(0).lt(100).describe("Target service availability percentage for the measurement period, such as 99.9."),
        periodDays: z.number().int().positive().describe("Length of the SLO measurement period in calendar days."),
        observedDowntimeMinutes: z.number().min(0).describe("Downtime already observed during the measurement period, in minutes."),
        requestVolume: z.number().int().positive().optional().describe("Optional total request count for calculating a request-failure error budget."),
        failedRequests: z.number().int().min(0).optional().describe("Optional failed request count; provide together with requestVolume.")
      }).refine((value) => (value.requestVolume === undefined) === (value.failedRequests === undefined), {
        message: "requestVolume and failedRequests must be provided together."
      }).refine((value) => value.requestVolume === undefined || value.failedRequests === undefined || value.failedRequests <= value.requestVolume, {
        message: "failedRequests cannot exceed requestVolume."
      }),
      outputSchema: z.object({
        sloTargetPercent: z.number(),
        periodDays: z.number(),
        allowedDowntimeMinutes: z.number(),
        observedDowntimeMinutes: z.number(),
        remainingDowntimeMinutes: z.number(),
        budgetStatus: z.enum(["within-budget", "exhausted"]),
        allowedFailedRequests: z.number().optional(),
        failedRequests: z.number().optional(),
        remainingFailedRequests: z.number().optional()
      })
    },
    async (input) => toolResult(estimateSloBudget(input))
  );

  server.registerTool(
    "review_iam_policy",
    {
      title: "Review IAM Policy",
      description: "Evaluate AWS IAM policy risk from structured facts or raw policy JSON, including wildcard scope, privilege-escalation actions and conditions. Use this for AWS IAM operational risk; for provider-specific AWS/Azure/GCP policy-pack checks, use review_cloud_identity_policy. It analyzes supplied policy data only and does not call AWS or modify IAM.",
      annotations: readOnlyAnnotations,
      inputSchema: z.object({
        policyName: z.string().min(2).describe("Name of the AWS IAM policy being assessed."),
        actions: z.array(z.string()).min(1).optional().describe("Explicit allowed IAM actions when raw policy JSON is not supplied."),
        resources: z.array(z.string()).min(1).optional().describe("Explicit IAM resource ARNs or patterns when raw policy JSON is not supplied."),
        policyJson: z.string().min(2).optional().describe("Raw AWS IAM policy JSON. When supplied, the server derives actions, resources, wildcard scope and privilege-escalation evidence."),
        hasWildcardActions: z.boolean().optional().describe("Whether the policy permits wildcard actions such as * or service:* patterns."),
        hasWildcardResources: z.boolean().optional().describe("Whether the policy grants permissions against wildcard resources."),
        allowsPrivilegeEscalationActions: z.boolean().optional().describe("Whether the policy contains actions that can enable privilege escalation."),
        hasConditionBlocks: z.boolean().optional().describe("Whether policy statements include Condition constraints that narrow access."),
        usedByProduction: z.boolean().optional().describe("Whether the policy is attached to or used by production identities or workloads.")
      }).refine((value) => Boolean(value.policyJson || (value.actions?.length && value.resources?.length)), {
        message: "Provide policyJson or both actions and resources."
      }),
      outputSchema: z.object({
        policyName: z.string(),
        riskScore: z.number(),
        riskLevel: riskSchema,
        assessmentConfidence: confidenceSchema,
        actions: z.array(z.string()),
        resources: z.array(z.string()),
        strengths: z.array(z.string()),
        findings: z.array(z.string()),
        uncertainties: z.array(z.string()),
        evidence: z.array(evidenceSchema),
        recommendedControls: z.array(z.string())
      })
    },
    async (input) => toolResult(reviewIamPolicy(input))
  );

  server.registerTool(
    "review_kubernetes_deployment",
    {
      title: "Review Kubernetes Deployment",
      description: "Evaluate Kubernetes workload production readiness and reliability from structured facts or multi-document YAML, including probes, resources, replicas, disruption protection and exposure. Use this for deployability/readiness; for workload security hardening, use review_kubernetes_security. It examines supplied evidence only and does not connect to a Kubernetes cluster.",
      annotations: readOnlyAnnotations,
      inputSchema: z.object({
        workloadName: z.string().min(2).optional().describe("Workload name when raw manifest YAML is not the only source of identity."),
        namespace: z.string().min(1).optional().describe("Kubernetes namespace containing the workload."),
        replicas: z.number().int().min(0).optional().describe("Configured replica count used to assess availability and redundancy."),
        manifestYaml: z.string().min(2).optional().describe("Deployment, StatefulSet or DaemonSet YAML, optionally with Service, Ingress and PodDisruptionBudget documents."),
        hasReadinessProbe: z.boolean().optional().describe("Whether workload containers define readiness probes."),
        hasLivenessProbe: z.boolean().optional().describe("Whether workload containers define liveness probes."),
        hasResourceRequests: z.boolean().optional().describe("Whether workload containers define CPU or memory requests."),
        hasResourceLimits: z.boolean().optional().describe("Whether workload containers define CPU or memory limits."),
        hasPodDisruptionBudget: z.boolean().optional().describe("Whether a PodDisruptionBudget protects workload availability during voluntary disruption."),
        usesLatestTag: z.boolean().optional().describe("Whether any container image uses the mutable latest tag."),
        runsAsRoot: z.boolean().optional().describe("Whether the workload is configured to run containers as root."),
        exposesPublicService: z.boolean().optional().describe("Whether the workload is exposed through a public Service or ingress path.")
      }).refine((value) => Boolean(value.manifestYaml || value.workloadName), {
        message: "Provide workloadName or manifestYaml."
      }),
      outputSchema: z.object({
        workloadName: z.string(),
        namespace: z.string(),
        readinessScore: z.number(),
        readinessLevel: readinessSchema,
        assessmentConfidence: confidenceSchema,
        strengths: z.array(z.string()),
        findings: z.array(z.string()),
        uncertainties: z.array(z.string()),
        evidence: z.array(evidenceSchema),
        recommendedControls: z.array(z.string())
      })
    },
    async (input) => toolResult(reviewKubernetesDeployment(input))
  );

  server.registerTool(
    "review_github_actions_workflow",
    {
      title: "Review GitHub Actions Workflow",
      description: "Evaluate GitHub Actions workflow security and deployment readiness from structured facts or raw workflow YAML, including triggers, action pinning, token permissions, caching, environment protection and concurrency. Use review_cicd_pipeline for generic non-GitHub delivery-process review. It examines supplied evidence only and does not call GitHub or dispatch workflows.",
      annotations: readOnlyAnnotations,
      inputSchema: z.object({
        workflowName: z.string().min(2).describe("Human-readable name of the GitHub Actions workflow being reviewed."),
        workflowYaml: z.string().min(2).optional().describe("Raw GitHub Actions workflow YAML. The server derives triggers, action pinning, token permissions, caching and concurrency."),
        triggers: z.array(z.string()).min(1).optional().describe("Workflow trigger events when raw YAML is not supplied, such as push, pull_request or workflow_dispatch."),
        deploysToProduction: z.boolean().optional().describe("Whether the workflow can deploy directly or indirectly to production."),
        usesPinnedActions: z.boolean().optional().describe("Whether third-party actions are pinned to immutable commit SHAs."),
        hasLeastPrivilegePermissions: z.boolean().optional().describe("Whether GITHUB_TOKEN permissions are explicitly restricted to least privilege."),
        hasSecretScanning: z.boolean().optional().describe("Whether the workflow or surrounding delivery process performs automated secret scanning."),
        hasDependencyCaching: z.boolean().optional().describe("Whether dependency caching is configured for repeatable and efficient builds."),
        hasEnvironmentProtection: z.boolean().optional().describe("Whether protected GitHub environments or equivalent approval controls guard production deployments."),
        hasConcurrencyControl: z.boolean().optional().describe("Whether concurrency settings prevent overlapping or conflicting workflow runs.")
      }).refine((value) => Boolean(value.workflowYaml || value.triggers?.length), {
        message: "Provide triggers or workflowYaml."
      }),
      outputSchema: z.object({
        workflowName: z.string(),
        workflowScore: z.number(),
        readinessLevel: readinessSchema,
        assessmentConfidence: confidenceSchema,
        triggers: z.array(z.string()),
        strengths: z.array(z.string()),
        findings: z.array(z.string()),
        uncertainties: z.array(z.string()),
        evidence: z.array(evidenceSchema),
        recommendedControls: z.array(z.string())
      })
    },
    async (input) => toolResult(reviewGitHubActionsWorkflow(input))
  );

  server.registerTool(
    "review_cloud_identity_policy",
    {
      title: "Review Cloud Identity Policy",
      description: "Apply deterministic provider-specific identity policy packs to raw AWS IAM, Azure RBAC or GCP IAM policy documents. Use this for cross-cloud identity security analysis; use review_iam_policy when assessing AWS IAM from mixed structured facts or policy JSON. It analyzes supplied policy JSON only and does not call cloud APIs or change permissions.",
      annotations: readOnlyAnnotations,
      inputSchema: z.object({
        provider: z.enum(["aws", "azure", "gcp"]).describe("Cloud provider whose identity policy syntax and policy pack should be applied."),
        policyName: z.string().min(2).describe("Name or identifier of the identity policy being reviewed."),
        policyJson: z.string().min(2).max(4_000_000).describe("Raw provider policy document in JSON form; AWS IAM, Azure role definition/assignment data, or GCP IAM policy."),
        environment: z.enum(["dev", "staging", "production"]).optional().describe("Optional deployment environment used to contextualize policy risk; defaults are handled by the policy pack.")
      }),
      outputSchema: z.object({
        provider: z.enum(["aws", "azure", "gcp"]),
        policyPack: z.string(),
        policyName: z.string(),
        environment: z.enum(["dev", "staging", "production"]),
        ...securitySummaryShape,
        facts: z.array(z.string()),
        findings: z.array(securityFindingSchema),
        recommendedGate: z.enum(["block", "security-review", "standard-review"])
      })
    },
    async (input) => toolResult(reviewCloudIdentityPolicy(input))
  );

  server.registerTool(
    "review_terraform_security",
    {
      title: "Review Terraform Security",
      description: "Inspect raw Terraform plan JSON for security-relevant changes such as destructive actions, public exposure, encryption gaps, deletion protection and IAM wildcard risk. Use this for Terraform security posture; use assess_terraform_change for broader release/change risk and governance. It parses the supplied plan only and does not execute Terraform or write state.",
      annotations: readOnlyAnnotations,
      inputSchema: z.object({
        terraformPlanJson: z.string().min(2).max(4_000_000).describe("Raw Terraform plan JSON, typically produced by terraform show -json, to inspect for security-relevant resource changes."),
        environment: z.enum(["dev", "staging", "production"]).optional().describe("Optional target environment used to contextualize the severity of findings.")
      }),
      outputSchema: z.object({
        environment: z.enum(["dev", "staging", "production"]),
        policyPack: z.string(),
        changedResources: z.number(),
        destructiveChanges: z.number(),
        replacements: z.number(),
        ...securitySummaryShape,
        findings: z.array(securityFindingSchema),
        recommendedGate: z.enum(["block", "change-advisory-review", "standard-review"])
      })
    },
    async (input) => toolResult(reviewTerraformSecurity(input))
  );

  server.registerTool(
    "review_kubernetes_security",
    {
      title: "Review Kubernetes Security",
      description: "Apply Kubernetes workload security rules to manifest YAML for privileged mode, host access, Linux capabilities, service accounts, seccomp, filesystem settings and network policy. Use this for security hardening; use review_kubernetes_deployment for reliability and production-readiness checks. It analyzes supplied YAML only and does not connect to a cluster.",
      annotations: readOnlyAnnotations,
      inputSchema: z.object({
        manifestYaml: z.string().min(2).max(4_000_000).describe("Raw multi-document Kubernetes YAML containing workloads and related policy objects to evaluate for security hardening."),
        environment: z.enum(["dev", "staging", "production"]).optional().describe("Optional target environment used to contextualize security findings.")
      }),
      outputSchema: z.object({
        environment: z.enum(["dev", "staging", "production"]),
        policyPack: z.string(),
        workloadCount: z.number(),
        publicExposureObjects: z.number(),
        networkPolicyPresent: z.boolean(),
        ...securitySummaryShape,
        findings: z.array(securityFindingSchema),
        recommendedGate: z.enum(["block", "security-review", "standard-review"])
      })
    },
    async (input) => toolResult(reviewKubernetesSecurity(input))
  );

  server.registerTool(
    "review_software_supply_chain",
    {
      title: "Review Software Supply Chain",
      description: "Correlate CycloneDX/SPDX SBOM quality with CI action pinning, Kubernetes image immutability, artifact signing and build provenance to assess software-supply-chain risk. Use this when an SBOM is available and supply-chain evidence needs to be evaluated together. It analyzes supplied artifacts only and does not call registries, CI systems, or clusters.",
      annotations: readOnlyAnnotations,
      inputSchema: z.object({
        sbomJson: z.string().min(2).max(4_000_000).describe("CycloneDX or SPDX SBOM JSON used as the primary software-supply-chain evidence."),
        workflowYaml: z.string().min(2).max(2_000_000).optional().describe("Optional GitHub Actions workflow YAML used to inspect action pinning and build controls."),
        kubernetesManifestYaml: z.string().min(2).max(4_000_000).optional().describe("Optional Kubernetes manifest YAML used to inspect runtime image immutability."),
        artifactSigned: z.boolean().optional().describe("Whether released artifacts or images are cryptographically signed."),
        hasProvenance: z.boolean().optional().describe("Whether verifiable build provenance or attestation is produced for released artifacts."),
        environment: z.enum(["dev", "staging", "production"]).optional().describe("Optional target environment used to contextualize supply-chain risk.")
      }),
      outputSchema: z.object({
        environment: z.enum(["dev", "staging", "production"]),
        policyPack: z.string(),
        sbomFormat: z.enum(["CycloneDX", "SPDX"]),
        sbomSpecVersion: z.string(),
        componentCount: z.number(),
        metadataCoverage: z.object({
          versionsPresentPercent: z.number(),
          hashesPresentPercent: z.number(),
          purlPresentPercent: z.number(),
          licensesPresentPercent: z.number()
        }),
        mutableActionReferences: z.boolean(),
        mutableRuntimeImages: z.boolean(),
        artifactSigned: z.boolean().nullable(),
        hasProvenance: z.boolean().nullable(),
        ...securitySummaryShape,
        findings: z.array(securityFindingSchema),
        correlationPaths: z.array(z.object({
          pathId: z.string(),
          severity: z.enum(["high", "critical"]),
          sequence: z.array(z.string()),
          impact: z.string()
        })),
        recommendedGate: z.enum(["block", "supply-chain-review", "standard-review"])
      })
    },
    async (input) => toolResult(reviewSoftwareSupplyChain(input))
  );

  if (process.env.CLOUD_DEVOPS_MCP_EXECUTION_ENABLED === "true") {
    const mutatingAnnotations = {
      readOnlyHint: false,
      destructiveHint: false,
      idempotentHint: false,
      openWorldHint: true
    } as const;
    const remoteSyncAnnotations = {
      readOnlyHint: false,
      destructiveHint: false,
      idempotentHint: true,
      openWorldHint: true
    } as const;

    server.registerTool(
      "git_status",
      {
        title: "Git Status",
        description: "Inspect an allowlisted local repository without modifying it.",
        annotations: readOnlyAnnotations,
        inputSchema: z.object({ repositoryPath: z.string().min(1) }),
        outputSchema: z.object({
          repositoryPath: z.string(),
          branch: z.string(),
          clean: z.boolean(),
          changedPaths: z.array(z.string()),
          ahead: z.number().nullable(),
          behind: z.number().nullable()
        })
      },
      async (input) => toolResult(await gitStatus(input))
    );

    server.registerTool(
      "git_fetch",
      {
        title: "Git Fetch",
        description: "Fetch remote refs for an allowlisted repository using an allowlisted remote.",
        annotations: remoteSyncAnnotations,
        inputSchema: z.object({
          repositoryPath: z.string().min(1),
          remote: z.string().optional(),
          prune: z.boolean().optional()
        }),
        outputSchema: z.object({
          repositoryPath: z.string(),
          remote: z.string(),
          fetched: z.boolean(),
          output: z.string()
        })
      },
      async (input) => toolResult(await gitFetch(input))
    );

    server.registerTool(
      "git_pull_ff_only",
      {
        title: "Git Pull Fast Forward Only",
        description: "Pull the currently checked-out branch with --ff-only. Dirty working trees are rejected.",
        annotations: remoteSyncAnnotations,
        inputSchema: z.object({
          repositoryPath: z.string().min(1),
          remote: z.string().optional(),
          branch: z.string().optional()
        }),
        outputSchema: z.object({
          repositoryPath: z.string(),
          remote: z.string(),
          branch: z.string(),
          updated: z.boolean(),
          output: z.string()
        })
      },
      async (input) => toolResult(await gitPullFfOnly(input))
    );

    server.registerTool(
      "git_create_branch",
      {
        title: "Git Create Branch",
        description: "Create and switch to an allowlisted non-protected branch from an approved local repository.",
        annotations: mutatingAnnotations,
        inputSchema: z.object({
          repositoryPath: z.string().min(1),
          branch: z.string().min(1),
          startPoint: z.string().optional()
        }),
        outputSchema: z.object({
          repositoryPath: z.string(),
          branch: z.string(),
          created: z.boolean(),
          startPoint: z.string()
        })
      },
      async (input) => toolResult(await gitCreateBranch(input))
    );

    server.registerTool(
      "git_commit",
      {
        title: "Git Commit Selected Files",
        description: "Stage only explicitly named repository paths and commit them on a non-protected branch. Supports dry-run preview.",
        annotations: mutatingAnnotations,
        inputSchema: z.object({
          repositoryPath: z.string().min(1),
          files: z.array(z.string().min(1)).min(1).max(100),
          message: z.string().min(1).max(160),
          dryRun: z.boolean().optional()
        }),
        outputSchema: z.object({
          repositoryPath: z.string(),
          branch: z.string(),
          dryRun: z.boolean().optional(),
          committed: z.boolean().optional(),
          commitSha: z.string().optional(),
          files: z.array(z.string()),
          preview: z.string().optional()
        })
      },
      async (input) => toolResult(await gitCommit(input))
    );

    server.registerTool(
      "git_push",
      {
        title: "Git Push",
        description: "Push only the current non-protected branch to an allowlisted remote. Force-push is never used. Supports dry-run.",
        annotations: mutatingAnnotations,
        inputSchema: z.object({
          repositoryPath: z.string().min(1),
          remote: z.string().optional(),
          dryRun: z.boolean().optional()
        }),
        outputSchema: z.object({
          repositoryPath: z.string(),
          remote: z.string(),
          branch: z.string(),
          dryRun: z.boolean(),
          pushed: z.boolean(),
          output: z.string()
        })
      },
      async (input) => toolResult(await gitPush(input))
    );

    server.registerTool(
      "github_create_pull_request",
      {
        title: "GitHub Create Pull Request",
        description: "Create a pull request from the current non-protected branch in an explicitly allowlisted GitHub repository.",
        annotations: mutatingAnnotations,
        inputSchema: z.object({
          repositoryPath: z.string().min(1),
          title: z.string().min(1).max(256),
          body: z.string().max(20000).optional(),
          base: z.string().optional(),
          draft: z.boolean().optional()
        }),
        outputSchema: z.object({
          repositoryPath: z.string(),
          repository: z.string(),
          number: z.number(),
          url: z.string(),
          state: z.string(),
          head: z.string(),
          base: z.string(),
          draft: z.boolean()
        })
      },
      async (input) => toolResult(await githubCreatePullRequest(input))
    );

    server.registerTool(
      "github_check_pull_request",
      {
        title: "GitHub Check Pull Request",
        description: "Inspect pull request mergeability and GitHub Actions check runs for an allowlisted repository.",
        annotations: { ...readOnlyAnnotations, openWorldHint: true },
        inputSchema: z.object({
          repositoryPath: z.string().min(1),
          pullRequestNumber: z.number().int().positive()
        }),
        outputSchema: z.object({
          repositoryPath: z.string(),
          repository: z.string(),
          number: z.number(),
          url: z.string(),
          state: z.string(),
          draft: z.boolean(),
          mergeable: z.boolean().nullable(),
          mergeableState: z.string(),
          headSha: z.string(),
          base: z.string(),
          checks: z.array(z.object({
            name: z.string(),
            status: z.string(),
            conclusion: z.string().nullable()
          })),
          allChecksPassed: z.boolean()
        })
      },
      async (input) => toolResult(await githubCheckPullRequest(input))
    );

    server.registerTool(
      "github_merge_pull_request",
      {
        title: "GitHub Merge Pull Request",
        description: "Merge an open PR only after CI checks pass and confirm is exactly MERGE. Direct protected-branch pushes remain blocked.",
        annotations: { ...mutatingAnnotations, destructiveHint: true },
        inputSchema: z.object({
          repositoryPath: z.string().min(1),
          pullRequestNumber: z.number().int().positive(),
          confirm: z.literal("MERGE"),
          method: z.enum(["merge", "squash", "rebase"]).optional()
        }),
        outputSchema: z.object({
          repositoryPath: z.string(),
          repository: z.string(),
          number: z.number(),
          merged: z.boolean(),
          commitSha: z.string(),
          message: z.string()
        })
      },
      async (input) => toolResult(await githubMergePullRequest(input))
    );

    server.registerTool(
      "github_trigger_workflow",
      {
        title: "GitHub Trigger Workflow",
        description: "Dispatch only an explicitly allowlisted GitHub Actions workflow. confirm must be exactly TRIGGER.",
        annotations: { ...mutatingAnnotations, destructiveHint: true },
        inputSchema: z.object({
          repositoryPath: z.string().min(1),
          workflow: z.string().min(1),
          ref: z.string().min(1),
          inputs: z.record(z.string(), z.string()).optional(),
          confirm: z.literal("TRIGGER")
        }),
        outputSchema: z.object({
          repositoryPath: z.string(),
          repository: z.string(),
          workflow: z.string(),
          ref: z.string(),
          triggered: z.boolean()
        })
      },
      async (input) => toolResult(await githubTriggerWorkflow(input))
    );
  }


  if (process.env.CLOUD_DEVOPS_MCP_INFRASTRUCTURE_OPERATIONS_ENABLED === "true") {
    const externalReadAnnotations = {
      readOnlyHint: true,
      destructiveHint: false,
      idempotentHint: true,
      openWorldHint: true
    } as const;

    server.registerTool(
      "terraform_fmt_check",
      {
        title: "Terraform Format Check",
        description: "Run terraform fmt in check-only mode inside an allowlisted repository. It never rewrites Terraform files.",
        annotations: readOnlyAnnotations,
        inputSchema: z.object({
          repositoryPath: z.string().min(1),
          workingDirectory: z.string().optional()
        }),
        outputSchema: z.object({
          repositoryPath: z.string(),
          workingDirectory: z.string(),
          formatted: z.boolean(),
          exitCode: z.number(),
          diff: z.string()
        })
      },
      async (input) => toolResult(await terraformFmtCheck(input))
    );

    server.registerTool(
      "terraform_validate",
      {
        title: "Terraform Validate",
        description: "Run terraform validate -json inside an allowlisted repository and return bounded diagnostics. It does not initialize providers, plan or apply infrastructure.",
        annotations: readOnlyAnnotations,
        inputSchema: z.object({
          repositoryPath: z.string().min(1),
          workingDirectory: z.string().optional()
        }),
        outputSchema: z.object({
          repositoryPath: z.string(),
          workingDirectory: z.string(),
          valid: z.boolean(),
          errorCount: z.number(),
          warningCount: z.number(),
          diagnostics: z.array(z.object({
            severity: z.string(),
            summary: z.string(),
            detail: z.string()
          }))
        })
      },
      async (input) => toolResult(await terraformValidate(input))
    );

    server.registerTool(
      "terraform_plan_summary",
      {
        title: "Terraform Plan Summary",
        description: "Run a non-apply Terraform plan with refresh disabled and return only a change summary. The tool never exposes full plan JSON and never runs terraform apply.",
        annotations: externalReadAnnotations,
        inputSchema: z.object({
          repositoryPath: z.string().min(1),
          workingDirectory: z.string().optional(),
          varFiles: z.array(z.string().min(1)).max(20).optional()
        }),
        outputSchema: z.object({
          repositoryPath: z.string(),
          workingDirectory: z.string(),
          planSucceeded: z.boolean(),
          hasChanges: z.boolean(),
          exitCode: z.number(),
          resourceChangeCount: z.number(),
          counts: z.object({
            create: z.number(),
            update: z.number(),
            delete: z.number(),
            replace: z.number(),
            read: z.number(),
            noOp: z.number()
          }),
          diagnostic: z.string()
        })
      },
      async (input) => toolResult(await terraformPlanSummary(input))
    );

    server.registerTool(
      "kubectl_current_context",
      {
        title: "Kubernetes Current Context",
        description: "Read the current kubectl context and require it to match the configured context allowlist before returning it.",
        annotations: readOnlyAnnotations,
        inputSchema: z.object({
          repositoryPath: z.string().min(1)
        }),
        outputSchema: z.object({
          repositoryPath: z.string(),
          context: z.string(),
          allowed: z.boolean()
        })
      },
      async (input) => toolResult(await kubectlCurrentContext(input))
    );

    server.registerTool(
      "kubectl_get_resources",
      {
        title: "Kubernetes Get Resources",
        description: "Read bounded metadata and status summaries for allowlisted Kubernetes resource types, contexts and namespaces. Secrets and arbitrary resource types are not exposed.",
        annotations: externalReadAnnotations,
        inputSchema: z.object({
          repositoryPath: z.string().min(1),
          context: z.string().min(1),
          resource: z.string().min(1),
          namespace: z.string().optional(),
          name: z.string().optional(),
          labelSelector: z.string().max(300).optional()
        }),
        outputSchema: z.object({
          repositoryPath: z.string(),
          context: z.string(),
          namespace: z.string(),
          resource: z.string(),
          count: z.number(),
          objects: z.array(z.object({
            kind: z.string(),
            name: z.string(),
            namespace: z.string(),
            phase: z.string().optional(),
            replicas: z.number().optional(),
            readyReplicas: z.number().optional()
          }))
        })
      },
      async (input) => toolResult(await kubectlGetResources(input))
    );

    server.registerTool(
      "kubectl_rollout_status",
      {
        title: "Kubernetes Rollout Status",
        description: "Read rollout readiness for an allowlisted Deployment, StatefulSet or DaemonSet without watching indefinitely or mutating the cluster.",
        annotations: externalReadAnnotations,
        inputSchema: z.object({
          repositoryPath: z.string().min(1),
          context: z.string().min(1),
          namespace: z.string().min(1),
          kind: z.enum(["deployment", "statefulset", "daemonset"]),
          name: z.string().min(1)
        }),
        outputSchema: z.object({
          repositoryPath: z.string(),
          context: z.string(),
          namespace: z.string(),
          resource: z.string(),
          ready: z.boolean(),
          exitCode: z.number(),
          message: z.string()
        })
      },
      async (input) => toolResult(await kubectlRolloutStatus(input))
    );
  }


  if (process.env.CLOUD_DEVOPS_MCP_CLOUD_INVENTORY_ENABLED === "true") {
    const liveReadAnnotations = {
      readOnlyHint: true,
      destructiveHint: false,
      idempotentHint: true,
      openWorldHint: true
    } as const;

    const cloudScopeSchema = z.object({
      provider: z.enum(["aws", "azure", "gcp"]),
      region: z.string().optional(),
      profile: z.string().optional(),
      subscriptionId: z.string().optional(),
      projectId: z.string().optional()
    });

    server.registerTool(
      "cloud_whoami",
      {
        title: "Cloud Identity",
        description: "Verify the active allowlisted AWS, Azure or GCP identity/scope before live reads. No credentials or tokens are returned.",
        annotations: liveReadAnnotations,
        inputSchema: cloudScopeSchema,
        outputSchema: z.object({
          provider: z.enum(["aws", "azure", "gcp"]),
          scope: z.string(),
          subject: z.string(),
          region: z.string()
        })
      },
      async (input) => toolResult(await cloudWhoAmI(input))
    );

    server.registerTool(
      "cloud_inventory_summary",
      {
        title: "Cloud Inventory Summary",
        description: "Read a bounded live resource inventory from an explicitly allowlisted AWS account/region, Azure subscription or GCP project.",
        annotations: liveReadAnnotations,
        inputSchema: cloudScopeSchema,
        outputSchema: z.object({
          provider: z.enum(["aws", "azure", "gcp"]),
          scope: z.string(),
          source: z.string(),
          resourceCount: z.number(),
          typeCounts: z.record(z.string(), z.number()),
          resources: z.array(z.object({
            id: z.string(),
            name: z.string(),
            type: z.string(),
            location: z.string(),
            state: z.string().optional()
          }))
        })
      },
      async (input) => toolResult(await cloudInventorySummary(input))
    );

    server.registerTool(
      "cloud_kubernetes_clusters",
      {
        title: "Cloud Kubernetes Clusters",
        description: "List EKS, AKS or GKE clusters from an explicitly allowlisted cloud scope without changing cluster or cloud state.",
        annotations: liveReadAnnotations,
        inputSchema: cloudScopeSchema,
        outputSchema: z.object({
          provider: z.enum(["aws", "azure", "gcp"]),
          scope: z.string(),
          clusterCount: z.number(),
          clusters: z.array(z.object({
            name: z.string(),
            location: z.string(),
            state: z.string()
          }))
        })
      },
      async (input) => toolResult(await cloudKubernetesClusters(input))
    );

    server.registerTool(
      "cloud_observability_summary",
      {
        title: "Cloud Observability Summary",
        description: "Read bounded observability configuration signals: CloudWatch alarms, Azure metric alerts or GCP logging sinks.",
        annotations: liveReadAnnotations,
        inputSchema: cloudScopeSchema,
        outputSchema: z.object({
          provider: z.enum(["aws", "azure", "gcp"]),
          scope: z.string(),
          signalType: z.string(),
          configuredCount: z.number(),
          stateCounts: z.record(z.string(), z.number())
        })
      },
      async (input) => toolResult(await cloudObservabilitySummary(input))
    );

    server.registerTool(
      "cloud_finops_signals",
      {
        title: "Cloud FinOps Signals",
        description: "Identify bounded, read-only cost-waste signals such as unattached disks/volumes and unassociated static public IPs in an allowlisted cloud scope.",
        annotations: liveReadAnnotations,
        inputSchema: cloudScopeSchema,
        outputSchema: z.object({
          provider: z.enum(["aws", "azure", "gcp"]),
          scope: z.string(),
          findingCount: z.number(),
          findings: z.array(z.object({
            ruleId: z.string(),
            resourceId: z.string(),
            detail: z.string()
          }))
        })
      },
      async (input) => toolResult(await cloudFinOpsSignals(input))
    );

    server.registerTool(
      "cloud_drift_compare",
      {
        title: "Cloud Drift Compare",
        description: "Compare expected resource identifiers with the bounded live inventory of an allowlisted cloud scope. It reports drift only and never reconciles resources.",
        annotations: liveReadAnnotations,
        inputSchema: cloudScopeSchema.extend({
          expectedResourceIds: z.array(z.string().min(1).max(1000)).min(1).max(500),
          includeUnexpected: z.boolean().optional()
        }),
        outputSchema: z.object({
          provider: z.enum(["aws", "azure", "gcp"]),
          scope: z.string(),
          expectedCount: z.number(),
          liveCount: z.number(),
          missingExpected: z.array(z.string()),
          unexpectedLive: z.array(z.string()),
          driftDetected: z.boolean()
        })
      },
      async (input) => toolResult(await cloudDriftCompare(input))
    );
  }


  return server;
}

const invokedPath = process.argv[1] ? pathToFileURL(process.argv[1]).href : undefined;
if (invokedPath === import.meta.url) {
  if (process.argv.includes("--http")) {
    const { startHttpServer } = await import("./http.js");
    await startHttpServer(createServer);
    console.error(`cloud-devops-mcp-server v${VERSION} running on authenticated Streamable HTTP`);
  } else {
    void serveStdio(createServer);
    console.error(`cloud-devops-mcp-server v${VERSION} running on stdio`);
  }
}
