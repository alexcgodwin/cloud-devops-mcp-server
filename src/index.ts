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

const VERSION = "0.4.0";

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
        "Use these read-only Cloud DevOps tools for evidence-backed review, multi-cloud identity policy analysis, Terraform and Kubernetes security checks, and supply-chain correlation. Prefer raw artifacts when available. Treat unknown evidence as unknown rather than assuming a failed control."
    }
  );

  server.registerTool(
    "assess_terraform_change",
    {
      title: "Assess Terraform Change",
      description: "Assess Terraform or infrastructure-as-code change risk from structured facts or Terraform plan JSON.",
      annotations: readOnlyAnnotations,
      inputSchema: z.object({
        changedResources: z
          .array(z.enum(["network", "iam", "database", "kubernetes", "compute", "observability", "ci_cd", "dns"]))
          .min(1)
          .optional()
          .describe("Infrastructure resource classes changed by the pull request or deployment."),
        terraformPlanJson: z.string().min(2).optional().describe("Optional raw Terraform plan JSON. When supplied, the server derives resource classes and evidence."),
        includesIamChanges: z.boolean().optional(),
        includesPublicIngress: z.boolean().optional(),
        modifiesStatefulResources: z.boolean().optional(),
        hasRollbackPlan: z.boolean().optional(),
        hasPeerReview: z.boolean().optional(),
        hasTerraformPlan: z.boolean().optional()
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
      description: "Correlate Terraform, IAM, Kubernetes and GitHub Actions evidence into one deployment-risk assessment with cross-domain change paths.",
      annotations: readOnlyAnnotations,
      inputSchema: z.object({
        changeName: z.string().min(2),
        environment: z.enum(["dev", "staging", "production"]),
        terraform: z.object({
          changedResources: z
            .array(z.enum(["network", "iam", "database", "kubernetes", "compute", "observability", "ci_cd", "dns"]))
            .min(1)
            .optional(),
          terraformPlanJson: z.string().min(2).optional(),
          includesIamChanges: z.boolean().optional(),
          includesPublicIngress: z.boolean().optional(),
          modifiesStatefulResources: z.boolean().optional(),
          hasRollbackPlan: z.boolean().optional(),
          hasPeerReview: z.boolean().optional(),
          hasTerraformPlan: z.boolean().optional()
        }).refine((value) => Boolean(value.terraformPlanJson || value.changedResources?.length), {
          message: "Terraform evidence requires changedResources or terraformPlanJson."
        }).optional(),
        iamPolicies: z.array(z.object({
          policyName: z.string().min(2),
          actions: z.array(z.string()).min(1).optional(),
          resources: z.array(z.string()).min(1).optional(),
          policyJson: z.string().min(2).optional(),
          hasWildcardActions: z.boolean().optional(),
          hasWildcardResources: z.boolean().optional(),
          allowsPrivilegeEscalationActions: z.boolean().optional(),
          hasConditionBlocks: z.boolean().optional(),
          usedByProduction: z.boolean().optional()
        }).refine((value) => Boolean(value.policyJson || (value.actions?.length && value.resources?.length)), {
          message: "Each IAM policy requires policyJson or both actions and resources."
        })).max(10).optional(),
        kubernetesWorkloads: z.array(z.object({
          workloadName: z.string().min(2).optional(),
          namespace: z.string().min(1).optional(),
          replicas: z.number().int().min(0).optional(),
          manifestYaml: z.string().min(2).optional(),
          hasReadinessProbe: z.boolean().optional(),
          hasLivenessProbe: z.boolean().optional(),
          hasResourceRequests: z.boolean().optional(),
          hasResourceLimits: z.boolean().optional(),
          hasPodDisruptionBudget: z.boolean().optional(),
          usesLatestTag: z.boolean().optional(),
          runsAsRoot: z.boolean().optional(),
          exposesPublicService: z.boolean().optional()
        }).refine((value) => Boolean(value.manifestYaml || value.workloadName), {
          message: "Each Kubernetes workload requires workloadName or manifestYaml."
        })).max(10).optional(),
        githubWorkflows: z.array(z.object({
          workflowName: z.string().min(2),
          workflowYaml: z.string().min(2).optional(),
          triggers: z.array(z.string()).min(1).optional(),
          deploysToProduction: z.boolean().optional(),
          usesPinnedActions: z.boolean().optional(),
          hasLeastPrivilegePermissions: z.boolean().optional(),
          hasSecretScanning: z.boolean().optional(),
          hasDependencyCaching: z.boolean().optional(),
          hasEnvironmentProtection: z.boolean().optional(),
          hasConcurrencyControl: z.boolean().optional()
        }).refine((value) => Boolean(value.workflowYaml || value.triggers?.length), {
          message: "Each GitHub Actions workflow requires workflowYaml or triggers."
        })).max(10).optional()
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
      description: "Create a practical incident response runbook for a cloud service symptom.",
      annotations: readOnlyAnnotations,
      inputSchema: z.object({
        service: z.string().min(2),
        environment: z.enum(["dev", "staging", "production"]),
        severity: z.enum(["sev1", "sev2", "sev3", "sev4"]),
        symptom: z.string().min(5),
        signals: z.array(z.string()).optional()
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
      description: "Review CI/CD readiness for production deployment while separating missing evidence from failed controls.",
      annotations: readOnlyAnnotations,
      inputSchema: z.object({
        pipelineName: z.string().min(2),
        deploymentStrategy: z.enum(["rolling", "blue_green", "canary", "recreate", "manual"]),
        environments: z.array(z.string()).min(1),
        hasAutomatedTests: z.boolean().optional(),
        hasSecurityScan: z.boolean().optional(),
        hasRollback: z.boolean().optional(),
        hasArtifactVersioning: z.boolean().optional(),
        hasManualApprovalForProduction: z.boolean().optional()
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
      description: "Calculate SLO downtime budget and optional request-failure budget with consistency checks.",
      annotations: readOnlyAnnotations,
      inputSchema: z.object({
        sloTargetPercent: z.number().gt(0).lt(100),
        periodDays: z.number().int().positive(),
        observedDowntimeMinutes: z.number().min(0),
        requestVolume: z.number().int().positive().optional(),
        failedRequests: z.number().int().min(0).optional()
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
      description: "Review AWS IAM policy risk from explicit facts or a raw policy JSON document.",
      annotations: readOnlyAnnotations,
      inputSchema: z.object({
        policyName: z.string().min(2),
        actions: z.array(z.string()).min(1).optional(),
        resources: z.array(z.string()).min(1).optional(),
        policyJson: z.string().min(2).optional().describe("Raw IAM policy JSON. The server derives wildcard and privilege-escalation evidence."),
        hasWildcardActions: z.boolean().optional(),
        hasWildcardResources: z.boolean().optional(),
        allowsPrivilegeEscalationActions: z.boolean().optional(),
        hasConditionBlocks: z.boolean().optional(),
        usedByProduction: z.boolean().optional()
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
      description: "Review Kubernetes production readiness from structured facts or multi-document Kubernetes YAML.",
      annotations: readOnlyAnnotations,
      inputSchema: z.object({
        workloadName: z.string().min(2).optional(),
        namespace: z.string().min(1).optional(),
        replicas: z.number().int().min(0).optional(),
        manifestYaml: z.string().min(2).optional().describe("Deployment/StatefulSet/DaemonSet YAML, optionally with Service, Ingress and PodDisruptionBudget documents."),
        hasReadinessProbe: z.boolean().optional(),
        hasLivenessProbe: z.boolean().optional(),
        hasResourceRequests: z.boolean().optional(),
        hasResourceLimits: z.boolean().optional(),
        hasPodDisruptionBudget: z.boolean().optional(),
        usesLatestTag: z.boolean().optional(),
        runsAsRoot: z.boolean().optional(),
        exposesPublicService: z.boolean().optional()
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
      description: "Review GitHub Actions security and deployment readiness from structured facts or raw workflow YAML.",
      annotations: readOnlyAnnotations,
      inputSchema: z.object({
        workflowName: z.string().min(2),
        workflowYaml: z.string().min(2).optional().describe("Raw GitHub Actions workflow YAML. The server derives triggers, action pinning, token permissions, caching and concurrency."),
        triggers: z.array(z.string()).min(1).optional(),
        deploysToProduction: z.boolean().optional(),
        usesPinnedActions: z.boolean().optional(),
        hasLeastPrivilegePermissions: z.boolean().optional(),
        hasSecretScanning: z.boolean().optional(),
        hasDependencyCaching: z.boolean().optional(),
        hasEnvironmentProtection: z.boolean().optional(),
        hasConcurrencyControl: z.boolean().optional()
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
      description: "Apply deterministic AWS IAM, Azure RBAC or GCP IAM policy packs to a raw policy document.",
      annotations: readOnlyAnnotations,
      inputSchema: z.object({
        provider: z.enum(["aws", "azure", "gcp"]),
        policyName: z.string().min(2),
        policyJson: z.string().min(2).max(4_000_000),
        environment: z.enum(["dev", "staging", "production"]).optional()
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
      description: "Inspect Terraform plan JSON for destructive changes, public exposure, encryption, deletion protection and IAM wildcard risk.",
      annotations: readOnlyAnnotations,
      inputSchema: z.object({
        terraformPlanJson: z.string().min(2).max(4_000_000),
        environment: z.enum(["dev", "staging", "production"]).optional()
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
      description: "Apply Kubernetes workload security rules for privileged mode, host access, capabilities, service accounts, seccomp, filesystems and network policy.",
      annotations: readOnlyAnnotations,
      inputSchema: z.object({
        manifestYaml: z.string().min(2).max(4_000_000),
        environment: z.enum(["dev", "staging", "production"]).optional()
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
      description: "Correlate CycloneDX or SPDX SBOM quality with CI action pinning, Kubernetes image immutability, artifact signing and provenance.",
      annotations: readOnlyAnnotations,
      inputSchema: z.object({
        sbomJson: z.string().min(2).max(4_000_000),
        workflowYaml: z.string().min(2).max(2_000_000).optional(),
        kubernetesManifestYaml: z.string().min(2).max(4_000_000).optional(),
        artifactSigned: z.boolean().optional(),
        hasProvenance: z.boolean().optional(),
        environment: z.enum(["dev", "staging", "production"]).optional()
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
