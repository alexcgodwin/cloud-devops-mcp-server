#!/usr/bin/env node
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import {
  assessTerraformChange,
  buildIncidentRunbook,
  estimateSloBudget,
  reviewGitHubActionsWorkflow,
  reviewIamPolicy,
  reviewKubernetesDeployment,
  reviewPipeline
} from "./logic.js";

const server = new McpServer({
  name: "cloud-devops-mcp-server",
  version: "0.1.0"
});

function jsonResponse(payload: unknown) {
  return {
    content: [
      {
        type: "text" as const,
        text: JSON.stringify(payload, null, 2)
      }
    ]
  };
}

server.tool(
  "assess_terraform_change",
  "Assess Terraform or infrastructure-as-code change risk before deployment.",
  {
    changedResources: z
      .array(z.enum(["network", "iam", "database", "kubernetes", "compute", "observability", "ci_cd", "dns"]))
      .min(1)
      .describe("Infrastructure resource classes changed by the pull request or deployment."),
    includesIamChanges: z.boolean().optional().describe("Whether identity, access policy or role changes are included."),
    includesPublicIngress: z.boolean().optional().describe("Whether public access, listener or ingress changes are included."),
    modifiesStatefulResources: z.boolean().optional().describe("Whether databases, volumes, queues or persistent resources are modified."),
    hasRollbackPlan: z.boolean().optional().describe("Whether the change has a documented rollback or forward-fix plan."),
    hasPeerReview: z.boolean().optional().describe("Whether another engineer reviewed the change."),
    hasTerraformPlan: z.boolean().optional().describe("Whether terraform plan or equivalent preview was generated and reviewed.")
  },
  async (input) => jsonResponse(assessTerraformChange(input))
);

server.tool(
  "build_incident_runbook",
  "Create a practical incident response runbook for a cloud service symptom.",
  {
    service: z.string().min(2).describe("Service, platform or application name."),
    environment: z.enum(["dev", "staging", "production"]).describe("Environment where the incident is happening."),
    severity: z.enum(["sev1", "sev2", "sev3", "sev4"]).describe("Incident severity."),
    symptom: z.string().min(5).describe("Observed symptom or user impact."),
    signals: z.array(z.string()).optional().describe("Metrics, logs, traces, alerts or other signals already observed.")
  },
  async (input) => jsonResponse(buildIncidentRunbook(input))
);

server.tool(
  "review_cicd_pipeline",
  "Review CI/CD readiness for production deployment and recommend release gates.",
  {
    pipelineName: z.string().min(2).describe("Pipeline or workflow name."),
    deploymentStrategy: z.enum(["rolling", "blue_green", "canary", "recreate", "manual"]).describe("Deployment strategy used by the pipeline."),
    environments: z.array(z.string()).min(1).describe("Environments promoted through the delivery path."),
    hasAutomatedTests: z.boolean().optional().describe("Whether automated tests run before deployment."),
    hasSecurityScan: z.boolean().optional().describe("Whether dependency, container or static scans run before deployment."),
    hasRollback: z.boolean().optional().describe("Whether rollback is automated or documented and tested."),
    hasArtifactVersioning: z.boolean().optional().describe("Whether artifacts are immutable and traceable to source control."),
    hasManualApprovalForProduction: z.boolean().optional().describe("Whether production requires approval or controlled promotion.")
  },
  async (input) => jsonResponse(reviewPipeline(input))
);

server.tool(
  "estimate_slo_error_budget",
  "Calculate SLO error budget for downtime and optional request failure budget.",
  {
    sloTargetPercent: z.number().gt(0).lt(100).describe("Target availability percentage, for example 99.9."),
    periodDays: z.number().int().positive().describe("SLO window in days."),
    observedDowntimeMinutes: z.number().min(0).describe("Downtime already consumed in minutes."),
    requestVolume: z.number().int().positive().optional().describe("Optional total request volume for the SLO window."),
    failedRequests: z.number().int().min(0).optional().describe("Optional failed request count for the SLO window.")
  },
  async (input) => jsonResponse(estimateSloBudget(input))
);

server.tool(
  "review_iam_policy",
  "Review AWS IAM policy risk for least privilege, wildcard access and privilege-escalation paths.",
  {
    policyName: z.string().min(2).describe("IAM policy, role or permission set name."),
    actions: z.array(z.string()).min(1).describe("Allowed IAM actions or service actions in the policy."),
    resources: z.array(z.string()).min(1).describe("Resource ARNs or resource patterns affected by the policy."),
    hasWildcardActions: z.boolean().optional().describe("Whether the policy includes broad action wildcards such as * or service:*"),
    hasWildcardResources: z.boolean().optional().describe("Whether the policy allows access to * or broad resource wildcards."),
    allowsPrivilegeEscalationActions: z
      .boolean()
      .optional()
      .describe("Whether the policy allows privilege-escalation paths such as iam:PassRole, sts:AssumeRole or policy attachment."),
    hasConditionBlocks: z.boolean().optional().describe("Whether the policy uses condition blocks to narrow access."),
    usedByProduction: z.boolean().optional().describe("Whether this policy is used by production workloads or production operators.")
  },
  async (input) => jsonResponse(reviewIamPolicy(input))
);

server.tool(
  "review_kubernetes_deployment",
  "Review Kubernetes workload production readiness and operational safety controls.",
  {
    workloadName: z.string().min(2).describe("Deployment, StatefulSet or workload name."),
    namespace: z.string().min(1).describe("Kubernetes namespace."),
    replicas: z.number().int().min(0).describe("Configured replica count."),
    hasReadinessProbe: z.boolean().optional().describe("Whether the workload has a readiness probe."),
    hasLivenessProbe: z.boolean().optional().describe("Whether the workload has a liveness probe."),
    hasResourceRequests: z.boolean().optional().describe("Whether CPU and memory requests are configured."),
    hasResourceLimits: z.boolean().optional().describe("Whether CPU and memory limits are configured."),
    hasPodDisruptionBudget: z.boolean().optional().describe("Whether a PodDisruptionBudget protects voluntary disruption."),
    usesLatestTag: z.boolean().optional().describe("Whether containers use the mutable latest tag."),
    runsAsRoot: z.boolean().optional().describe("Whether the workload runs as root or lacks restricted security context."),
    exposesPublicService: z.boolean().optional().describe("Whether the workload is reachable from the public internet.")
  },
  async (input) => jsonResponse(reviewKubernetesDeployment(input))
);

server.tool(
  "review_github_actions_workflow",
  "Review GitHub Actions workflow security, release safety and production deployment readiness.",
  {
    workflowName: z.string().min(2).describe("Workflow name."),
    triggers: z.array(z.string()).min(1).describe("Workflow triggers such as push, pull_request, workflow_dispatch or pull_request_target."),
    deploysToProduction: z.boolean().optional().describe("Whether this workflow deploys or promotes to production."),
    usesPinnedActions: z.boolean().optional().describe("Whether actions are pinned to trusted versions or commit SHAs."),
    hasLeastPrivilegePermissions: z.boolean().optional().describe("Whether the workflow sets explicit least-privilege token permissions."),
    hasSecretScanning: z.boolean().optional().describe("Whether secret scanning or credential guardrails are present."),
    hasDependencyCaching: z.boolean().optional().describe("Whether dependency caching is configured where appropriate."),
    hasEnvironmentProtection: z.boolean().optional().describe("Whether production environments require reviewers or protected deployment rules."),
    hasConcurrencyControl: z.boolean().optional().describe("Whether concurrency prevents overlapping deployments.")
  },
  async (input) => jsonResponse(reviewGitHubActionsWorkflow(input))
);

const transport = new StdioServerTransport();
await server.connect(transport);
