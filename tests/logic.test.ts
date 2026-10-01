import { describe, expect, it } from "vitest";
import {
  assessTerraformChange,
  buildIncidentRunbook,
  estimateSloBudget,
  reviewGitHubActionsWorkflow,
  reviewIamPolicy,
  reviewKubernetesDeployment,
  reviewPipeline
} from "../src/logic.js";

describe("assessTerraformChange", () => {
  it("raises risk for public ingress, IAM and missing controls", () => {
    const result = assessTerraformChange({
      changedResources: ["network", "iam"],
      includesIamChanges: true,
      includesPublicIngress: true,
      hasRollbackPlan: false,
      hasPeerReview: false,
      hasTerraformPlan: false
    });

    expect(result.riskLevel).toBe("critical");
    expect(result.checklist.join(" ")).toContain("least privilege");
  });
});

describe("buildIncidentRunbook", () => {
  it("creates production communication guidance for urgent incidents", () => {
    const result = buildIncidentRunbook({
      service: "payments-api",
      environment: "production",
      severity: "sev1",
      symptom: "elevated 5xx errors",
      signals: ["error rate above 12 percent"]
    });

    expect(result.communication[0]).toContain("15 minutes");
    expect(result.mitigation[0]).toContain("production");
  });
});

describe("reviewPipeline", () => {
  it("scores hardened pipelines as production ready", () => {
    const result = reviewPipeline({
      pipelineName: "platform-release",
      deploymentStrategy: "canary",
      environments: ["dev", "staging", "production"],
      hasAutomatedTests: true,
      hasSecurityScan: true,
      hasRollback: true,
      hasArtifactVersioning: true,
      hasManualApprovalForProduction: true
    });

    expect(result.readinessLevel).toBe("production-ready");
  });
});

describe("estimateSloBudget", () => {
  it("calculates downtime budget", () => {
    const result = estimateSloBudget({
      sloTargetPercent: 99.9,
      periodDays: 30,
      observedDowntimeMinutes: 12
    });

    expect(result.allowedDowntimeMinutes).toBe(43.2);
    expect(result.budgetStatus).toBe("within-budget");
  });
});

describe("reviewIamPolicy", () => {
  it("flags wildcard and privilege escalation risk", () => {
    const result = reviewIamPolicy({
      policyName: "platform-admin",
      actions: ["iam:*", "sts:AssumeRole"],
      resources: ["*"],
      hasWildcardActions: true,
      hasWildcardResources: true,
      allowsPrivilegeEscalationActions: true,
      hasConditionBlocks: false,
      usedByProduction: true
    });

    expect(result.riskLevel).toBe("critical");
    expect(result.findings.join(" ")).toContain("privilege-escalation");
  });
});

describe("reviewKubernetesDeployment", () => {
  it("marks hardened workloads as production ready", () => {
    const result = reviewKubernetesDeployment({
      workloadName: "payments-api",
      namespace: "production",
      replicas: 3,
      hasReadinessProbe: true,
      hasLivenessProbe: true,
      hasResourceRequests: true,
      hasResourceLimits: true,
      hasPodDisruptionBudget: true,
      usesLatestTag: false,
      runsAsRoot: false,
      exposesPublicService: false
    });

    expect(result.readinessLevel).toBe("production-ready");
    expect(result.strengths.join(" ")).toContain("Replica");
  });
});

describe("reviewGitHubActionsWorkflow", () => {
  it("flags unsafe production workflows", () => {
    const result = reviewGitHubActionsWorkflow({
      workflowName: "production-deploy",
      triggers: ["push", "pull_request_target"],
      deploysToProduction: true,
      usesPinnedActions: false,
      hasLeastPrivilegePermissions: false,
      hasSecretScanning: false,
      hasDependencyCaching: true,
      hasEnvironmentProtection: false,
      hasConcurrencyControl: false
    });

    expect(result.readinessLevel).toBe("not-ready");
    expect(result.findings.join(" ")).toContain("protected environments");
  });
});
