import { describe, expect, it } from "vitest";
import {
  assessTerraformChange,
  buildIncidentRunbook,
  estimateSloBudget,
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
