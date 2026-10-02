import { describe, expect, it } from "vitest";
import {
  analyzeFinOpsWaste,
  assessCloudHealth,
  assessObservabilityCoverage,
  correlateDeploymentIncident,
  detectConfigurationDrift,
  generateOperationsBrief
} from "../src/operations-intelligence.js";

describe("operations intelligence", () => {
  it("combines operational evidence into a bounded cloud-health score", () => {
    const result = assessCloudHealth({
      service: "payments-api",
      environment: "production",
      cloud: { resourceCount: 12, alarmStates: { ALARM: 2, OK: 4 } },
      metrics: [
        { name: "5xx", status: "critical", detail: "12% errors" },
        { name: "latency", status: "degraded", detail: "p95 elevated" }
      ],
      logs: { errorCount: 3, criticalCount: 1 },
      kubernetes: { podCount: 4, unhealthyCount: 2, restartingCount: 1 },
      cicd: { status: "failed", failedJobCount: 1 },
      slo: { budgetStatus: "exhausted", remainingPercent: 0 },
      drift: { driftDetected: true, missingExpected: 1 },
      finops: { findingCount: 2 }
    });
    expect(result.healthStatus).toBe("critical");
    expect(result.healthScore).toBeGreaterThanOrEqual(0);
    expect(result.signalSummary).toMatchObject({
      criticalMetricCount: 1,
      degradedMetricCount: 1,
      firingAlarmCount: 2
    });
    expect(result.recommendedActions.length).toBeGreaterThan(4);
  });  it("keeps healthy evidence healthy and reports no adverse evidence", () => {
    const result = assessCloudHealth({
      service: "api",
      environment: "staging",
      metrics: [{ name: "availability", status: "normal", detail: "healthy" }],
      slo: { budgetStatus: "within-budget", remainingPercent: 80 }
    });
    expect(result).toMatchObject({ healthScore: 100, healthStatus: "healthy" });
    expect(result.evidence).toContain("No adverse evidence was supplied.");
  });

  it("correlates post-deployment signals without declaring root cause", () => {
    const deployedAt = 1_700_000_000;
    const result = correlateDeploymentIncident({
      service: "checkout",
      deployment: { id: "deploy-42", deployedAt, status: "success" },
      windowMinutes: 30,
      metrics: [{ timestamp: deployedAt + 60, name: "5xx", status: "critical", detail: "errors rose" }],
      logs: [{ timestamp: deployedAt + 120, level: "error", message: "database timeout" }],
      alerts: [{ timestamp: deployedAt + 150, source: "grafana", status: "firing", summary: "High errors" }],
      kubernetes: [{ timestamp: deployedAt + 180, workload: "checkout", status: "degraded", detail: "pods restarting" }]
    });
    expect(result).toMatchObject({
      relationship: "strong",
      domainCount: 4,
      eventCount: 4,
      firstAdverseSeconds: 60
    });
    expect(result.nextChecks.join(" ")).toMatch(/before assigning causation/i);
  });  it("returns insufficient evidence when the deployment window has no adverse signals", () => {
    const result = correlateDeploymentIncident({
      service: "api",
      deployment: { id: "d1", deployedAt: 1000, status: "success" },
      metrics: [{ timestamp: 1010, name: "latency", status: "normal", detail: "normal" }]
    });
    expect(result).toMatchObject({
      relationship: "insufficient-evidence",
      domainCount: 0,
      eventCount: 0,
      firstAdverseSeconds: null
    });
  });

  it("measures observability coverage and lists exact gaps", () => {
    const result = assessObservabilityCoverage({
      service: "orders",
      metrics: true,
      logs: true,
      alerts: true,
      dashboards: true,
      slo: true,
      tracing: false,
      deploymentMarkers: false,
      onCallRunbook: true
    });
    expect(result).toMatchObject({ coverageScore: 75, maturity: "strong" });
    expect(result.gaps).toEqual(["tracing", "deploymentMarkers"]);
    expect(result.recommendedActions).toHaveLength(2);
  });  it("correlates cloud FinOps findings with Terraform ownership and low utilization", () => {
    const result = analyzeFinOpsWaste({
      cloudFindings: [
        { ruleId: "UNATTACHED_VOLUME", resourceId: "vol-1", detail: "available EBS volume" },
        { ruleId: "UNASSOCIATED_IP", resourceId: "eip-1", detail: "unassociated Elastic IP" }
      ],
      terraformManagedResourceIds: ["vol-1"],
      workloadUtilization: [
        {
          workload: "worker",
          cpuRequestMillicores: 1000,
          cpuUsageMillicores: 80,
          memoryRequestMiB: 1024,
          memoryUsageMiB: 100,
          replicas: 3
        },
        {
          workload: "api",
          cpuRequestMillicores: 1000,
          cpuUsageMillicores: 700
        }
      ]
    });
    expect(result).toMatchObject({
      cloudFindingCount: 2,
      terraformManagedFindingCount: 1,
      lowUtilizationWorkloadCount: 1
    });
    expect(result.cloudFindings[0].managedByTerraform).toBe(true);
    expect(result.lowUtilizationWorkloads[0].workload).toBe("worker");
  });  it("detects cloud and Kubernetes drift as separate domains", () => {
    const result = detectConfigurationDrift({
      expectedCloudResourceIds: ["a", "b"],
      liveCloudResourceIds: ["b", "c"],
      expectedKubernetesWorkloads: ["api", "worker"],
      liveKubernetesWorkloads: ["api", "cron"]
    });
    expect(result).toMatchObject({
      driftDetected: true,
      driftDomains: ["cloud", "kubernetes"],
      driftCount: 4,
      cloud: { missingExpected: ["a"], unexpectedLive: ["c"] },
      kubernetes: { missingExpected: ["worker"], unexpectedLive: ["cron"] }
    });
  });

  it("returns no drift for matching inventories", () => {
    const result = detectConfigurationDrift({
      expectedCloudResourceIds: ["a"],
      liveCloudResourceIds: ["a"],
      expectedKubernetesWorkloads: ["api"],
      liveKubernetesWorkloads: ["api"]
    });
    expect(result).toMatchObject({
      driftDetected: false,
      driftDomains: [],
      driftCount: 0,
      recommendedActions: []
    });
  });  it("generates a concise operations brief from normalized summaries", () => {
    const result = generateOperationsBrief({
      service: "payments",
      environment: "production",
      health: { healthStatus: "degraded", healthScore: 68 },
      incident: { relationship: "strong", correlationCount: 4 },
      deployment: { id: "deploy-9", status: "success" },
      slo: { budgetStatus: "within-budget", remainingPercent: 40 },
      drift: { driftDetected: true, driftCount: 2 },
      finops: { findingCount: 3, lowUtilizationWorkloadCount: 1 }
    });
    expect(result).toMatchObject({
      overallStatus: "attention",
      service: "payments",
      environment: "production"
    });
    expect(result.risks.join(" ")).toMatch(/drift/i);
    expect(result.nextActions.length).toBeGreaterThanOrEqual(3);
  });

  it("escalates an exhausted SLO to a critical operations brief", () => {
    const result = generateOperationsBrief({
      service: "api",
      environment: "production",
      health: { healthStatus: "healthy", healthScore: 95 },
      slo: { budgetStatus: "exhausted" }
    });
    expect(result.overallStatus).toBe("critical");
    expect(result.headline).toMatch(/immediate operational review/i);
  });
});
