import type { McpServer } from "@modelcontextprotocol/server";
import * as z from "zod/v4";

type HealthStatus = "healthy" | "degraded" | "critical";

function clamp(value: number, min: number, max: number): number {
  return Math.min(max, Math.max(min, value));
}

function finite(value: unknown, fallback = 0): number {
  const number = Number(value);
  return Number.isFinite(number) ? number : fallback;
}

function unique(values: string[]): string[] {
  return [...new Set(values.filter(Boolean))];
}

export function assessCloudHealth(input: {
  service: string;
  environment: "dev" | "staging" | "production";
  cloud?: { resourceCount: number; alarmStates?: Record<string, number> };
  metrics?: Array<{ name: string; status: "normal" | "degraded" | "critical"; detail: string }>;
  logs?: { errorCount: number; criticalCount?: number };
  kubernetes?: { podCount: number; unhealthyCount: number; restartingCount: number };
  cicd?: { status: "success" | "failed" | "running"; failedJobCount?: number };
  slo?: { budgetStatus: "within-budget" | "exhausted"; remainingPercent?: number };
  drift?: { driftDetected: boolean; missingExpected?: number; unexpectedLive?: number };
  finops?: { findingCount: number };
}) {
  const evidence: string[] = [];
  const actions: string[] = [];
  let penalty = 0;

  const metrics = input.metrics ?? [];
  const criticalMetrics = metrics.filter((item) => item.status === "critical");
  const degradedMetrics = metrics.filter((item) => item.status === "degraded");
  if (criticalMetrics.length) {
    penalty += Math.min(40, criticalMetrics.length * 20);
    evidence.push(`${criticalMetrics.length} critical metric signal(s).`);
    actions.push("Investigate critical service metrics and compare them with recent deployments.");
  }
  if (degradedMetrics.length) {
    penalty += Math.min(20, degradedMetrics.length * 8);
    evidence.push(`${degradedMetrics.length} degraded metric signal(s).`);
    actions.push("Review degraded metrics against the service baseline.");
  }

  const alarmStates = input.cloud?.alarmStates ?? {};
  const firingAlarms = Object.entries(alarmStates)
    .filter(([key]) => /alarm|firing|active/i.test(key))
    .reduce((sum, [, value]) => sum + Math.max(0, finite(value)), 0);
  if (firingAlarms > 0) {
    penalty += Math.min(20, firingAlarms * 5);
    evidence.push(`${firingAlarms} active cloud alarm signal(s).`);
    actions.push("Review active cloud alarms and confirm the affected resources.");
  }
  const errorCount = Math.max(0, finite(input.logs?.errorCount));
  const criticalLogCount = Math.max(0, finite(input.logs?.criticalCount));
  if (errorCount || criticalLogCount) {
    penalty += Math.min(15, errorCount * 2) + Math.min(15, criticalLogCount * 5);
    evidence.push(`${errorCount} error log signal(s) and ${criticalLogCount} critical log signal(s).`);
    actions.push("Correlate error logs with metrics, alerts and deployment timing.");
  }

  if (input.kubernetes) {
    const podCount = Math.max(0, finite(input.kubernetes.podCount));
    const unhealthy = Math.max(0, finite(input.kubernetes.unhealthyCount));
    const restarting = Math.max(0, finite(input.kubernetes.restartingCount));
    const unhealthyRatio = podCount > 0 ? unhealthy / podCount : unhealthy > 0 ? 1 : 0;
    if (unhealthy > 0) {
      penalty += Math.min(25, Math.round(unhealthyRatio * 25));
      evidence.push(`${unhealthy} of ${podCount} pod(s) are unhealthy.`);
      actions.push("Inspect unhealthy pods, readiness state and recent rollout events.");
    }
    if (restarting > 0) {
      penalty += Math.min(10, restarting * 2);
      evidence.push(`${restarting} pod(s) are repeatedly restarting.`);
    }
  }

  if (input.cicd?.status === "failed") {
    penalty += 15;
    evidence.push("The latest CI/CD signal is failed.");
    actions.push("Inspect the failed delivery run before another production change.");
  } else if (input.cicd?.status === "running") {
    penalty += 3;
    evidence.push("A delivery run is currently in progress.");
  }
  if (input.slo?.budgetStatus === "exhausted") {
    penalty += 25;
    evidence.push("The SLO error budget is exhausted.");
    actions.push("Treat further risky changes as gated until reliability recovers.");
  } else if (input.slo?.remainingPercent !== undefined && finite(input.slo.remainingPercent, 100) < 25) {
    penalty += 10;
    evidence.push("Less than 25% of the SLO error budget remains.");
    actions.push("Review release risk because the remaining error budget is low.");
  }

  if (input.drift?.driftDetected) {
    penalty += 10;
    evidence.push("Configuration drift is present.");
    actions.push("Review drift evidence and reconcile through the approved source of truth.");
  }

  const finopsFindings = Math.max(0, finite(input.finops?.findingCount));
  if (finopsFindings > 0) {
    evidence.push(`${finopsFindings} FinOps waste signal(s) are present.`);
    actions.push("Review waste findings separately from immediate service-health remediation.");
  }

  const healthScore = clamp(Math.round(100 - penalty), 0, 100);
  const healthStatus: HealthStatus = healthScore >= 85 ? "healthy" : healthScore >= 60 ? "degraded" : "critical";
  if (!evidence.length) evidence.push("No adverse evidence was supplied.");

  return {
    service: input.service,
    environment: input.environment,
    healthScore,
    healthStatus,
    evidence: unique(evidence),
    recommendedActions: unique(actions),
    signalSummary: {
      metricCount: metrics.length,
      criticalMetricCount: criticalMetrics.length,
      degradedMetricCount: degradedMetrics.length,
      firingAlarmCount: firingAlarms,
      errorLogCount: errorCount,
      criticalLogCount
    }
  };
}
export function correlateDeploymentIncident(input: {
  service: string;
  deployment: { id: string; deployedAt: number; status: "success" | "failed" | "running" };
  windowMinutes?: number;
  metrics?: Array<{ timestamp: number; name: string; status: "normal" | "degraded" | "critical"; detail: string }>;
  logs?: Array<{ timestamp: number; level: "info" | "warn" | "error" | "critical"; message: string }>;
  alerts?: Array<{ timestamp: number; source: string; status: "firing" | "resolved" | "unknown"; summary: string }>;
  kubernetes?: Array<{ timestamp: number; workload: string; status: "healthy" | "degraded" | "failed"; detail: string }>;
}) {
  const windowMinutes = clamp(Math.round(finite(input.windowMinutes, 30)), 1, 120);
  const start = finite(input.deployment.deployedAt);
  const end = start + windowMinutes * 60;
  const timeline: Array<{ timestamp: number; domain: string; severity: string; detail: string }> = [];

  for (const item of input.metrics ?? []) {
    if (item.timestamp >= start && item.timestamp <= end && item.status !== "normal") {
      timeline.push({ timestamp: item.timestamp, domain: "metrics", severity: item.status, detail: `${item.name}: ${item.detail}` });
    }
  }
  for (const item of input.logs ?? []) {
    if (item.timestamp >= start && item.timestamp <= end && ["error", "critical"].includes(item.level)) {
      timeline.push({ timestamp: item.timestamp, domain: "logs", severity: item.level, detail: item.message });
    }
  }
  for (const item of input.alerts ?? []) {
    if (item.timestamp >= start && item.timestamp <= end && item.status === "firing") {
      timeline.push({ timestamp: item.timestamp, domain: "alerts", severity: "firing", detail: `${item.source}: ${item.summary}` });
    }
  }
  for (const item of input.kubernetes ?? []) {
    if (item.timestamp >= start && item.timestamp <= end && item.status !== "healthy") {
      timeline.push({ timestamp: item.timestamp, domain: "kubernetes", severity: item.status, detail: `${item.workload}: ${item.detail}` });
    }
  }
  timeline.sort((a, b) => a.timestamp - b.timestamp);

  const domains = unique(timeline.map((item) => item.domain));
  const firstAdverseSeconds = timeline.length ? Math.max(0, timeline[0]!.timestamp - start) : null;
  const relationship = domains.length >= 3 && timeline.length >= 3
    ? "strong"
    : domains.length >= 2 && timeline.length >= 2
      ? "possible"
      : "insufficient-evidence";
  const reasons = timeline.length
    ? [`${timeline.length} adverse signal(s) appeared within ${windowMinutes} minutes after deployment.`,
       `${domains.length} evidence domain(s) contributed to the timeline.`]
    : ["No adverse signals were supplied inside the deployment correlation window."];

  return {
    service: input.service,
    deploymentId: input.deployment.id,
    deploymentStatus: input.deployment.status,
    windowMinutes,
    relationship,
    domainCount: domains.length,
    eventCount: timeline.length,
    firstAdverseSeconds,
    evidenceTimeline: timeline.slice(0, 200),
    reasons,
    nextChecks: unique([
      "Compare the same signals against the pre-deployment baseline.",
      "Confirm whether the affected workload version changed in this deployment.",
      "Review rollback or forward-fix options before assigning causation."
    ])
  };
}
export function assessObservabilityCoverage(input: {
  service: string;
  metrics: boolean;
  logs: boolean;
  alerts: boolean;
  dashboards: boolean;
  slo: boolean;
  tracing: boolean;
  deploymentMarkers: boolean;
  onCallRunbook: boolean;
}) {
  const controls = {
    metrics: input.metrics,
    logs: input.logs,
    alerts: input.alerts,
    dashboards: input.dashboards,
    slo: input.slo,
    tracing: input.tracing,
    deploymentMarkers: input.deploymentMarkers,
    onCallRunbook: input.onCallRunbook
  };
  const entries = Object.entries(controls);
  const covered = entries.filter(([, value]) => value).map(([key]) => key);
  const gaps = entries.filter(([, value]) => !value).map(([key]) => key);
  const coverageScore = Math.round((covered.length / entries.length) * 100);
  const maturity = coverageScore >= 88 ? "comprehensive" : coverageScore >= 75 ? "strong" : coverageScore >= 50 ? "partial" : "minimal";
  const guidance: Record<string, string> = {
    metrics: "Add service and dependency metrics with clear ownership.",
    logs: "Centralize structured logs with bounded retention and searchable fields.",
    alerts: "Add actionable alerts tied to user or service impact.",
    dashboards: "Provide a dashboard for golden signals and dependency health.",
    slo: "Define an SLO and error-budget policy for the service.",
    tracing: "Add distributed tracing for cross-service request paths.",
    deploymentMarkers: "Record deployment markers so regressions can be correlated with releases.",
    onCallRunbook: "Maintain an on-call runbook with first-response and rollback guidance."
  };
  return {
    service: input.service,
    coverageScore,
    maturity,
    coveredControls: covered,
    gaps,
    recommendedActions: gaps.map((gap) => guidance[gap]!)
  };
}
export function analyzeFinOpsWaste(input: {
  cloudFindings: Array<{ ruleId: string; resourceId: string; detail: string }>;
  terraformManagedResourceIds?: string[];
  workloadUtilization?: Array<{
    workload: string;
    cpuRequestMillicores?: number;
    cpuUsageMillicores?: number;
    memoryRequestMiB?: number;
    memoryUsageMiB?: number;
    replicas?: number;
  }>;
}) {
  const managed = new Set((input.terraformManagedResourceIds ?? []).map((value) => value.trim()).filter(Boolean));
  const cloudFindings = input.cloudFindings.slice(0, 500).map((finding) => ({
    ...finding,
    managedByTerraform: managed.has(finding.resourceId),
    remediationPath: managed.has(finding.resourceId)
      ? "Change or remove the resource through Terraform after owner validation."
      : "Validate ownership and lifecycle before removing or resizing the resource."
  }));

  const lowUtilizationWorkloads = (input.workloadUtilization ?? []).slice(0, 200).flatMap((item) => {
    const cpuRequest = finite(item.cpuRequestMillicores);
    const cpuUsage = finite(item.cpuUsageMillicores);
    const memoryRequest = finite(item.memoryRequestMiB);
    const memoryUsage = finite(item.memoryUsageMiB);
    const cpuRatio = cpuRequest > 0 ? cpuUsage / cpuRequest : null;
    const memoryRatio = memoryRequest > 0 ? memoryUsage / memoryRequest : null;
    const ratios = [cpuRatio, memoryRatio].filter((value): value is number => value !== null && Number.isFinite(value));
    const maxRatio = ratios.length ? Math.max(...ratios) : null;
    if (maxRatio === null || maxRatio >= 0.2) return [];
    return [{
      workload: item.workload,
      replicas: Math.max(0, Math.round(finite(item.replicas, 1))),
      maxRequestUtilizationPercent: Math.round(maxRatio * 10000) / 100,
      recommendation: "Review rightsizing with a longer utilization window before changing requests, limits or replicas."
    }];
  });

  return {
    cloudFindingCount: cloudFindings.length,
    terraformManagedFindingCount: cloudFindings.filter((item) => item.managedByTerraform).length,
    lowUtilizationWorkloadCount: lowUtilizationWorkloads.length,
    cloudFindings,
    lowUtilizationWorkloads,
    recommendedActions: unique([
      cloudFindings.length ? "Validate orphaned or unattached resources before deletion." : "",
      cloudFindings.some((item) => item.managedByTerraform) ? "Use Terraform as the source of truth for managed-resource cleanup." : "",
      lowUtilizationWorkloads.length ? "Use a representative utilization window before rightsizing workloads." : ""
    ])
  };
}
export function detectConfigurationDrift(input: {
  expectedCloudResourceIds?: string[];
  liveCloudResourceIds?: string[];
  expectedKubernetesWorkloads?: string[];
  liveKubernetesWorkloads?: string[];
}) {
  const expectedCloud = unique(input.expectedCloudResourceIds ?? []);
  const liveCloud = unique(input.liveCloudResourceIds ?? []);
  const expectedKube = unique(input.expectedKubernetesWorkloads ?? []);
  const liveKube = unique(input.liveKubernetesWorkloads ?? []);
  const liveCloudSet = new Set(liveCloud);
  const expectedCloudSet = new Set(expectedCloud);
  const liveKubeSet = new Set(liveKube);
  const expectedKubeSet = new Set(expectedKube);
  const missingCloud = expectedCloud.filter((id) => !liveCloudSet.has(id));
  const unexpectedCloud = liveCloud.filter((id) => !expectedCloudSet.has(id));
  const missingKubernetes = expectedKube.filter((id) => !liveKubeSet.has(id));
  const unexpectedKubernetes = liveKube.filter((id) => !expectedKubeSet.has(id));
  const driftDomains = unique([
    missingCloud.length || unexpectedCloud.length ? "cloud" : "",
    missingKubernetes.length || unexpectedKubernetes.length ? "kubernetes" : ""
  ]);
  return {
    driftDetected: driftDomains.length > 0,
    driftDomains,
    driftCount: missingCloud.length + unexpectedCloud.length + missingKubernetes.length + unexpectedKubernetes.length,
    cloud: { missingExpected: missingCloud, unexpectedLive: unexpectedCloud },
    kubernetes: { missingExpected: missingKubernetes, unexpectedLive: unexpectedKubernetes },
    recommendedActions: driftDomains.length
      ? ["Review drift against the approved source of truth before reconciliation.", "Prefer pull-requested configuration changes over direct runtime edits."]
      : []
  };
}
export function generateOperationsBrief(input: {
  service: string;
  environment: "dev" | "staging" | "production";
  health?: { healthStatus: HealthStatus; healthScore: number };
  incident?: { relationship: "strong" | "possible" | "insufficient-evidence"; correlationCount?: number };
  deployment?: { id?: string; status: "success" | "failed" | "running" };
  slo?: { budgetStatus: "within-budget" | "exhausted"; remainingPercent?: number };
  drift?: { driftDetected: boolean; driftCount?: number };
  finops?: { findingCount: number; lowUtilizationWorkloadCount?: number };
}) {
  const risks: string[] = [];
  const highlights: string[] = [];
  const nextActions: string[] = [];

  if (input.health) highlights.push(`Service health is ${input.health.healthStatus} at ${Math.round(input.health.healthScore)}/100.`);
  if (input.deployment) highlights.push(`Latest deployment ${input.deployment.id ?? ""} is ${input.deployment.status}.`.replace("  ", " "));
  if (input.incident?.relationship === "strong") {
    risks.push("Multiple post-deployment signal domains align strongly in time.");
    nextActions.push("Review the deployment correlation timeline before deciding on rollback.");
  } else if (input.incident?.relationship === "possible") {
    risks.push("Some post-deployment signals align, but evidence is not yet strong enough to assign causation.");
    nextActions.push("Collect missing telemetry and compare with the pre-deployment baseline.");
  }
  if (input.slo?.budgetStatus === "exhausted") {
    risks.push("The SLO error budget is exhausted.");
    nextActions.push("Gate risky releases until the reliability position is reviewed.");
  }
  if (input.drift?.driftDetected) {
    risks.push(`Configuration drift is present${input.drift.driftCount !== undefined ? ` in ${input.drift.driftCount} item(s)` : ""}.`);
    nextActions.push("Reconcile drift through the approved source of truth.");
  }
  if (finite(input.finops?.findingCount) > 0) {
    highlights.push(`${finite(input.finops?.findingCount)} FinOps waste signal(s) require review.`);
    nextActions.push("Validate ownership and utilization before cost-remediation changes.");
  }

  const overallStatus = input.health?.healthStatus === "critical" || input.slo?.budgetStatus === "exhausted"
    ? "critical"
    : input.health?.healthStatus === "degraded" || input.incident?.relationship === "strong" || input.drift?.driftDetected
      ? "attention"
      : "stable";
  const headline = overallStatus === "critical"
    ? `${input.service} requires immediate operational review.`
    : overallStatus === "attention"
      ? `${input.service} has operational signals that need attention.`
      : `${input.service} is stable based on the supplied evidence.`;

  return {
    service: input.service,
    environment: input.environment,
    overallStatus,
    headline,
    highlights: unique(highlights),
    risks: unique(risks),
    nextActions: unique(nextActions)
  };
}

function result(payload: Record<string, unknown>) {
  return {
    content: [{ type: "text" as const, text: JSON.stringify(payload, null, 2) }],
    structuredContent: payload
  };
}

const intelligenceAnnotations = {
  readOnlyHint: true,
  destructiveHint: false,
  idempotentHint: true,
  openWorldHint: false
} as const;

export function registerOperationsIntelligenceTools(server: McpServer) {
  server.registerTool(
    "assess_cloud_health",
    {
      title: "Assess Cloud Health",
      description: "Combine supplied cloud alarms, service metrics, logs, Kubernetes health, CI/CD, SLO, drift and FinOps evidence into one deterministic service-health assessment without changing any external system.",
      annotations: intelligenceAnnotations,
      inputSchema: z.object({
        service: z.string().min(2),
        environment: z.enum(["dev", "staging", "production"]),
        cloud: z.object({ resourceCount: z.number(), alarmStates: z.record(z.string(), z.number()).optional() }).optional(),
        metrics: z.array(z.object({ name: z.string(), status: z.enum(["normal", "degraded", "critical"]), detail: z.string() })).max(100).optional(),
        logs: z.object({ errorCount: z.number(), criticalCount: z.number().optional() }).optional(),        kubernetes: z.object({ podCount: z.number(), unhealthyCount: z.number(), restartingCount: z.number() }).optional(),
        cicd: z.object({ status: z.enum(["success", "failed", "running"]), failedJobCount: z.number().optional() }).optional(),
        slo: z.object({ budgetStatus: z.enum(["within-budget", "exhausted"]), remainingPercent: z.number().optional() }).optional(),
        drift: z.object({ driftDetected: z.boolean(), missingExpected: z.number().optional(), unexpectedLive: z.number().optional() }).optional(),
        finops: z.object({ findingCount: z.number() }).optional()
      }),
      outputSchema: z.object({
        service: z.string(),
        environment: z.string(),
        healthScore: z.number(),
        healthStatus: z.enum(["healthy", "degraded", "critical"]),
        evidence: z.array(z.string()),
        recommendedActions: z.array(z.string()),
        signalSummary: z.object({
          metricCount: z.number(),
          criticalMetricCount: z.number(),
          degradedMetricCount: z.number(),
          firingAlarmCount: z.number(),
          errorLogCount: z.number(),
          criticalLogCount: z.number()
        })
      })
    },
    async (input) => result(assessCloudHealth(input))
  );

  server.registerTool(
    "correlate_deployment_incident",
    {
      title: "Correlate Deployment Incident",
      description: "Build a bounded post-deployment evidence timeline across metrics, logs, alerts and Kubernetes signals, then report whether timing shows strong, possible or insufficient evidence of a deployment relationship without claiming root cause.",
      annotations: intelligenceAnnotations,      inputSchema: z.object({
        service: z.string().min(2),
        deployment: z.object({ id: z.string().min(1), deployedAt: z.number(), status: z.enum(["success", "failed", "running"]) }),
        windowMinutes: z.number().min(1).max(120).optional(),
        metrics: z.array(z.object({ timestamp: z.number(), name: z.string(), status: z.enum(["normal", "degraded", "critical"]), detail: z.string() })).max(200).optional(),
        logs: z.array(z.object({ timestamp: z.number(), level: z.enum(["info", "warn", "error", "critical"]), message: z.string() })).max(200).optional(),
        alerts: z.array(z.object({ timestamp: z.number(), source: z.string(), status: z.enum(["firing", "resolved", "unknown"]), summary: z.string() })).max(200).optional(),
        kubernetes: z.array(z.object({ timestamp: z.number(), workload: z.string(), status: z.enum(["healthy", "degraded", "failed"]), detail: z.string() })).max(200).optional()
      }),
      outputSchema: z.object({
        service: z.string(),
        deploymentId: z.string(),
        deploymentStatus: z.string(),
        windowMinutes: z.number(),
        relationship: z.enum(["strong", "possible", "insufficient-evidence"]),
        domainCount: z.number(),
        eventCount: z.number(),
        firstAdverseSeconds: z.number().nullable(),
        evidenceTimeline: z.array(z.object({ timestamp: z.number(), domain: z.string(), severity: z.string(), detail: z.string() })),
        reasons: z.array(z.string()),
        nextChecks: z.array(z.string())
      })
    },
    async (input) => result(correlateDeploymentIncident(input))
  );

  server.registerTool(
    "assess_observability_coverage",
    {
      title: "Assess Observability Coverage",
      description: "Assess whether a service has the core observability controls needed for production operations, including metrics, logs, alerts, dashboards, SLOs, tracing, deployment markers and an on-call runbook.",
      annotations: intelligenceAnnotations,      inputSchema: z.object({
        service: z.string().min(2),
        metrics: z.boolean(),
        logs: z.boolean(),
        alerts: z.boolean(),
        dashboards: z.boolean(),
        slo: z.boolean(),
        tracing: z.boolean(),
        deploymentMarkers: z.boolean(),
        onCallRunbook: z.boolean()
      }),
      outputSchema: z.object({
        service: z.string(),
        coverageScore: z.number(),
        maturity: z.enum(["comprehensive", "strong", "partial", "minimal"]),
        coveredControls: z.array(z.string()),
        gaps: z.array(z.string()),
        recommendedActions: z.array(z.string())
      })
    },
    async (input) => result(assessObservabilityCoverage(input))
  );

  server.registerTool(
    "analyze_finops_waste",
    {
      title: "Analyze FinOps Waste",
      description: "Correlate bounded cloud waste findings with Terraform ownership and caller-supplied Kubernetes utilization evidence so cost-remediation work can follow the correct source of truth without deleting or resizing resources.",
      annotations: intelligenceAnnotations,
      inputSchema: z.object({
        cloudFindings: z.array(z.object({ ruleId: z.string(), resourceId: z.string(), detail: z.string() })).max(500),
        terraformManagedResourceIds: z.array(z.string()).max(1000).optional(),
        workloadUtilization: z.array(z.object({
          workload: z.string(),
          cpuRequestMillicores: z.number().optional(),
          cpuUsageMillicores: z.number().optional(),
          memoryRequestMiB: z.number().optional(),          memoryUsageMiB: z.number().optional(),
          replicas: z.number().optional()
        })).max(200).optional()
      }),
      outputSchema: z.object({
        cloudFindingCount: z.number(),
        terraformManagedFindingCount: z.number(),
        lowUtilizationWorkloadCount: z.number(),
        cloudFindings: z.array(z.object({
          ruleId: z.string(),
          resourceId: z.string(),
          detail: z.string(),
          managedByTerraform: z.boolean(),
          remediationPath: z.string()
        })),
        lowUtilizationWorkloads: z.array(z.object({
          workload: z.string(),
          replicas: z.number(),
          maxRequestUtilizationPercent: z.number(),
          recommendation: z.string()
        })),
        recommendedActions: z.array(z.string())
      })
    },
    async (input) => result(analyzeFinOpsWaste(input))
  );

  server.registerTool(
    "detect_configuration_drift",
    {
      title: "Detect Configuration Drift",
      description: "Compare expected cloud resource identifiers and Kubernetes workloads with supplied live identifiers to detect cross-runtime configuration drift while remaining analysis-only and leaving reconciliation to approved workflows.",
      annotations: intelligenceAnnotations,
      inputSchema: z.object({
        expectedCloudResourceIds: z.array(z.string()).max(1000).optional(),
        liveCloudResourceIds: z.array(z.string()).max(1000).optional(),
        expectedKubernetesWorkloads: z.array(z.string()).max(1000).optional(),
        liveKubernetesWorkloads: z.array(z.string()).max(1000).optional()
      }),      outputSchema: z.object({
        driftDetected: z.boolean(),
        driftDomains: z.array(z.string()),
        driftCount: z.number(),
        cloud: z.object({ missingExpected: z.array(z.string()), unexpectedLive: z.array(z.string()) }),
        kubernetes: z.object({ missingExpected: z.array(z.string()), unexpectedLive: z.array(z.string()) }),
        recommendedActions: z.array(z.string())
      })
    },
    async (input) => result(detectConfigurationDrift(input))
  );

  server.registerTool(
    "generate_operations_brief",
    {
      title: "Generate Operations Brief",
      description: "Generate one concise operational brief from supplied health, incident, deployment, SLO, drift and FinOps summaries so an operator can see current status, risks and next actions without querying or mutating external systems.",
      annotations: intelligenceAnnotations,
      inputSchema: z.object({
        service: z.string().min(2),
        environment: z.enum(["dev", "staging", "production"]),
        health: z.object({ healthStatus: z.enum(["healthy", "degraded", "critical"]), healthScore: z.number() }).optional(),
        incident: z.object({ relationship: z.enum(["strong", "possible", "insufficient-evidence"]), correlationCount: z.number().optional() }).optional(),
        deployment: z.object({ id: z.string().optional(), status: z.enum(["success", "failed", "running"]) }).optional(),
        slo: z.object({ budgetStatus: z.enum(["within-budget", "exhausted"]), remainingPercent: z.number().optional() }).optional(),
        drift: z.object({ driftDetected: z.boolean(), driftCount: z.number().optional() }).optional(),
        finops: z.object({ findingCount: z.number(), lowUtilizationWorkloadCount: z.number().optional() }).optional()
      }),
      outputSchema: z.object({
        service: z.string(),
        environment: z.string(),
        overallStatus: z.enum(["stable", "attention", "critical"]),
        headline: z.string(),
        highlights: z.array(z.string()),
        risks: z.array(z.string()),
        nextActions: z.array(z.string())
      })
    },    async (input) => result(generateOperationsBrief(input))
  );
}
