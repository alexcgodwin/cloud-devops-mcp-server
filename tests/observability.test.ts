import { Client, InMemoryTransport } from "@modelcontextprotocol/client";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { createServer } from "../src/index.js";
import {
  cloudWatchLogsQuery,
  correlateIncidentSignals,
  githubActionsFailureDiagnosis,
  grafanaAlertSummary,
  kubernetesHealthSummary,
  prometheusQuery,
  type HttpFetcher
} from "../src/observability.js";
import type { CommandRunner } from "../src/infrastructure.js";

function sequenceRunner(results: Array<{ stdout?: string; stderr?: string; exitCode?: number }>) {
  const calls: Array<{ executable: string; args: string[] }> = [];
  const runner: CommandRunner = async (executable, args) => {
    calls.push({ executable, args });
    const next = results.shift() ?? {};
    return {
      stdout: next.stdout ?? "",
      stderr: next.stderr ?? "",
      exitCode: next.exitCode ?? 0
    };
  };
  return { runner, calls };
}

function jsonResult(payload: unknown, status = 200) {
  return {
    ok: status >= 200 && status < 300,
    status,
    async json() {
      return payload;
    },
    async text() {
      return JSON.stringify(payload);
    }
  };
}

function textResult(payload: string, status = 200) {
  return {
    ok: status >= 200 && status < 300,
    status,
    async json() {
      return JSON.parse(payload);
    },
    async text() {
      return payload;
    }
  };
}

describe("production observability intelligence", () => {
  beforeEach(() => {
    process.env.CLOUD_DEVOPS_MCP_OBSERVABILITY_ENABLED = "true";
    process.env.CLOUD_DEVOPS_MCP_ALLOWED_PROMETHEUS_URLS = "https://prom.example.com";
    process.env.CLOUD_DEVOPS_MCP_ALLOWED_GRAFANA_URLS = "https://grafana.example.com";
    process.env.CLOUD_DEVOPS_MCP_ALLOWED_AWS_ACCOUNTS = "123456789012";
    process.env.CLOUD_DEVOPS_MCP_ALLOWED_AWS_REGIONS = "ca-central-1";
    process.env.CLOUD_DEVOPS_MCP_ALLOWED_AWS_PROFILES = "dev";
    process.env.CLOUD_DEVOPS_MCP_ALLOWED_CLOUDWATCH_LOG_GROUPS = "/aws/eks/prod";
    process.env.CLOUD_DEVOPS_MCP_ALLOWED_KUBE_CONTEXTS = "prod-cluster";
    process.env.CLOUD_DEVOPS_MCP_ALLOWED_KUBE_NAMESPACES = "platform";
    process.env.CLOUD_DEVOPS_MCP_ALLOWED_GITHUB_REPOSITORIES = "alexcgodwin/cloud-devops-mcp-server";
    process.env.CLOUD_DEVOPS_MCP_GITHUB_TOKEN = "test-token-not-real";
  });

  afterEach(() => {
    for (const key of Object.keys(process.env)) {
      if (key.startsWith("CLOUD_DEVOPS_MCP_")) delete process.env[key];
    }
  });

  it("queries an allowlisted Prometheus endpoint and returns bounded series summaries", async () => {
    let requested = "";
    const fetcher: HttpFetcher = async (url) => {
      requested = url;
      return jsonResult({
        status: "success",
        data: {
          resultType: "vector",
          result: [
            { metric: { job: "api", instance: "1" }, value: [1700000000, "0.42"] }
          ]
        }
      });
    };
    const result = await prometheusQuery({
      baseUrl: "https://prom.example.com",
      query: "rate(http_requests_total[5m])"
    }, fetcher);
    expect(result).toMatchObject({
      mode: "instant",
      resultType: "vector",
      seriesCount: 1
    });
    expect(result.series[0]).toMatchObject({ sampleCount: 1, latestValue: "0.42" });
    expect(requested).toContain("/api/v1/query?");
  });

  it("summarizes Grafana alert rules and active alerts", async () => {
    const responses = [
      jsonResult([
        { uid: "rule-1", title: "High latency", folderUID: "prod", ruleGroup: "api", condition: "C", isPaused: false },
        { uid: "rule-2", title: "Error rate", folderUID: "prod", ruleGroup: "api", condition: "B", isPaused: true }
      ]),
      jsonResult([
        { labels: { alertname: "High latency" }, annotations: { summary: "p95 high" }, status: { state: "active" } }
      ])
    ];
    const fetcher: HttpFetcher = async () => responses.shift()!;
    const result = await grafanaAlertSummary({ baseUrl: "https://grafana.example.com" }, fetcher);
    expect(result).toMatchObject({
      ruleCount: 2,
      pausedCount: 1,
      activeAlertsAvailable: true,
      activeAlertCount: 1
    });
  });

  it("runs a bounded CloudWatch Logs Insights query against an allowlisted log group", async () => {
    const runner = sequenceRunner([
      { stdout: JSON.stringify({ Account: "123456789012" }) },
      { stdout: JSON.stringify({ queryId: "query-123" }) },
      { stdout: JSON.stringify({
        status: "Complete",
        results: [
          [{ field: "@timestamp", value: "2026-10-02T01:00:00Z" }, { field: "@message", value: "ERROR request failed" }]
        ],
        statistics: { recordsMatched: 1, recordsScanned: 20, bytesScanned: 2048 }
      }) }
    ]);
    const result = await cloudWatchLogsQuery({
      region: "ca-central-1",
      profile: "dev",
      logGroup: "/aws/eks/prod",
      queryString: "fields @timestamp, @message | filter @message like /ERROR/ | limit 20",
      startTime: 1700000000,
      endTime: 1700003600,
      limit: 20
    }, runner.runner);
    expect(result).toMatchObject({
      status: "Complete",
      resultCount: 1,
      statistics: { recordsMatched: 1, recordsScanned: 20, bytesScanned: 2048 }
    });
    expect(runner.calls.some((call) => call.args.includes("start-query"))).toBe(true);
    expect(runner.calls.some((call) => call.args.includes("get-query-results"))).toBe(true);
  });

  it("summarizes Kubernetes pod health without exposing Secrets or mutation commands", async () => {
    const runner = sequenceRunner([{
      stdout: JSON.stringify({
        items: [
          {
            metadata: { name: "api-1" },
            status: {
              phase: "Running",
              containerStatuses: [{ ready: true, restartCount: 0, state: { running: {} } }]
            }
          },
          {
            metadata: { name: "api-2" },
            status: {
              phase: "Running",
              containerStatuses: [{ ready: false, restartCount: 4, state: { waiting: { reason: "CrashLoopBackOff" } } }]
            }
          }
        ]
      })
    }]);
    const result = await kubernetesHealthSummary({
      context: "prod-cluster",
      namespace: "platform",
      labelSelector: "app=api"
    }, runner.runner);
    expect(result).toMatchObject({
      podCount: 2,
      runningCount: 2,
      readyCount: 1,
      restartingCount: 1,
      unhealthyCount: 1
    });
    expect(result.unhealthyPods[0]).toMatchObject({
      name: "api-2",
      reason: "CrashLoopBackOff"
    });
    expect(runner.calls[0].args).toEqual(expect.arrayContaining(["get", "pods", "-o", "json"]));
    expect(runner.calls[0].args).not.toEqual(expect.arrayContaining(["apply", "delete", "exec"]));
  });

  it("diagnoses failed GitHub Actions jobs from job metadata and bounded logs", async () => {
    const fetcher: HttpFetcher = async (url) => {
      if (url.includes("/jobs?")) {
        return jsonResult({
          jobs: [
            {
              id: 101,
              name: "test",
              conclusion: "failure",
              steps: [
                { name: "Install", conclusion: "success" },
                { name: "Run tests", conclusion: "failure" }
              ]
            },
            { id: 102, name: "build", conclusion: "success", steps: [] }
          ]
        });
      }
      return textResult("npm ERR! Test failed\nAssertionError: expected 1 to equal 2");
    };
    const result = await githubActionsFailureDiagnosis({
      repository: "alexcgodwin/cloud-devops-mcp-server",
      runId: 12345
    }, fetcher);
    expect(result).toMatchObject({
      totalJobCount: 2,
      failedJobCount: 1,
      diagnosedJobCount: 1,
      categoryCounts: { tests: 1 }
    });
    expect(result.failedJobs[0]).toMatchObject({
      name: "test",
      category: "tests",
      failedSteps: ["Run tests"]
    });
  });

  it("correlates metrics, logs, alerts, Kubernetes and CI/CD signals", () => {
    const result = correlateIncidentSignals({
      service: "payments-api",
      metrics: [{ name: "http_5xx_rate", status: "critical", detail: "5xx rate increased to 12%" }],
      logs: [{ level: "error", message: "database connection timeout" }],
      alerts: [{ source: "grafana", status: "firing", summary: "High 5xx rate" }],
      kubernetes: [{ workload: "payments-api", status: "degraded", detail: "3 pods restarting" }],
      cicd: [{ pipeline: "deploy-prod", status: "failed", detail: "rollout failed" }]
    });
    expect(result.domainCount).toBe(5);
    expect(result.correlationCount).toBeGreaterThanOrEqual(4);
    expect(result.incidentConfidence).toBe("high");
    expect(result.correlations.map((item) => item.ruleId)).toEqual(expect.arrayContaining([
      "OBS_METRIC_LOG_DEGRADATION",
      "OBS_K8S_LOG_RUNTIME_INSTABILITY",
      "OBS_ALERT_METRIC_CONFIRMATION"
    ]));
  });

  it("fails closed for unapproved observability scopes", async () => {
    const neverFetch: HttpFetcher = async () => jsonResult({});
    const neverRun: CommandRunner = async () => ({ stdout: "{}", stderr: "", exitCode: 0 });

    await expect(prometheusQuery({
      baseUrl: "https://evil.example.com",
      query: "up"
    }, neverFetch)).rejects.toThrow(/not in CLOUD_DEVOPS_MCP_ALLOWED_PROMETHEUS_URLS/i);

    await expect(cloudWatchLogsQuery({
      region: "ca-central-1",
      logGroup: "/aws/eks/unapproved",
      queryString: "fields @message",
      startTime: 1700000000,
      endTime: 1700000100
    }, neverRun)).rejects.toThrow(/log group is not/i);

    await expect(kubernetesHealthSummary({
      context: "other-cluster",
      namespace: "platform"
    }, neverRun)).rejects.toThrow(/context is not/i);

    await expect(githubActionsFailureDiagnosis({
      repository: "someone/else",
      runId: 1
    }, neverFetch)).rejects.toThrow(/repository is not/i);

    process.env.CLOUD_DEVOPS_MCP_OBSERVABILITY_ENABLED = "false";
    await expect(prometheusQuery({
      baseUrl: "https://prom.example.com",
      query: "up"
    }, neverFetch)).rejects.toThrow(/disabled/i);
  });

  it("exposes twelve observability and operations-intelligence tools only when the observability gate is enabled", async () => {
    const server = createServer();
    const client = new Client({ name: "observability-test", version: "1.0.0" });
    const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
    await server.connect(serverTransport);
    await client.connect(clientTransport);
    try {
      const { tools } = await client.listTools();
      expect(tools).toHaveLength(24);
      expect(tools.map((tool) => tool.name)).toEqual(expect.arrayContaining([
        "prometheus_query",
        "grafana_alert_summary",
        "cloudwatch_logs_query",
        "kubernetes_health_summary",
        "github_actions_failure_diagnosis",
        "correlate_incident_signals",
        "assess_cloud_health",
        "correlate_deployment_incident",
        "assess_observability_coverage",
        "analyze_finops_waste",
        "detect_configuration_drift",
        "generate_operations_brief"
      ]));
      const observabilityTools = tools.filter((tool) => [
        "prometheus_query",
        "grafana_alert_summary",
        "cloudwatch_logs_query",
        "kubernetes_health_summary",
        "github_actions_failure_diagnosis",
        "correlate_incident_signals",
        "assess_cloud_health",
        "correlate_deployment_incident",
        "assess_observability_coverage",
        "analyze_finops_waste",
        "detect_configuration_drift",
        "generate_operations_brief"
      ].includes(tool.name));
      expect(observabilityTools.every((tool) => tool.annotations?.readOnlyHint === true)).toBe(true);
      expect(observabilityTools.every((tool) => tool.annotations?.destructiveHint === false)).toBe(true);
    } finally {
      await client.close();
      await server.close();
    }
  });

  it("covers Prometheus range queries and validation boundaries", async () => {
    const fetcher: HttpFetcher = async (url) => {
      expect(url).toContain("/api/v1/query_range?");
      return jsonResult({
        status: "success",
        data: {
          resultType: "matrix",
          result: [
            { metric: { job: "api" }, values: [[1700000000, "1"], [1700000060, "2"]] },
            { metric: {}, values: [] }
          ]
        }
      });
    };
    const result = await prometheusQuery({
      baseUrl: "https://prom.example.com/",
      query: "up",
      startTime: 1700000000,
      endTime: 1700003600,
      stepSeconds: 60
    }, fetcher);
    expect(result.mode).toBe("range");
    expect(result.series[0]).toMatchObject({ sampleCount: 2, latestValue: "2" });
    expect(result.series[1]).toMatchObject({ sampleCount: 0, latestTimestamp: null, latestValue: "" });

    await expect(prometheusQuery({
      baseUrl: "https://prom.example.com",
      query: "up",
      startTime: 1700000000
    }, fetcher)).rejects.toThrow(/provided together/i);
    await expect(prometheusQuery({
      baseUrl: "https://prom.example.com",
      query: "up",
      startTime: 1700000000,
      endTime: 1700030000
    }, fetcher)).rejects.toThrow(/range must be/i);
    await expect(prometheusQuery({
      baseUrl: "https://prom.example.com",
      query: "up",
      startTime: 1700000000,
      endTime: 1700000100,
      stepSeconds: 1
    }, fetcher)).rejects.toThrow(/stepSeconds/i);
  });

  it("covers degraded Grafana, CloudWatch polling and pod states", async () => {
    const grafanaResponses = [jsonResult({}), jsonResult({}, 503)];
    const grafana = await grafanaAlertSummary(
      { baseUrl: "https://grafana.example.com" },
      async () => grafanaResponses.shift()!
    );
    expect(grafana).toMatchObject({
      ruleCount: 0,
      activeAlertsAvailable: false,
      activeAlertCount: 0
    });

    const cloud = sequenceRunner([
      { stdout: JSON.stringify({ Account: "123456789012" }) },
      { stdout: JSON.stringify({ queryId: "q2" }) },
      { stdout: JSON.stringify({ status: "Running" }) },
      { stdout: JSON.stringify({ status: "Complete", results: [], statistics: {} }) }
    ]);
    const cloudResult = await cloudWatchLogsQuery({
      region: "ca-central-1",
      logGroup: "/aws/eks/prod",
      queryString: "fields @message",
      startTime: 1700000000,
      endTime: 1700000100
    }, cloud.runner);
    expect(cloudResult).toMatchObject({
      status: "Complete",
      resultCount: 0,
      statistics: { recordsMatched: 0, recordsScanned: 0, bytesScanned: 0 }
    });

    const kube = sequenceRunner([{
      stdout: JSON.stringify({
        items: [
          { metadata: { name: "pending" }, status: { phase: "Pending" } },
          { metadata: { name: "failed" }, status: { phase: "Failed", containerStatuses: [
            { ready: false, restartCount: 1, state: { terminated: { reason: "Error" } } }
          ] } }
        ]
      })
    }]);
    const health = await kubernetesHealthSummary({
      context: "prod-cluster",
      namespace: "platform"
    }, kube.runner);
    expect(health).toMatchObject({
      podCount: 2,
      pendingCount: 1,
      failedCount: 1,
      readyCount: 0,
      unhealthyCount: 2
    });
    expect(health.unhealthyPods.map((pod) => pod.reason)).toContain("Error");
  });

  it("covers GitHub failure categories, missing logs and credential validation", async () => {
    const jobs = [
      { id: 1, name: "permissions", conclusion: "failure", steps: [{ name: "deploy", conclusion: "failure" }] },
      { id: 2, name: "terraform plan", conclusion: "timed_out", steps: [] },
      { id: 3, name: "kubectl deploy", conclusion: "cancelled", steps: [] },
      { id: 4, name: "docker build", conclusion: "startup_failure", steps: [] },
      { id: 5, name: "network", conclusion: "stale", steps: [] }
    ];
    const fetcher: HttpFetcher = async (url) => {
      if (url.includes("/jobs?")) return jsonResult({ jobs });
      const id = Number(url.match(/jobs\/(\d+)\//)?.[1] ?? 0);
      if (id === 1) return textResult("Error: Resource not accessible by integration");
      if (id === 2) return textResult("terraform plan timed out");
      if (id === 3) return textResult("kubectl rollout failed");
      if (id === 4) return textResult("docker build failed to solve");
      return textResult("could not resolve host", 500);
    };
    const result = await githubActionsFailureDiagnosis({
      repository: "alexcgodwin/cloud-devops-mcp-server",
      runId: 99
    }, fetcher);
    expect(result.diagnosedJobCount).toBe(5);
    expect(result.categoryCounts).toMatchObject({
      authorization: 1,
      timeout: 1,
      kubernetes: 1,
      "container-build": 1,
      unclassified: 1
    });

    delete process.env.CLOUD_DEVOPS_MCP_GITHUB_TOKEN;
    await expect(githubActionsFailureDiagnosis({
      repository: "alexcgodwin/cloud-devops-mcp-server",
      runId: 1
    }, fetcher)).rejects.toThrow(/GITHUB_TOKEN is required/i);
  });

  it("returns low or medium incident confidence when evidence is sparse", () => {
    const low = correlateIncidentSignals({ service: "api" });
    expect(low).toMatchObject({
      domainCount: 0,
      signalCount: 0,
      correlationCount: 0,
      incidentConfidence: "low"
    });
    expect(low.recommendedNextChecks).toHaveLength(5);

    const medium = correlateIncidentSignals({
      service: "api",
      metrics: [{ name: "errors", status: "degraded", detail: "errors rising" }],
      logs: [{ level: "error", message: "request failed" }]
    });
    expect(medium).toMatchObject({
      domainCount: 2,
      correlationCount: 1,
      incidentConfidence: "medium"
    });
  });
});
