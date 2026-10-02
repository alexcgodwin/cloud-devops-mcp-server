import { Client, InMemoryTransport } from "@modelcontextprotocol/client";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { createServer } from "../src/index.js";
import {
  analyzeSloBurnRate,
  assessTracingCoverage,
  correlateTraceSloIncident,
  traceDependencyMap,
  traceSearch,
  traceSummary,
  type TraceHttpFetcher
} from "../src/tracing.js";

function jsonResult(payload: any, status = 200) {
  return {
    ok: status >= 200 && status < 300,
    status,
    async json() { return payload; },
    async text() { return JSON.stringify(payload); }
  };
}

describe("distributed tracing and SLO intelligence", () => {
  beforeEach(() => {
    process.env.CLOUD_DEVOPS_MCP_TRACING_ENABLED = "true";
    process.env.CLOUD_DEVOPS_MCP_ALLOWED_TEMPO_URLS = "https://tempo.example.com";
    process.env.CLOUD_DEVOPS_MCP_ALLOWED_JAEGER_URLS = "https://jaeger.example.com";
    process.env.CLOUD_DEVOPS_MCP_TEMPO_BEARER_TOKEN = "tempo-test-token";
    process.env.CLOUD_DEVOPS_MCP_JAEGER_BEARER_TOKEN = "jaeger-test-token";
  });

  afterEach(() => {
    for (const key of Object.keys(process.env)) {
      if (key.startsWith("CLOUD_DEVOPS_MCP_")) delete process.env[key];
    }
  });

  it("searches Tempo with bounded TraceQL and normalizes summaries", async () => {
    let requested = "";
    let authorization = "";
    const fetcher: TraceHttpFetcher = async (url, init) => {
      requested = url;
      authorization = init?.headers?.Authorization ?? "";
      return jsonResult({
        traces: [{
          traceID: "0123456789abcdef0123456789abcdef",
          rootServiceName: "payments",
          rootTraceName: "POST /charge",
          startTimeUnixNano: "1700000000000000000",
          durationMs: 321.4,
          spanCount: 8
        }]
      });
    };
    const result = await traceSearch({
      backend: "tempo",
      baseUrl: "https://tempo.example.com",
      service: "payments",
      traceQl: '{ resource.service.name = "payments" }',
      startTime: 1700000000,
      endTime: 1700003600,
      limit: 20
    }, fetcher);
    expect(result).toMatchObject({ backend: "tempo", service: "payments", resultCount: 1 });
    expect(result.traces[0]).toMatchObject({ rootServiceName: "payments", spanCount: 8 });
    expect(requested).toContain("/api/search?");
    expect(requested).toContain("q=");
    expect(authorization).toBe("Bearer tempo-test-token");
  });
  it("searches the stable Jaeger v3 trace-summary API", async () => {
    let requested = "";
    const fetcher: TraceHttpFetcher = async (url) => {
      requested = url;
      return jsonResult({
        result: {
          traceSummaries: [{
            traceId: "0123456789abcdef",
            serviceName: "orders",
            operationName: "GET /orders",
            startTimeUnixNano: "1700000000000000000",
            durationMs: 90,
            spanCount: 4
          }]
        }
      });
    };
    const result = await traceSearch({
      backend: "jaeger",
      baseUrl: "https://jaeger.example.com",
      service: "orders",
      operation: "GET /orders",
      startTime: 1700000000,
      endTime: 1700001800,
      limit: 10
    }, fetcher);
    expect(result).toMatchObject({ backend: "jaeger", service: "orders", operation: "GET /orders", resultCount: 1 });
    expect(requested).toContain("/api/v3/trace-summaries?");
    expect(requested).toContain("query.serviceName=orders");
    expect(requested).toContain("query.operationName=GET+%2Forders");
  });

  it("retrieves and summarizes OpenTelemetry-style Tempo trace data", async () => {
    const traceId = "0123456789abcdef0123456789abcdef";
    const fetcher: TraceHttpFetcher = async (url) => {
      expect(url).toContain(`/api/v2/traces/${traceId}`);
      return jsonResult({
        resourceSpans: [{
          resource: { attributes: [{ key: "service.name", value: { stringValue: "api" } }] },
          scopeSpans: [{
            spans: [
              {
                traceId,
                spanId: "1111111111111111",
                name: "GET /checkout",
                startTimeUnixNano: "1700000000000000000",
                endTimeUnixNano: "1700000001200000000",
                status: { code: "STATUS_CODE_OK" }
              },
              {
                traceId,
                spanId: "2222222222222222",
                parentSpanId: "1111111111111111",
                name: "db query",
                startTimeUnixNano: "1700000000100000000",
                endTimeUnixNano: "1700000001000000000",
                status: { code: "STATUS_CODE_ERROR" }
              }
            ]
          }]
        }]
      });
    };
    const result = await traceSummary({
      backend: "tempo",
      baseUrl: "https://tempo.example.com",
      traceId
    }, fetcher);
    expect(result).toMatchObject({
      traceId,
      spanCount: 2,
      serviceCount: 1,
      errorSpanCount: 1,
      rootSpanCount: 1,
      durationMs: 1200
    });
    expect(result.slowestSpans[0]).toMatchObject({ name: "GET /checkout", durationMs: 1200 });
  });
  it("retrieves Jaeger v3 trace data from the result envelope", async () => {
    const traceId = "0123456789abcdef";
    const fetcher: TraceHttpFetcher = async (url) => {
      expect(url).toContain(`/api/v3/traces/${traceId}`);
      expect(url).toContain("startTime=");
      return jsonResult({
        result: {
          resourceSpans: [{
            resource: { attributes: [{ key: "service.name", value: { stringValue: "worker" } }] },
            scopeSpans: [{
              spans: [{
                traceId,
                spanId: "aaaaaaaaaaaaaaaa",
                name: "consume",
                startTimeUnixNano: "1700000000000000000",
                endTimeUnixNano: "1700000000250000000",
                attributes: [{ key: "http.status_code", value: { intValue: "500" } }]
              }]
            }]
          }]
        }
      });
    };
    const result = await traceSummary({
      backend: "jaeger",
      baseUrl: "https://jaeger.example.com",
      traceId,
      startTime: 1700000000,
      endTime: 1700000100
    }, fetcher);
    expect(result).toMatchObject({
      backend: "jaeger",
      spanCount: 1,
      errorSpanCount: 1,
      durationMs: 250
    });
  });

  it("builds service dependency edges from parent-child spans", () => {
    const result = traceDependencyMap({
      service: "checkout",
      spans: [
        { spanId: "1", service: "frontend", name: "request", durationMs: 1000 },
        { spanId: "2", parentSpanId: "1", service: "checkout", name: "checkout", durationMs: 800 },
        { spanId: "3", parentSpanId: "2", service: "payments", name: "charge", durationMs: 300, error: true },
        { spanId: "4", parentSpanId: "2", service: "payments", name: "charge", durationMs: 200 }
      ]
    });
    expect(result).toMatchObject({ spanCount: 4, serviceCount: 3, edgeCount: 2 });
    expect(result.edges).toEqual(expect.arrayContaining([
      expect.objectContaining({ caller: "checkout", callee: "payments", callCount: 2, errorCount: 1, errorRatePercent: 50, averageDurationMs: 250 })
    ]));
  });
  it("assesses distributed tracing coverage from explicit controls", () => {
    const result = assessTracingCoverage({
      service: "payments",
      serverSpans: true,
      clientSpans: true,
      databaseSpans: true,
      messagingSpans: false,
      errorStatus: true,
      serviceNameResource: true,
      environmentResource: true,
      deploymentVersionResource: false,
      traceLogCorrelation: true,
      samplingPolicyDocumented: true
    });
    expect(result).toMatchObject({ coverageScore: 80, maturity: "strong" });
    expect(result.gaps).toEqual(["messagingSpans", "deploymentVersionResource"]);
    expect(result.recommendedActions).toHaveLength(2);
  });

  it("calculates multi-window SLO burn rate and severity", () => {
    const result = analyzeSloBurnRate({
      service: "payments",
      sloTargetPercent: 99.9,
      shortWindow: { minutes: 5, totalRequests: 10000, failedRequests: 200 },
      longWindow: { minutes: 60, totalRequests: 120000, failedRequests: 900 }
    });
    expect(result.shortWindow.burnRate).toBe(20);
    expect(result.longWindow.burnRate).toBe(7.5);
    expect(result).toMatchObject({ combinedBurnRate: 20, severity: "critical" });
    expect(result.budgetExhaustionHoursAtCurrentRate).toBe(36);
  });

  it("keeps normal SLO burn below one times budget consumption", () => {
    const result = analyzeSloBurnRate({
      service: "api",
      sloTargetPercent: 99,
      shortWindow: { minutes: 5, totalRequests: 10000, failedRequests: 20 },
      longWindow: { minutes: 60, totalRequests: 100000, failedRequests: 100 }
    });
    expect(result.severity).toBe("normal");
    expect(result.combinedBurnRate).toBeLessThan(1);
  });
  it("correlates trace, SLO, dependencies and deployment timing without ranking a root cause", () => {
    const result = correlateTraceSloIncident({
      service: "checkout",
      trace: {
        spanCount: 12,
        errorSpanCount: 3,
        durationMs: 1800,
        services: ["checkout", "payments", "database"]
      },
      slo: { severity: "critical", combinedBurnRate: 18 },
      deployment: { id: "deploy-77", deployedAt: 1700000000, traceObservedAt: 1700000120 },
      dependencyEdges: [{
        caller: "checkout",
        callee: "payments",
        callCount: 10,
        errorCount: 4,
        averageDurationMs: 720
      }]
    });
    expect(result).toMatchObject({
      correlationStrength: "strong",
      evidenceDomainCount: 4,
      deploymentProximitySeconds: 120
    });
    expect(result.problematicDependencies[0]).toMatchObject({ callee: "payments", errorCount: 4 });
    expect(result.nextChecks.join(" ")).toMatch(/before assigning root cause/i);
  });

  it("fails closed for disabled or unapproved tracing targets and malformed requests", async () => {
    const fetcher: TraceHttpFetcher = async () => jsonResult({});
    await expect(traceSearch({
      backend: "tempo",
      baseUrl: "https://unapproved.example.com",
      service: "api",
      startTime: 100,
      endTime: 200
    }, fetcher)).rejects.toThrow(/not in CLOUD_DEVOPS_MCP_ALLOWED_TEMPO_URLS/i);

    await expect(traceSummary({
      backend: "jaeger",
      baseUrl: "https://jaeger.example.com",
      traceId: "not-a-trace-id"
    }, fetcher)).rejects.toThrow(/traceId/i);

    await expect(traceSearch({
      backend: "jaeger",
      baseUrl: "https://jaeger.example.com",
      service: "api",
      startTime: 100,
      endTime: 30000
    }, fetcher)).rejects.toThrow(/cannot exceed 21600/i);

    await expect(traceSearch({
      backend: "jaeger",
      baseUrl: "https://jaeger.example.com",
      service: "api",
      startTime: 100,
      endTime: 200,
      traceQl: "{}"
    }, fetcher)).rejects.toThrow(/Tempo backend/i);

    process.env.CLOUD_DEVOPS_MCP_TRACING_ENABLED = "false";
    await expect(traceSearch({
      backend: "tempo",
      baseUrl: "https://tempo.example.com",
      service: "api",
      startTime: 100,
      endTime: 200
    }, fetcher)).rejects.toThrow(/disabled/i);
  });
  it("validates SLO input boundaries", () => {
    expect(() => analyzeSloBurnRate({
      service: "api",
      sloTargetPercent: 100,
      shortWindow: { minutes: 5, totalRequests: 100, failedRequests: 0 },
      longWindow: { minutes: 60, totalRequests: 1000, failedRequests: 0 }
    })).toThrow(/sloTargetPercent/i);

    expect(() => analyzeSloBurnRate({
      service: "api",
      sloTargetPercent: 99.9,
      shortWindow: { minutes: 60, totalRequests: 100, failedRequests: 0 },
      longWindow: { minutes: 5, totalRequests: 1000, failedRequests: 0 }
    })).toThrow(/shortWindow must be shorter/i);

    expect(() => analyzeSloBurnRate({
      service: "api",
      sloTargetPercent: 99.9,
      shortWindow: { minutes: 5, totalRequests: 100, failedRequests: 101 },
      longWindow: { minutes: 60, totalRequests: 1000, failedRequests: 0 }
    })).toThrow(/failedRequests/i);
  });

  it("exposes exactly six v0.9 tools only when the tracing gate is enabled", async () => {
    const server = createServer();
    const client = new Client({ name: "tracing-test", version: "1.0.0" });
    const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
    await server.connect(serverTransport);
    await client.connect(clientTransport);
    try {
      const { tools } = await client.listTools();
      expect(tools).toHaveLength(18);
      const names = tools.map((tool) => tool.name);
      expect(names).toEqual(expect.arrayContaining([
        "trace_search",
        "trace_summary",
        "trace_dependency_map",
        "assess_tracing_coverage",
        "analyze_slo_burn_rate",
        "correlate_trace_slo_incident"
      ]));
      const tracingTools = tools.filter((tool) => [
        "trace_search",
        "trace_summary",
        "trace_dependency_map",
        "assess_tracing_coverage",
        "analyze_slo_burn_rate",
        "correlate_trace_slo_incident"
      ].includes(tool.name));
      expect(tracingTools.every((tool) => tool.annotations?.readOnlyHint === true)).toBe(true);
      expect(tracingTools.every((tool) => tool.annotations?.destructiveHint === false)).toBe(true);
    } finally {
      await client.close();
      await server.close();
    }
  });
});
