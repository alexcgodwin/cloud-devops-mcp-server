import { appendFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { resolve } from "node:path";
import type { McpServer } from "@modelcontextprotocol/server";
import * as z from "zod/v4";

export type TraceHttpFetcher = (url: string, init?: { headers?: Record<string, string> }) => Promise<{
  ok: boolean;
  status: number;
  json(): Promise<any>;
  text(): Promise<string>;
}>;

const http: TraceHttpFetcher = (url, init) => fetch(url, init);

function csv(name: string): string[] {
  return (process.env[name] ?? "").split(",").map((value) => value.trim()).filter(Boolean);
}

function enabled() {
  if (process.env.CLOUD_DEVOPS_MCP_TRACING_ENABLED !== "true") {
    throw new Error("Distributed tracing intelligence is disabled.");
  }
}

function redact(value: string): string {
  return value
    .replace(/AKIA[0-9A-Z]{16}/g, "[REDACTED_AWS_ACCESS_KEY]")
    .replace(/gh[pousr]_[A-Za-z0-9_]{20,}/g, "[REDACTED_GITHUB_TOKEN]")
    .replace(/github_pat_[A-Za-z0-9_]{20,}/g, "[REDACTED_GITHUB_TOKEN]")
    .replace(/(token|password|secret|client_secret|access_key)\s*[=:]\s*[^\s,;]+/gi, "$1=[REDACTED]");
}

async function audit(action: string, scope: string, outcome: "success" | "failure", detail = "") {
  const path = process.env.CLOUD_DEVOPS_MCP_AUDIT_LOG || resolve(tmpdir(), "cloud-devops-mcp-audit.jsonl");
  await appendFile(path, JSON.stringify({
    timestamp: new Date().toISOString(),
    action,
    scope,
    outcome,
    detail: redact(detail).slice(0, 2000)
  }) + "\n").catch(() => undefined);
}

function allowlistedBaseUrl(backend: "tempo" | "jaeger", input: string): string {
  const envName = backend === "tempo"
    ? "CLOUD_DEVOPS_MCP_ALLOWED_TEMPO_URLS"
    : "CLOUD_DEVOPS_MCP_ALLOWED_JAEGER_URLS";
  const parse = (value: string) => {
    const url = new URL(value);
    if (url.username || url.password || url.search || url.hash) {
      throw new Error("Tracing URL cannot contain credentials, query parameters or fragments.");
    }
    if (url.protocol !== "https:" && !(url.protocol === "http:" && ["localhost", "127.0.0.1", "::1"].includes(url.hostname))) {
      throw new Error("Tracing URL must use HTTPS unless localhost.");
    }
    return url.toString().replace(/\/+$/, "");
  };
  const value = parse(input);
  if (!csv(envName).map(parse).includes(value)) throw new Error(`Tracing endpoint is not in ${envName}.`);
  return value;
}

function authHeaders(backend: "tempo" | "jaeger"): Record<string, string> {
  const token = backend === "tempo"
    ? process.env.CLOUD_DEVOPS_MCP_TEMPO_BEARER_TOKEN?.trim()
    : process.env.CLOUD_DEVOPS_MCP_JAEGER_BEARER_TOKEN?.trim();
  const headers: Record<string, string> = { Accept: "application/json" };
  if (token) headers.Authorization = `Bearer ${token}`;
  return headers;
}

function validateTraceId(value: string): string {
  const id = value.trim().toLowerCase();
  if (!/^(?:[0-9a-f]{16}|[0-9a-f]{32})$/.test(id)) throw new Error("traceId must be a 64-bit or 128-bit hexadecimal trace ID.");
  return id;
}

function boundedWindow(startTime: number, endTime: number) {
  if (!Number.isInteger(startTime) || !Number.isInteger(endTime) || endTime <= startTime) {
    throw new Error("Tracing time range must use increasing Unix-second integers.");
  }
  if (endTime - startTime > 21600) throw new Error("Tracing time range cannot exceed 21600 seconds.");
}

function attributeMap(attributes: any): Record<string, string> {
  if (!Array.isArray(attributes)) return {};
  const result: Record<string, string> = {};
  for (const attr of attributes.slice(0, 200)) {
    const key = String(attr?.key ?? "");
    if (!key) continue;
    const value = attr?.value ?? {};
    const scalar = value.stringValue ?? value.intValue ?? value.doubleValue ?? value.boolValue ??
      value.string_value ?? value.int_value ?? value.double_value ?? value.bool_value ?? "";
    result[key] = String(scalar);
  }
  return result;
}

type NormalizedSpan = {
  traceId: string;
  spanId: string;
  parentSpanId: string;
  service: string;
  name: string;
  startTimeUnixNano: string;
  endTimeUnixNano: string;
  durationMs: number;
  error: boolean;
  attributes: Record<string, string>;
};

function serviceFromResource(resource: any, fallback = ""): string {
  const attrs = attributeMap(resource?.attributes);
  return attrs["service.name"] ?? fallback;
}

function errorFromSpan(span: any, attrs: Record<string, string>): boolean {
  const code = String(span?.status?.code ?? span?.status?.statusCode ?? "").toUpperCase();
  if (code === "2" || code.includes("ERROR")) return true;
  if (["true", "1"].includes(String(attrs["error"] ?? "").toLowerCase())) return true;
  const httpStatus = Number(attrs["http.status_code"] ?? attrs["http.response.status_code"]);
  return Number.isFinite(httpStatus) && httpStatus >= 500;
}

function normalizeSpan(span: any, service: string): NormalizedSpan {
  const attrs = attributeMap(span?.attributes);
  const start = BigInt(String(span?.startTimeUnixNano ?? span?.start_time_unix_nano ?? "0"));
  const end = BigInt(String(span?.endTimeUnixNano ?? span?.end_time_unix_nano ?? "0"));
  const durationMs = end > start ? Number(end - start) / 1_000_000 : 0;
  return {
    traceId: String(span?.traceId ?? span?.trace_id ?? "").toLowerCase(),
    spanId: String(span?.spanId ?? span?.span_id ?? "").toLowerCase(),
    parentSpanId: String(span?.parentSpanId ?? span?.parent_span_id ?? "").toLowerCase(),
    service,
    name: String(span?.name ?? ""),
    startTimeUnixNano: start.toString(),
    endTimeUnixNano: end.toString(),
    durationMs: Math.round(durationMs * 1000) / 1000,
    error: errorFromSpan(span, attrs),
    attributes: attrs
  };
}

function normalizeTracePayload(payload: any): NormalizedSpan[] {
  const spans: NormalizedSpan[] = [];
  const visit = (node: any, inheritedService = "") => {
    if (!node || typeof node !== "object") return;
    const service = node.resource ? serviceFromResource(node.resource, inheritedService) : inheritedService;

    const spanCollections = [node.scopeSpans, node.scope_spans, node.instrumentationLibrarySpans, node.instrumentation_library_spans]
      .filter(Array.isArray);
    for (const collections of spanCollections) {
      for (const scope of collections as any[]) {
        for (const span of Array.isArray(scope?.spans) ? scope.spans : []) {
          spans.push(normalizeSpan(span, service));
        }
      }
    }

    for (const key of ["resourceSpans", "resource_spans", "batches"]) {
      for (const child of Array.isArray(node[key]) ? node[key] : []) visit(child, service);
    }
    if (node.result && typeof node.result === "object") visit(node.result, service);
  };
  visit(payload);
  return spans.slice(0, 5000);
}

function summarizeSpans(backend: "tempo" | "jaeger", baseUrl: string, traceId: string, spans: NormalizedSpan[]) {
  const services = [...new Set(spans.map((span) => span.service).filter(Boolean))].sort();
  const operations = [...new Set(spans.map((span) => span.name).filter(Boolean))].sort().slice(0, 200);
  const byId = new Map(spans.map((span) => [span.spanId, span]));
  const roots = spans.filter((span) => !span.parentSpanId || !byId.has(span.parentSpanId));
  const start = spans.reduce<bigint | null>((min, span) => {
    const value = BigInt(span.startTimeUnixNano || "0");
    return value > 0n && (min === null || value < min) ? value : min;
  }, null);
  const end = spans.reduce<bigint | null>((max, span) => {
    const value = BigInt(span.endTimeUnixNano || "0");
    return value > 0n && (max === null || value > max) ? value : max;
  }, null);
  const durationMs = start !== null && end !== null && end > start ? Number(end - start) / 1_000_000 : 0;
  return {
    backend,
    baseUrl,
    traceId,
    spanCount: spans.length,
    serviceCount: services.length,
    services,
    operationCount: operations.length,
    operations,
    errorSpanCount: spans.filter((span) => span.error).length,
    rootSpanCount: roots.length,
    rootOperations: roots.map((span) => ({ service: span.service, name: span.name })).slice(0, 20),
    durationMs: Math.round(durationMs * 1000) / 1000,
    slowestSpans: [...spans]
      .sort((a, b) => b.durationMs - a.durationMs)
      .slice(0, 20)
      .map((span) => ({ service: span.service, name: span.name, durationMs: span.durationMs, error: span.error }))
  };
}

export async function traceSummary(
  input: { backend: "tempo" | "jaeger"; baseUrl: string; traceId: string; startTime?: number; endTime?: number },
  fetcher: TraceHttpFetcher = http
) {
  enabled();
  const root = allowlistedBaseUrl(input.backend, input.baseUrl);
  const traceId = validateTraceId(input.traceId);
  if ((input.startTime === undefined) !== (input.endTime === undefined)) throw new Error("startTime and endTime must be supplied together.");
  if (input.startTime !== undefined && input.endTime !== undefined) boundedWindow(input.startTime, input.endTime);
  const params = new URLSearchParams();
  if (input.startTime !== undefined && input.endTime !== undefined) {
    if (input.backend === "tempo") {
      params.set("start", String(input.startTime));
      params.set("end", String(input.endTime));
    } else {
      params.set("startTime", new Date(input.startTime * 1000).toISOString());
      params.set("endTime", new Date(input.endTime * 1000).toISOString());
    }
  }
  const endpoint = input.backend === "tempo" ? `/api/v2/traces/${traceId}` : `/api/v3/traces/${traceId}`;
  const url = `${root}${endpoint}${params.size ? `?${params}` : ""}`;
  try {
    const response = await fetcher(url, { headers: authHeaders(input.backend) });
    if (!response.ok) throw new Error(`${input.backend} returned HTTP ${response.status}.`);
    const payload = await response.json();
    const spans = normalizeTracePayload(payload);
    if (!spans.length) throw new Error("Trace response contained no readable spans.");
    const summary = summarizeSpans(input.backend, root, traceId, spans);
    await audit("trace_summary", `${input.backend}:${root}:${traceId}`, "success", `spans=${spans.length}`);
    return summary;
  } catch (error: any) {
    await audit("trace_summary", `${input.backend}:${root}:${traceId}`, "failure", error.message);
    throw error;
  }
}export async function traceSearch(
  input: {
    backend: "tempo" | "jaeger";
    baseUrl: string;
    service: string;
    startTime: number;
    endTime: number;
    limit?: number;
    operation?: string;
    traceQl?: string;
  },
  fetcher: TraceHttpFetcher = http
) {
  enabled();
  const root = allowlistedBaseUrl(input.backend, input.baseUrl);
  boundedWindow(input.startTime, input.endTime);
  const service = input.service.trim();
  const operation = input.operation?.trim();
  const limit = Number(input.limit ?? 20);
  if (!service || service.length > 300) throw new Error("service is required and must be 300 characters or fewer.");
  if (operation && operation.length > 300) throw new Error("operation must be 300 characters or fewer.");
  if (!Number.isInteger(limit) || limit < 1 || limit > 100) throw new Error("limit must be between 1 and 100.");

  let url: string;
  if (input.backend === "tempo") {
    const query = input.traceQl?.trim() || `{ resource.service.name = "${service.replaceAll('"', '\\"')}" }`;
    if (!query || query.length > 2000 || query.includes("\0")) throw new Error("Invalid TraceQL query.");
    const params = new URLSearchParams({
      q: query,
      start: String(input.startTime),
      end: String(input.endTime),
      limit: String(limit)
    });
    url = `${root}/api/search?${params}`;
  } else {
    if (input.traceQl) throw new Error("traceQl is supported only by the Tempo backend.");
    const params = new URLSearchParams({
      "query.serviceName": service,
      "query.startTimeMin": new Date(input.startTime * 1000).toISOString(),
      "query.startTimeMax": new Date(input.endTime * 1000).toISOString(),
      "query.pagination.pageSize": String(limit)
    });
    if (operation) params.set("query.operationName", operation);
    url = `${root}/api/v3/trace-summaries?${params}`;
  }

  try {
    const response = await fetcher(url, { headers: authHeaders(input.backend) });
    if (!response.ok) throw new Error(`${input.backend} returned HTTP ${response.status}.`);
    const payload = await response.json();
    const raw = input.backend === "tempo"
      ? (Array.isArray(payload?.traces) ? payload.traces : [])
      : (() => {
          const candidate = payload?.result ?? payload;
          for (const key of ["traceSummaries", "trace_summaries", "summaries"]) {
            if (Array.isArray(candidate?.[key])) return candidate[key];
          }
          return [];
        })();
    const traces = raw.slice(0, limit).map((item: any) => ({
      traceId: String(item?.traceID ?? item?.traceId ?? item?.trace_id ?? "").toLowerCase(),
      rootServiceName: String(item?.rootServiceName ?? item?.root_service_name ?? item?.serviceName ?? item?.service_name ?? ""),
      rootTraceName: String(item?.rootTraceName ?? item?.root_trace_name ?? item?.operationName ?? item?.operation_name ?? ""),
      startTimeUnixNano: String(item?.startTimeUnixNano ?? item?.start_time_unix_nano ?? ""),
      durationMs: Number(item?.durationMs ?? item?.duration_ms ?? 0),
      spanCount: Number(item?.spanCount ?? item?.span_count ?? item?.spans ?? 0)
    }));
    await audit("trace_search", `${input.backend}:${root}:${service}`, "success", `traces=${traces.length}`);
    return { backend: input.backend, baseUrl: root, service, operation: operation ?? "", resultCount: traces.length, traces };
  } catch (error: any) {
    await audit("trace_search", `${input.backend}:${root}:${service}`, "failure", error.message);
    throw error;
  }
}export function traceDependencyMap(input: {
  service: string;
  spans: Array<{ spanId: string; parentSpanId?: string; service: string; name: string; durationMs?: number; error?: boolean }>;
}) {
  const spans = input.spans.slice(0, 5000);
  const byId = new Map(spans.map((span) => [span.spanId, span]));
  const edges = new Map<string, { caller: string; callee: string; count: number; errorCount: number; totalDurationMs: number }>();
  for (const span of spans) {
    if (!span.parentSpanId) continue;
    const parent = byId.get(span.parentSpanId);
    if (!parent || !parent.service || !span.service || parent.service === span.service) continue;
    const key = `${parent.service}\0${span.service}`;
    const edge = edges.get(key) ?? { caller: parent.service, callee: span.service, count: 0, errorCount: 0, totalDurationMs: 0 };
    edge.count += 1;
    if (span.error) edge.errorCount += 1;
    edge.totalDurationMs += Number.isFinite(Number(span.durationMs)) ? Math.max(0, Number(span.durationMs)) : 0;
    edges.set(key, edge);
  }
  const normalized = [...edges.values()]
    .map((edge) => ({
      caller: edge.caller,
      callee: edge.callee,
      callCount: edge.count,
      errorCount: edge.errorCount,
      errorRatePercent: edge.count ? Math.round((edge.errorCount / edge.count) * 10000) / 100 : 0,
      averageDurationMs: edge.count ? Math.round((edge.totalDurationMs / edge.count) * 1000) / 1000 : 0
    }))
    .sort((a, b) => b.callCount - a.callCount || a.caller.localeCompare(b.caller) || a.callee.localeCompare(b.callee));
  const services = [...new Set(spans.map((span) => span.service).filter(Boolean))].sort();
  return {
    service: input.service,
    spanCount: spans.length,
    serviceCount: services.length,
    services,
    edgeCount: normalized.length,
    edges: normalized.slice(0, 500)
  };
}export function assessTracingCoverage(input: {
  service: string;
  serverSpans: boolean;
  clientSpans: boolean;
  databaseSpans: boolean;
  messagingSpans: boolean;
  errorStatus: boolean;
  serviceNameResource: boolean;
  environmentResource: boolean;
  deploymentVersionResource: boolean;
  traceLogCorrelation: boolean;
  samplingPolicyDocumented: boolean;
}) {
  const controls = {
    serverSpans: input.serverSpans,
    clientSpans: input.clientSpans,
    databaseSpans: input.databaseSpans,
    messagingSpans: input.messagingSpans,
    errorStatus: input.errorStatus,
    serviceNameResource: input.serviceNameResource,
    environmentResource: input.environmentResource,
    deploymentVersionResource: input.deploymentVersionResource,
    traceLogCorrelation: input.traceLogCorrelation,
    samplingPolicyDocumented: input.samplingPolicyDocumented
  };
  const guidance: Record<string, string> = {
    serverSpans: "Instrument inbound requests with server spans.",
    clientSpans: "Instrument outbound dependency calls with client spans.",
    databaseSpans: "Instrument database operations where they materially affect request latency.",
    messagingSpans: "Instrument producer and consumer paths for asynchronous messaging.",
    errorStatus: "Record span error status consistently for failed operations.",
    serviceNameResource: "Set a stable service.name resource attribute.",
    environmentResource: "Attach deployment.environment or an equivalent environment resource attribute.",
    deploymentVersionResource: "Attach service.version or deployment version metadata for release correlation.",
    traceLogCorrelation: "Propagate trace and span identifiers into structured application logs.",
    samplingPolicyDocumented: "Document the sampling policy, including production rate and tail-sampling rules if used."
  };
  const entries = Object.entries(controls);
  const covered = entries.filter(([, value]) => value).map(([key]) => key);
  const gaps = entries.filter(([, value]) => !value).map(([key]) => key);
  const coverageScore = Math.round((covered.length / entries.length) * 100);
  const maturity = coverageScore >= 90 ? "comprehensive" : coverageScore >= 70 ? "strong" : coverageScore >= 50 ? "partial" : "minimal";
  return {
    service: input.service,
    coverageScore,
    maturity,
    coveredControls: covered,
    gaps,
    recommendedActions: gaps.map((gap) => guidance[gap]!)
  };
}export function analyzeSloBurnRate(input: {
  service: string;
  sloTargetPercent: number;
  shortWindow: { minutes: number; totalRequests: number; failedRequests: number };
  longWindow: { minutes: number; totalRequests: number; failedRequests: number };
}) {
  const target = Number(input.sloTargetPercent);
  if (!Number.isFinite(target) || target <= 0 || target >= 100) throw new Error("sloTargetPercent must be greater than 0 and less than 100.");
  const validateWindow = (name: string, window: typeof input.shortWindow) => {
    if (!Number.isFinite(window.minutes) || window.minutes <= 0 || window.minutes > 43200) throw new Error(`${name}.minutes is invalid.`);
    if (!Number.isInteger(window.totalRequests) || window.totalRequests <= 0) throw new Error(`${name}.totalRequests must be a positive integer.`);
    if (!Number.isInteger(window.failedRequests) || window.failedRequests < 0 || window.failedRequests > window.totalRequests) {
      throw new Error(`${name}.failedRequests must be between 0 and totalRequests.`);
    }
  };
  validateWindow("shortWindow", input.shortWindow);
  validateWindow("longWindow", input.longWindow);
  if (input.shortWindow.minutes >= input.longWindow.minutes) throw new Error("shortWindow must be shorter than longWindow.");

  const budgetFraction = (100 - target) / 100;
  const calculate = (window: typeof input.shortWindow) => {
    const errorRate = window.failedRequests / window.totalRequests;
    return {
      minutes: window.minutes,
      totalRequests: window.totalRequests,
      failedRequests: window.failedRequests,
      errorRatePercent: Math.round(errorRate * 10000) / 100,
      burnRate: Math.round((errorRate / budgetFraction) * 1000) / 1000
    };
  };
  const short = calculate(input.shortWindow);
  const long = calculate(input.longWindow);
  const combined = Math.max(short.burnRate, long.burnRate);
  const severity = short.burnRate >= 14.4 && long.burnRate >= 6
    ? "critical"
    : short.burnRate >= 6 && long.burnRate >= 3
      ? "high"
      : combined >= 1
        ? "elevated"
        : "normal";
  const budgetExhaustionHoursAtCurrentRate = combined > 0 ? Math.round((30 * 24 / combined) * 100) / 100 : null;
  return {
    service: input.service,
    sloTargetPercent: target,
    errorBudgetPercent: Math.round((100 - target) * 100000) / 100000,
    shortWindow: short,
    longWindow: long,
    combinedBurnRate: combined,
    severity,
    budgetExhaustionHoursAtCurrentRate,
    recommendedActions: severity === "critical"
      ? ["Treat the SLO burn as an active reliability incident.", "Correlate failing requests with traces, deployments and dependency errors before further risky changes."]
      : severity === "high"
        ? ["Investigate the sustained error-budget burn and identify the affected request paths.", "Review recent deployments and high-error trace dependencies."]
        : severity === "elevated"
          ? ["Monitor the burn trend and inspect representative slow or error traces."]
          : ["Continue normal SLO monitoring."]
  };
}export function correlateTraceSloIncident(input: {
  service: string;
  trace: {
    spanCount: number;
    errorSpanCount: number;
    durationMs: number;
    services: string[];
    slowestSpans?: Array<{ service: string; name: string; durationMs: number; error: boolean }>;
  };
  slo: { severity: "normal" | "elevated" | "high" | "critical"; combinedBurnRate: number };
  deployment?: { id: string; deployedAt: number; traceObservedAt?: number };
  dependencyEdges?: Array<{ caller: string; callee: string; callCount: number; errorCount: number; averageDurationMs: number }>;
}) {
  const evidence: Array<{ domain: string; detail: string }> = [];
  if (input.trace.errorSpanCount > 0) evidence.push({ domain: "tracing", detail: `${input.trace.errorSpanCount} error span(s) appear in the representative trace.` });
  if (input.trace.durationMs > 1000) evidence.push({ domain: "tracing", detail: `Representative trace duration is ${input.trace.durationMs} ms.` });
  if (input.slo.severity !== "normal") evidence.push({ domain: "slo", detail: `SLO burn is ${input.slo.severity} at ${input.slo.combinedBurnRate}x.` });

  const problematicEdges = (input.dependencyEdges ?? [])
    .filter((edge) => edge.errorCount > 0 || edge.averageDurationMs >= 500)
    .sort((a, b) => b.errorCount - a.errorCount || b.averageDurationMs - a.averageDurationMs)
    .slice(0, 10);
  for (const edge of problematicEdges) {
    evidence.push({
      domain: "dependencies",
      detail: `${edge.caller} -> ${edge.callee}: ${edge.errorCount} error(s), ${edge.averageDurationMs} ms average duration.`
    });
  }

  let deploymentProximitySeconds: number | null = null;
  if (input.deployment?.traceObservedAt !== undefined) {
    deploymentProximitySeconds = Math.abs(input.deployment.traceObservedAt - input.deployment.deployedAt);
    if (deploymentProximitySeconds <= 1800) {
      evidence.push({ domain: "deployment", detail: `Representative trace was observed ${deploymentProximitySeconds} second(s) from deployment ${input.deployment.id}.` });
    }
  }

  const domains = [...new Set(evidence.map((item) => item.domain))];
  const correlationStrength = domains.length >= 3 && input.slo.severity !== "normal" && input.trace.errorSpanCount > 0
    ? "strong"
    : domains.length >= 2
      ? "possible"
      : "insufficient-evidence";

  return {
    service: input.service,
    correlationStrength,
    evidenceDomainCount: domains.length,
    evidence,
    problematicDependencies: problematicEdges,
    deploymentProximitySeconds,
    nextChecks: [
      "Compare representative traces from before and after the incident window.",
      "Confirm whether failing or slow spans are concentrated in one service version or dependency.",
      "Use logs and metrics to validate trace evidence before assigning root cause."
    ]
  };
}

function toolResult(payload: Record<string, unknown>) {
  return {
    content: [{ type: "text" as const, text: JSON.stringify(payload, null, 2) }],
    structuredContent: payload
  };
}

const tracingAnnotations = {
  readOnlyHint: true,
  destructiveHint: false,
  idempotentHint: true,
  openWorldHint: true
} as const;

const analysisAnnotations = {
  readOnlyHint: true,
  destructiveHint: false,
  idempotentHint: true,
  openWorldHint: false
} as const;

export function registerTracingTools(server: McpServer) {
  const backendSchema = z.enum(["tempo", "jaeger"]);

  server.registerTool(
    "trace_search",
    {
      title: "Trace Search",
      description: "Search an explicitly allowlisted Grafana Tempo or Jaeger trace backend within a bounded time window and return normalized trace summaries. Tempo supports bounded TraceQL; Jaeger uses its stable v3 HTTP trace-summary API. This tool is read-only and never sends spans or changes backend state.",
      annotations: tracingAnnotations,
      inputSchema: z.object({
        backend: backendSchema.describe("Tracing backend to query."),
        baseUrl: z.string().min(1).describe("Explicitly allowlisted tracing backend base URL."),
        service: z.string().min(1).max(300).describe("Service name used to scope trace search."),
        startTime: z.number().int().describe("Search start as Unix seconds."),
        endTime: z.number().int().describe("Search end as Unix seconds; the window is capped at six hours."),
        limit: z.number().int().min(1).max(100).optional().describe("Maximum trace summaries to return."),
        operation: z.string().max(300).optional().describe("Optional operation/span name. Applied to Jaeger search."),
        traceQl: z.string().max(2000).optional().describe("Optional Tempo TraceQL query. Unsupported for Jaeger.")
      }),
      outputSchema: z.object({
        backend: backendSchema,
        baseUrl: z.string(),
        service: z.string(),
        operation: z.string(),
        resultCount: z.number(),
        traces: z.array(z.object({
          traceId: z.string(),
          rootServiceName: z.string(),
          rootTraceName: z.string(),
          startTimeUnixNano: z.string(),
          durationMs: z.number(),
          spanCount: z.number()
        }))
      })
    },
    async (input) => toolResult(await traceSearch(input))
  );
  server.registerTool(
    "trace_summary",
    {
      title: "Trace Summary",
      description: "Retrieve one trace by hexadecimal trace ID from an explicitly allowlisted Tempo or Jaeger backend, normalize OpenTelemetry-style resource and span data, and summarize services, operations, errors, roots, duration and slow spans. The tool is bounded, read-only and does not ingest or mutate telemetry.",
      annotations: tracingAnnotations,
      inputSchema: z.object({
        backend: backendSchema.describe("Tracing backend containing the trace."),
        baseUrl: z.string().min(1).describe("Explicitly allowlisted tracing backend base URL."),
        traceId: z.string().min(16).max(32).describe("64-bit or 128-bit hexadecimal trace ID."),
        startTime: z.number().int().optional().describe("Optional trace lookup start as Unix seconds; provide with endTime."),
        endTime: z.number().int().optional().describe("Optional trace lookup end as Unix seconds; provide with startTime.")
      }),
      outputSchema: z.object({
        backend: backendSchema,
        baseUrl: z.string(),
        traceId: z.string(),
        spanCount: z.number(),
        serviceCount: z.number(),
        services: z.array(z.string()),
        operationCount: z.number(),
        operations: z.array(z.string()),
        errorSpanCount: z.number(),
        rootSpanCount: z.number(),
        rootOperations: z.array(z.object({ service: z.string(), name: z.string() })),
        durationMs: z.number(),
        slowestSpans: z.array(z.object({
          service: z.string(),
          name: z.string(),
          durationMs: z.number(),
          error: z.boolean()
        }))
      })
    },
    async (input) => toolResult(await traceSummary(input))
  );

  server.registerTool(
    "trace_dependency_map",
    {
      title: "Trace Dependency Map",
      description: "Build a deterministic service dependency map from caller-supplied span relationships, including call counts, error counts, error rates and average child-span duration. Use normalized trace evidence from one or more traces; this analysis tool makes no external calls and performs no mutations.",
      annotations: analysisAnnotations,
      inputSchema: z.object({
        service: z.string().min(2).describe("Primary service or system represented by the supplied spans."),
        spans: z.array(z.object({
          spanId: z.string().min(1).describe("Span identifier."),
          parentSpanId: z.string().optional().describe("Optional parent span identifier."),
          service: z.string().min(1).describe("Service that emitted the span."),
          name: z.string().describe("Span or operation name."),
          durationMs: z.number().min(0).optional().describe("Span duration in milliseconds."),
          error: z.boolean().optional().describe("Whether the span represents an error.")
        })).min(1).max(5000).describe("Bounded normalized span relationships.")
      }),
      outputSchema: z.object({
        service: z.string(),
        spanCount: z.number(),
        serviceCount: z.number(),
        services: z.array(z.string()),
        edgeCount: z.number(),
        edges: z.array(z.object({
          caller: z.string(),
          callee: z.string(),
          callCount: z.number(),
          errorCount: z.number(),
          errorRatePercent: z.number(),
          averageDurationMs: z.number()
        }))
      })
    },
    async (input) => toolResult(traceDependencyMap(input))
  );
  server.registerTool(
    "assess_tracing_coverage",
    {
      title: "Assess Tracing Coverage",
      description: "Assess distributed-tracing production coverage from explicit instrumentation facts: inbound/outbound spans, database and messaging spans, error status, resource attributes, deployment version metadata, trace-log correlation and documented sampling policy. Missing controls are reported as gaps without querying any backend.",
      annotations: analysisAnnotations,
      inputSchema: z.object({
        service: z.string().min(2).describe("Service being assessed."),
        serverSpans: z.boolean().describe("Whether inbound/server request paths emit spans."),
        clientSpans: z.boolean().describe("Whether outbound dependency calls emit spans."),
        databaseSpans: z.boolean().describe("Whether relevant database operations emit spans."),
        messagingSpans: z.boolean().describe("Whether asynchronous producer/consumer paths emit spans."),
        errorStatus: z.boolean().describe("Whether failed operations record span error status consistently."),
        serviceNameResource: z.boolean().describe("Whether service.name is set consistently."),
        environmentResource: z.boolean().describe("Whether environment metadata is attached to trace resources."),
        deploymentVersionResource: z.boolean().describe("Whether service/deployment version metadata is attached."),
        traceLogCorrelation: z.boolean().describe("Whether structured logs contain trace/span correlation identifiers."),
        samplingPolicyDocumented: z.boolean().describe("Whether production sampling behavior is documented.")
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
    async (input) => toolResult(assessTracingCoverage(input))
  );

  const burnWindowSchema = z.object({
    minutes: z.number().positive().describe("Window size in minutes."),
    totalRequests: z.number().int().positive().describe("Total eligible requests in the window."),
    failedRequests: z.number().int().min(0).describe("Failed requests in the window.")
  });

  server.registerTool(
    "analyze_slo_burn_rate",
    {
      title: "Analyze SLO Burn Rate",
      description: "Calculate short- and long-window error-budget burn rates from explicit request counts for a service SLO, classify the current burn signal, and estimate how quickly a 30-day budget would be consumed at the observed rate. It does not fetch metrics or trigger remediation.",
      annotations: analysisAnnotations,
      inputSchema: z.object({
        service: z.string().min(2).describe("Service governed by the SLO."),
        sloTargetPercent: z.number().gt(0).lt(100).describe("SLO target percentage, for example 99.9."),
        shortWindow: burnWindowSchema.describe("Short observation window."),
        longWindow: burnWindowSchema.describe("Long observation window; must be longer than the short window.")
      }),
      outputSchema: z.object({
        service: z.string(),
        sloTargetPercent: z.number(),
        errorBudgetPercent: z.number(),
        shortWindow: z.object({
          minutes: z.number(),
          totalRequests: z.number(),
          failedRequests: z.number(),
          errorRatePercent: z.number(),
          burnRate: z.number()
        }),
        longWindow: z.object({
          minutes: z.number(),
          totalRequests: z.number(),
          failedRequests: z.number(),
          errorRatePercent: z.number(),
          burnRate: z.number()
        }),
        combinedBurnRate: z.number(),
        severity: z.enum(["normal", "elevated", "high", "critical"]),
        budgetExhaustionHoursAtCurrentRate: z.number().nullable(),
        recommendedActions: z.array(z.string())
      })
    },
    async (input) => toolResult(analyzeSloBurnRate(input))
  );
  server.registerTool(
    "correlate_trace_slo_incident",
    {
      title: "Correlate Trace and SLO Incident",
      description: "Correlate a representative distributed trace with SLO burn evidence, optional deployment timing and service-dependency edges. The tool reports evidence strength and problematic dependencies while explicitly stopping short of root-cause ranking, which requires broader evidence.",
      annotations: analysisAnnotations,
      inputSchema: z.object({
        service: z.string().min(2).describe("Service being investigated."),
        trace: z.object({
          spanCount: z.number().int().min(0).describe("Number of spans in the representative trace."),
          errorSpanCount: z.number().int().min(0).describe("Number of error spans."),
          durationMs: z.number().min(0).describe("End-to-end trace duration in milliseconds."),
          services: z.array(z.string()).max(500).describe("Services present in the trace."),
          slowestSpans: z.array(z.object({
            service: z.string(),
            name: z.string(),
            durationMs: z.number().min(0),
            error: z.boolean()
          })).max(100).optional().describe("Optional slow/error span summaries.")
        }),
        slo: z.object({
          severity: z.enum(["normal", "elevated", "high", "critical"]).describe("SLO burn severity."),
          combinedBurnRate: z.number().min(0).describe("Observed maximum short/long-window burn rate.")
        }),
        deployment: z.object({
          id: z.string().min(1).describe("Deployment identifier."),
          deployedAt: z.number().describe("Deployment time as Unix seconds."),
          traceObservedAt: z.number().optional().describe("Representative trace observation time as Unix seconds.")
        }).optional(),
        dependencyEdges: z.array(z.object({
          caller: z.string(),
          callee: z.string(),
          callCount: z.number().int().min(0),
          errorCount: z.number().int().min(0),
          averageDurationMs: z.number().min(0)
        })).max(500).optional().describe("Optional service dependency edges from trace_dependency_map.")
      }),
      outputSchema: z.object({
        service: z.string(),
        correlationStrength: z.enum(["strong", "possible", "insufficient-evidence"]),
        evidenceDomainCount: z.number(),
        evidence: z.array(z.object({ domain: z.string(), detail: z.string() })),
        problematicDependencies: z.array(z.object({
          caller: z.string(),
          callee: z.string(),
          callCount: z.number(),
          errorCount: z.number(),
          averageDurationMs: z.number()
        })),
        deploymentProximitySeconds: z.number().nullable(),
        nextChecks: z.array(z.string())
      })
    },
    async (input) => toolResult(correlateTraceSloIncident(input))
  );
}
