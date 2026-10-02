import { appendFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { resolve } from "node:path";
import { defaultCommandRunner, type CommandRunner } from "./infrastructure.js";

export type HttpFetcher = (url: string, init?: { headers?: Record<string, string> }) => Promise<{
  ok: boolean; status: number; json(): Promise<any>; text(): Promise<string>;
}>;
const http: HttpFetcher = (url, init) => fetch(url, init);

function csv(name: string) {
  return (process.env[name] ?? "").split(",").map((v) => v.trim()).filter(Boolean);
}
function enabled() {
  if (process.env.CLOUD_DEVOPS_MCP_OBSERVABILITY_ENABLED !== "true") throw new Error("Production observability is disabled.");
}
function redact(value: string) {
  return value
    .replace(/AKIA[0-9A-Z]{16}/g, "[REDACTED_AWS_ACCESS_KEY]")
    .replace(/gh[pousr]_[A-Za-z0-9_]{20,}/g, "[REDACTED_GITHUB_TOKEN]")
    .replace(/github_pat_[A-Za-z0-9_]{20,}/g, "[REDACTED_GITHUB_TOKEN]")
    .replace(/(token|password|secret|client_secret|access_key)\s*[=:]\s*[^\s,;]+/gi, "$1=[REDACTED]");
}
async function audit(action: string, scope: string, outcome: "success" | "failure", detail = "") {
  const path = process.env.CLOUD_DEVOPS_MCP_AUDIT_LOG || resolve(tmpdir(), "cloud-devops-mcp-audit.jsonl");
  await appendFile(path, JSON.stringify({ timestamp: new Date().toISOString(), action, scope, outcome, detail: redact(detail).slice(0, 2000) }) + "\n").catch(() => undefined);
}
function baseUrl(env: string, input: string) {
  const parse = (v: string) => {
    const u = new URL(v);
    if (u.username || u.password || u.search || u.hash) throw new Error("Observability URL cannot contain credentials, query parameters or fragments.");
    if (u.protocol !== "https:" && !(u.protocol === "http:" && ["localhost", "127.0.0.1", "::1"].includes(u.hostname))) throw new Error("Observability URL must use HTTPS unless localhost.");
    return u.toString().replace(/\/+$/, "");
  };
  const value = parse(input);
  if (!csv(env).map(parse).includes(value)) throw new Error(`Observability endpoint is not in ${env}.`);
  return value;
}
function headers(token?: string): Record<string, string> {
  const result: Record<string, string> = { Accept: "application/json" };
  if (token) result.Authorization = `Bearer ${token}`;
  return result;
}

export async function prometheusQuery(
  input: { baseUrl: string; query: string; startTime?: number; endTime?: number; stepSeconds?: number },
  fetcher: HttpFetcher = http
) {
  enabled();
  const root = baseUrl("CLOUD_DEVOPS_MCP_ALLOWED_PROMETHEUS_URLS", input.baseUrl);
  const query = input.query.trim();
  if (!query || query.length > 2000 || query.includes("\0")) throw new Error("Invalid PromQL query.");
  const ranged = input.startTime !== undefined || input.endTime !== undefined;
  if (ranged && (input.startTime === undefined || input.endTime === undefined)) throw new Error("startTime and endTime must be provided together.");
  const params = new URLSearchParams({ query });
  if (ranged) {
    const start = Number(input.startTime), end = Number(input.endTime), step = Number(input.stepSeconds ?? 60);
    if (!Number.isFinite(start) || !Number.isFinite(end) || end <= start || end - start > 21600) throw new Error("Prometheus range must be between 1 and 21600 seconds.");
    if (!Number.isFinite(step) || step < 15 || step > 3600) throw new Error("stepSeconds must be between 15 and 3600.");
    params.set("start", String(start)); params.set("end", String(end)); params.set("step", String(step));
  }
  const mode = ranged ? "range" : "instant";
  try {
    const response = await fetcher(`${root}/api/v1/query${ranged ? "_range" : ""}?${params}`, { headers: headers(process.env.CLOUD_DEVOPS_MCP_PROMETHEUS_BEARER_TOKEN) });
    if (!response.ok) throw new Error(`Prometheus returned HTTP ${response.status}.`);
    const payload = await response.json();
    if (payload?.status !== "success") throw new Error(`Prometheus query failed: ${String(payload?.error ?? "unknown")}`);
    const series = (Array.isArray(payload?.data?.result) ? payload.data.result : []).slice(0, 200).map((item: any) => {
      const samples = Array.isArray(item?.values) ? item.values : Array.isArray(item?.value) ? [item.value] : [];
      const last = samples.at(-1);
      return {
        metric: Object.fromEntries(Object.entries(item?.metric ?? {}).map(([k, v]) => [String(k), String(v)])),
        sampleCount: samples.length,
        latestTimestamp: Array.isArray(last) && Number.isFinite(Number(last[0])) ? Number(last[0]) : null,
        latestValue: Array.isArray(last) ? String(last[1] ?? "") : ""
      };
    });
    await audit("prometheus_query", root, "success", `${series.length} series`);
    return { baseUrl: root, mode, resultType: String(payload?.data?.resultType ?? "unknown"), seriesCount: series.length, series };
  } catch (e: any) { await audit("prometheus_query", root, "failure", e.message); throw e; }
}

export async function grafanaAlertSummary(input: { baseUrl: string }, fetcher: HttpFetcher = http) {
  enabled();
  const root = baseUrl("CLOUD_DEVOPS_MCP_ALLOWED_GRAFANA_URLS", input.baseUrl);
  const auth = headers(process.env.CLOUD_DEVOPS_MCP_GRAFANA_TOKEN);
  try {
    const r = await fetcher(`${root}/api/v1/provisioning/alert-rules`, { headers: auth });
    if (!r.ok) throw new Error(`Grafana returned HTTP ${r.status}.`);
    const payload = await r.json();
    const normalized = (Array.isArray(payload) ? payload : []).slice(0, 200).map((x: any) => ({
      uid: String(x?.uid ?? ""), title: String(x?.title ?? ""), folderUID: String(x?.folderUID ?? ""),
      ruleGroup: String(x?.ruleGroup ?? ""), condition: String(x?.condition ?? ""), paused: Boolean(x?.isPaused)
    }));
    const ar = await fetcher(`${root}/api/alertmanager/grafana/api/v2/alerts?active=true&silenced=false&inhibited=false`, { headers: auth });
    const activePayload = ar.ok ? await ar.json() : [];
    const activeAlerts = (Array.isArray(activePayload) ? activePayload : []).slice(0, 200).map((x: any) => ({
      labels: Object.fromEntries(Object.entries(x?.labels ?? {}).map(([k, v]) => [String(k), String(v)])),
      annotations: Object.fromEntries(Object.entries(x?.annotations ?? {}).map(([k, v]) => [String(k), String(v)])),
      state: String(x?.status?.state ?? "active")
    }));
    await audit("grafana_alert_summary", root, "success", `rules=${normalized.length},active=${activeAlerts.length}`);
    return { baseUrl: root, ruleCount: normalized.length, pausedCount: normalized.filter((x) => x.paused).length, activeAlertsAvailable: ar.ok, activeAlertCount: activeAlerts.length, rules: normalized, activeAlerts };
  } catch (e: any) { await audit("grafana_alert_summary", root, "failure", e.message); throw e; }
}

function awsRegion(region: string) {
  const v = region.trim();
  if (!/^[a-z]{2}(?:-gov)?-[a-z]+-\d$/.test(v) || !csv("CLOUD_DEVOPS_MCP_ALLOWED_AWS_REGIONS").includes(v)) throw new Error("AWS region is not allowlisted.");
  return v;
}
function awsProfile(profile?: string) {
  if (!profile) return undefined;
  const v = profile.trim();
  if (!/^[A-Za-z0-9._-]{1,128}$/.test(v) || !csv("CLOUD_DEVOPS_MCP_ALLOWED_AWS_PROFILES").includes(v)) throw new Error("AWS profile is not allowlisted.");
  return v;
}
function awsArgs(region: string, profile?: string) {
  const args: string[] = []; const p = awsProfile(profile); if (p) args.push("--profile", p); args.push("--region", awsRegion(region)); return args;
}
async function account(region: string, profile: string | undefined, runner: CommandRunner) {
  const r = await runner("aws", [...awsArgs(region, profile), "sts", "get-caller-identity", "--output", "json", "--no-cli-pager"], process.cwd());
  const id = String(JSON.parse(r.stdout || "{}")?.Account ?? "");
  if (!csv("CLOUD_DEVOPS_MCP_ALLOWED_AWS_ACCOUNTS").includes(id)) throw new Error("AWS account is not allowlisted.");
  return id;
}

export async function cloudWatchLogsQuery(
  input: { region: string; profile?: string; logGroup: string; queryString: string; startTime: number; endTime: number; limit?: number },
  runner: CommandRunner = defaultCommandRunner
) {
  enabled();
  const region = awsRegion(input.region), logGroup = input.logGroup.trim(), query = input.queryString.trim(), limit = Number(input.limit ?? 50);
  if (!csv("CLOUD_DEVOPS_MCP_ALLOWED_CLOUDWATCH_LOG_GROUPS").includes(logGroup)) throw new Error("CloudWatch log group is not allowlisted.");
  if (!query || query.length > 4000 || query.includes("\0")) throw new Error("Invalid CloudWatch Logs query.");
  if (!Number.isInteger(input.startTime) || !Number.isInteger(input.endTime) || input.endTime <= input.startTime || input.endTime - input.startTime > 21600) throw new Error("CloudWatch Logs query window must be between 1 and 21600 seconds.");
  if (!Number.isInteger(limit) || limit < 1 || limit > 100) throw new Error("CloudWatch Logs limit must be 1-100.");
  let scope = region;
  try {
    scope = `${await account(region, input.profile, runner)}:${region}:${logGroup}`;
    const start = await runner("aws", [...awsArgs(region, input.profile), "logs", "start-query", "--log-group-name", logGroup, "--start-time", String(input.startTime), "--end-time", String(input.endTime), "--query-string", query, "--limit", String(limit), "--output", "json", "--no-cli-pager"], process.cwd());
    const queryId = String(JSON.parse(start.stdout || "{}")?.queryId ?? "");
    if (!queryId) throw new Error("CloudWatch Logs Insights did not return a queryId.");
    let payload: any = {};
    for (let i = 0; i < 5; i += 1) {
      const r = await runner("aws", [...awsArgs(region, input.profile), "logs", "get-query-results", "--query-id", queryId, "--output", "json", "--no-cli-pager"], process.cwd());
      payload = JSON.parse(r.stdout || "{}");
      if (!["Scheduled", "Running"].includes(String(payload?.status ?? ""))) break;
      if (i < 4) await new Promise((resolvePromise) => setTimeout(resolvePromise, 300));
    }
    const rows = (Array.isArray(payload?.results) ? payload.results : []).slice(0, limit).map((row: any[]) =>
      Object.fromEntries((Array.isArray(row) ? row : []).map((f: any) => [String(f?.field ?? ""), redact(String(f?.value ?? "")).slice(0, 4000)]).filter(([k]) => k))
    );
    const s = payload?.statistics ?? {};
    await audit("cloudwatch_logs_query", scope, "success", `${rows.length} rows`);
    return { scope, logGroup, status: String(payload?.status ?? "Unknown"), resultCount: rows.length, rows, statistics: { recordsMatched: Number(s.recordsMatched ?? 0), recordsScanned: Number(s.recordsScanned ?? 0), bytesScanned: Number(s.bytesScanned ?? 0) } };
  } catch (e: any) { await audit("cloudwatch_logs_query", scope, "failure", e.message); throw e; }
}

export async function kubernetesHealthSummary(
  input: { context: string; namespace: string; labelSelector?: string },
  runner: CommandRunner = defaultCommandRunner
) {
  enabled();
  const context = input.context.trim(), namespace = input.namespace.trim(), selector = input.labelSelector?.trim();
  if (!csv("CLOUD_DEVOPS_MCP_ALLOWED_KUBE_CONTEXTS").includes(context)) throw new Error("Kubernetes context is not allowlisted.");
  if (!csv("CLOUD_DEVOPS_MCP_ALLOWED_KUBE_NAMESPACES").includes(namespace)) throw new Error("Kubernetes namespace is not allowlisted.");
  if (selector && (!/^[A-Za-z0-9_.=,!()\-\/]{1,300}$/.test(selector) || selector.startsWith("-"))) throw new Error("Invalid Kubernetes label selector.");
  const args = ["--context", context, "--namespace", namespace, "get", "pods"]; if (selector) args.push("--selector", selector); args.push("-o", "json", "--request-timeout=15s");
  const scope = `${context}:${namespace}`;
  try {
    const payload = JSON.parse((await runner("kubectl", args, process.cwd())).stdout || "{}");
    const pods = (Array.isArray(payload?.items) ? payload.items : []).slice(0, 300).map((p: any) => {
      const cs = Array.isArray(p?.status?.containerStatuses) ? p.status.containerStatuses : [];
      const restarts = cs.reduce((sum: number, x: any) => sum + Number(x?.restartCount ?? 0), 0);
      const reason = cs.flatMap((x: any) => [x?.state?.waiting?.reason, x?.state?.terminated?.reason]).filter(Boolean)[0] ?? "";
      return { name: String(p?.metadata?.name ?? ""), phase: String(p?.status?.phase ?? "Unknown"), ready: cs.length > 0 && cs.every((x: any) => x?.ready === true), restarts, reason: String(reason) };
    });
    const bad = pods.filter((p: any) => p.phase !== "Running" || !p.ready || p.restarts >= 3);
    await audit("kubernetes_health_summary", scope, "success", `unhealthy=${bad.length}`);
    return { context, namespace, podCount: pods.length, runningCount: pods.filter((p: any) => p.phase === "Running").length, readyCount: pods.filter((p: any) => p.ready).length, pendingCount: pods.filter((p: any) => p.phase === "Pending").length, failedCount: pods.filter((p: any) => p.phase === "Failed").length, restartingCount: pods.filter((p: any) => p.restarts >= 3).length, unhealthyCount: bad.length, unhealthyPods: bad.slice(0, 100) };
  } catch (e: any) { await audit("kubernetes_health_summary", scope, "failure", e.message); throw e; }
}

function repo(value: string) {
  const v = value.trim();
  if (!/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(v) || !csv("CLOUD_DEVOPS_MCP_ALLOWED_GITHUB_REPOSITORIES").map((x) => x.toLowerCase()).includes(v.toLowerCase())) throw new Error("GitHub repository is not allowlisted.");
  return v;
}
function failureCategory(text: string) {
  const v = text.toLowerCase();
  if (/no space left|disk quota/.test(v)) return "disk-capacity";
  if (/timed out|timeout|timed_out/.test(v)) return "timeout";
  if (/resource not accessible|permission denied|\b403\b|unauthorized|forbidden/.test(v)) return "authorization";
  if (/rate limit/.test(v)) return "rate-limit";
  if (/terraform/.test(v)) return "terraform";
  if (/kubectl|helm|kubernetes/.test(v)) return "kubernetes";
  if (/docker build|buildx|failed to solve/.test(v)) return "container-build";
  if (/npm err|test failed|assertionerror|vitest|jest/.test(v)) return "tests";
  if (/could not resolve host|connection refused|network is unreachable|name resolution|econnreset/.test(v)) return "network";
  if (/secret.*(not found|missing)|credential.*(not found|missing)/.test(v)) return "secret-configuration";
  return "unclassified";
}

export async function githubActionsFailureDiagnosis(input: { repository: string; runId: number }, fetcher: HttpFetcher = http) {
  enabled();
  const repository = repo(input.repository), runId = Number(input.runId), token = process.env.CLOUD_DEVOPS_MCP_GITHUB_TOKEN?.trim();
  if (!Number.isSafeInteger(runId) || runId <= 0) throw new Error("runId must be positive.");
  if (!token) throw new Error("CLOUD_DEVOPS_MCP_GITHUB_TOKEN is required.");
  const h = { Authorization: `Bearer ${token}`, Accept: "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28" };
  const scope = `${repository}:${runId}`;
  try {
    const response = await fetcher(`https://api.github.com/repos/${repository}/actions/runs/${runId}/jobs?per_page=100`, { headers: h });
    if (!response.ok) throw new Error(`GitHub Actions returned HTTP ${response.status}.`);
    const payload = await response.json();
    const all = (Array.isArray(payload?.jobs) ? payload.jobs : []).slice(0, 100);
    const bad = new Set(["failure", "cancelled", "timed_out", "action_required", "startup_failure", "stale"]);
    const failed = all.filter((j: any) => bad.has(String(j?.conclusion ?? "").toLowerCase()));
    const failedJobs: any[] = [];
    for (const job of failed.slice(0, 5)) {
      const steps = (Array.isArray(job?.steps) ? job.steps : []).filter((s: any) => bad.has(String(s?.conclusion ?? "").toLowerCase())).map((s: any) => String(s?.name ?? "")).filter(Boolean);
      const lr = await fetcher(`https://api.github.com/repos/${repository}/actions/jobs/${Number(job?.id)}/logs`, { headers: h });
      const logs = lr.ok ? (await lr.text()).slice(0, 200000) : "";
      failedJobs.push({ id: Number(job?.id ?? 0), name: String(job?.name ?? ""), conclusion: String(job?.conclusion ?? ""), failedSteps: steps, category: failureCategory(`${job?.name}\n${steps.join("\n")}\n${logs}`), evidence: [...new Set(redact(logs).split(/\r?\n/).filter((l) => /(error|fail|fatal|denied|timeout|not found)/i.test(l)).map((l) => l.trim().slice(0, 500)))].slice(0, 5) });
    }
    const categoryCounts: Record<string, number> = {}; for (const j of failedJobs) categoryCounts[j.category] = (categoryCounts[j.category] ?? 0) + 1;
    await audit("github_actions_failure_diagnosis", scope, "success", `failed=${failed.length}`);
    return { repository, runId, totalJobCount: all.length, failedJobCount: failed.length, diagnosedJobCount: failedJobs.length, categoryCounts, failedJobs };
  } catch (e: any) { await audit("github_actions_failure_diagnosis", scope, "failure", e.message); throw e; }
}

export function correlateIncidentSignals(input: {
  service: string;
  metrics?: Array<{ name: string; status: "normal" | "degraded" | "critical"; detail: string }>;
  logs?: Array<{ level: "info" | "warn" | "error" | "critical"; message: string }>;
  alerts?: Array<{ source: string; status: "firing" | "resolved" | "unknown"; summary: string }>;
  kubernetes?: Array<{ workload: string; status: "healthy" | "degraded" | "failed"; detail: string }>;
  cicd?: Array<{ pipeline: string; status: "success" | "failed" | "running"; detail: string }>;
}) {
  const m = input.metrics ?? [], l = input.logs ?? [], a = input.alerts ?? [], k = input.kubernetes ?? [], c = input.cicd ?? [];
  const dm = m.filter((x) => x.status !== "normal"), el = l.filter((x) => ["error", "critical"].includes(x.level)), fa = a.filter((x) => x.status === "firing"), uk = k.filter((x) => x.status !== "healthy"), fc = c.filter((x) => x.status === "failed");
  const correlations: any[] = [];
  const add = (ruleId: string, title: string, confidence: "high" | "medium", domains: string[], evidence: string[]) => correlations.push({ ruleId, title, confidence, domains, evidence: evidence.filter(Boolean) });
  if (dm.length && el.length) add("OBS_METRIC_LOG_DEGRADATION", "Degraded metrics align with error logs.", "high", ["metrics", "logs"], [dm[0]!.detail, el[0]!.message]);
  if (uk.length && el.length) add("OBS_K8S_LOG_RUNTIME_INSTABILITY", "Kubernetes health issues align with error logs.", "high", ["kubernetes", "logs"], [uk[0]!.detail, el[0]!.message]);
  if (fc.length && uk.length) add("OBS_CICD_K8S_RELEASE_FAILURE", "A failed delivery signal overlaps with unhealthy Kubernetes state.", "medium", ["cicd", "kubernetes"], [fc[0]!.detail, uk[0]!.detail]);
  if (fa.length && dm.length) add("OBS_ALERT_METRIC_CONFIRMATION", "A firing alert is supported by degraded metric evidence.", "high", ["alerts", "metrics"], [fa[0]!.summary, dm[0]!.detail]);
  if (fc.length && dm.length) add("OBS_CICD_METRIC_REGRESSION", "A failed delivery signal overlaps with degraded service metrics.", "medium", ["cicd", "metrics"], [fc[0]!.detail, dm[0]!.detail]);
  const domains = [m.length, l.length, a.length, k.length, c.length].filter(Boolean).length;
  const next: string[] = []; if (!m.length) next.push("Collect service metrics."); if (!l.length) next.push("Collect bounded error logs."); if (!a.length) next.push("Check active alerts."); if (!k.length) next.push("Check pod health."); if (!c.length) next.push("Check the latest CI/CD run.");
  return { service: input.service, domainCount: domains, signalCount: m.length + l.length + a.length + k.length + c.length, correlationCount: correlations.length, incidentConfidence: correlations.some((x) => x.confidence === "high") && domains >= 3 ? "high" : correlations.length ? "medium" : "low", correlations, recommendedNextChecks: next };
}
