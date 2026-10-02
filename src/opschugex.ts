import type { McpServer } from "@modelcontextprotocol/server";
import * as z from "zod/v4";

export type OpsChugexFetcher = (
  url: string,
  init: {
    method: "POST";
    headers: Record<string, string>;
    body: string;
  }
) => Promise<{
  ok: boolean;
  status: number;
  text(): Promise<string>;
}>;

const http: OpsChugexFetcher = (url, init) => fetch(url, init);

const domainSchema = z.enum([
  "metrics",
  "logs",
  "traces",
  "kubernetes",
  "cloud",
  "terraform",
  "ci_cd"
]);

const confidenceSchema = z.enum(["strong", "moderate", "weak", "insufficient"]);

const evidenceSchema = z.object({
  id: z.string().min(1).max(200).describe("Stable evidence identifier used for auditability."),
  domain: domainSchema.describe("Evidence domain that produced the signal."),
  observedAt: z.number().positive().describe("Observation time as Unix seconds."),
  entity: z.string().min(1).max(500).describe("Service, resource, workload, dependency, pipeline, or other affected entity."),
  signal: z.string().min(1).max(500).describe("Normalized signal name such as cpu_saturation, rollout_failure, or dependency_timeout."),
  state: z.enum(["abnormal", "normal"]).describe("Whether the evidence supports an abnormal condition or provides contradicting healthy evidence."),
  severity: z.enum(["info", "warning", "high", "critical"]).describe("Severity of the observed signal."),
  summary: z.string().min(1).max(4000).describe("Bounded factual summary of the evidence."),
  attributes: z.record(z.string(), z.union([z.string(), z.number(), z.boolean()])).optional().describe("Optional bounded metadata; do not include credentials or secrets.")
});

const inputSchema = z.object({
  incident: z.object({
    service: z.string().min(1).max(300).describe("Service or platform component being investigated."),
    startedAt: z.number().positive().describe("Incident start time as Unix seconds."),
    environment: z.string().max(100).optional().describe("Optional environment such as production or staging."),
    deploymentId: z.string().max(300).optional().describe("Optional deployment identifier when a recent release is relevant.")
  }).describe("Incident context for evidence correlation."),
  evidence: z.array(evidenceSchema).max(1000).describe("Bounded evidence from metrics, logs, traces, Kubernetes, cloud, Terraform, and CI/CD.")
});

const rankedCauseSchema = z.object({
  rank: z.number(),
  causeType: z.string(),
  title: z.string(),
  evidenceScore: z.number(),
  confidence: confidenceSchema,
  supportingEvidenceIds: z.array(z.string()),
  contradictingEvidenceIds: z.array(z.string()),
  supportingDomains: z.array(domainSchema),
  reasoningSummary: z.string(),
  nextChecks: z.array(z.string())
});

const outputSchema = z.object({
  service: z.string(),
  assessment: confidenceSchema,
  evidenceDomainCount: z.number(),
  rankedCauses: z.array(rankedCauseSchema),
  limitations: z.array(z.string())
});

function ensureEnabled() {
  if (process.env.CLOUD_DEVOPS_MCP_OPSCHUGEX_INTELLIGENCE_ENABLED !== "true") {
    throw new Error("OpsChugex commercial root-cause intelligence is disabled.");
  }
}

function endpoint(): string {
  const raw = process.env.CLOUD_DEVOPS_MCP_OPSCHUGEX_ROOT_CAUSE_URL?.trim();
  if (!raw) throw new Error("CLOUD_DEVOPS_MCP_OPSCHUGEX_ROOT_CAUSE_URL is required.");

  const url = new URL(raw);
  if (url.username || url.password || url.search || url.hash) {
    throw new Error("OpsChugex root-cause URL cannot contain credentials, query parameters, or fragments.");
  }
  if (
    url.protocol !== "https:" &&
    !(url.protocol === "http:" && ["localhost", "127.0.0.1", "::1"].includes(url.hostname))
  ) {
    throw new Error("OpsChugex root-cause URL must use HTTPS unless localhost.");
  }
  return url.toString();
}

function bearerToken(): string {
  const token = process.env.CLOUD_DEVOPS_MCP_OPSCHUGEX_TOKEN?.trim() ?? "";
  if (token.length < 32) {
    throw new Error("CLOUD_DEVOPS_MCP_OPSCHUGEX_TOKEN must be at least 32 characters.");
  }
  return token;
}

export async function requestRootCauseDiagnosis(
  input: z.infer<typeof inputSchema>,
  fetcher: OpsChugexFetcher = http
) {
  ensureEnabled();
  const response = await fetcher(endpoint(), {
    method: "POST",
    headers: {
      Accept: "application/json",
      "Content-Type": "application/json",
      Authorization: `Bearer ${bearerToken()}`
    },
    body: JSON.stringify(input)
  });

  if (!response.ok) {
    throw new Error(`OpsChugex root-cause service returned HTTP ${response.status}.`);
  }

  const body = await response.text();
  let parsed: unknown;
  try {
    parsed = JSON.parse(body);
  } catch {
    throw new Error("OpsChugex root-cause service returned invalid JSON.");
  }
  return outputSchema.parse(parsed);
}

export function registerOpsChugexRootCauseTool(server: McpServer) {
  server.registerTool(
    "diagnose_root_cause",
    {
      title: "Diagnose Root Cause",
      description:
        "Send bounded multi-domain incident evidence to the configured private OpsChugex intelligence service and return evidence-ranked probable causes with supporting signals, contradictions, limitations, and next checks. This public MCP tool contains no proprietary scoring rules, accepts no endpoint or credential arguments, performs no remediation, and does not mutate cloud, Kubernetes, Terraform, CI/CD, or observability state.",
      annotations: {
        readOnlyHint: true,
        destructiveHint: false,
        idempotentHint: true,
        openWorldHint: true
      },
      inputSchema,
      outputSchema
    },
    async (input) => {
      const payload = await requestRootCauseDiagnosis(input);
      return {
        content: [{ type: "text" as const, text: JSON.stringify(payload, null, 2) }],
        structuredContent: payload
      };
    }
  );
}
