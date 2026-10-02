import type { McpServer } from "@modelcontextprotocol/server";
import * as z from "zod/v4";
import type { OpsChugexFetcher } from "./opschugex.js";

const http: OpsChugexFetcher = (url, init) => fetch(url, init);

const providerSchema = z.enum(["aws", "azure", "gcp", "generic"]);
const confidenceSchema = z.enum(["low", "medium", "high"]);
const prioritySchema = z.enum(["low", "medium", "high", "critical"]);
const opportunityTypeSchema = z.enum([
  "idle-resource",
  "rightsize-compute",
  "storage-optimization",
  "cost-anomaly",
  "commitment-coverage",
  "spot-candidate",
  "kubernetes-overrequest",
  "cost-allocation"
]);

const cloudResourceSchema = z.object({
  id: z.string().min(1).max(300),
  provider: providerSchema,
  service: z.string().min(1).max(300),
  resourceType: z.string().min(1).max(300),
  environment: z.string().min(1).max(100),
  monthlyCost: z.number().nonnegative(),
  previousMonthlyCost: z.number().nonnegative().optional(),
  cpuAvgPct: z.number().min(0).max(100).optional(),
  cpuP95Pct: z.number().min(0).max(100).optional(),
  memoryAvgPct: z.number().min(0).max(100).optional(),
  memoryP95Pct: z.number().min(0).max(100).optional(),
  storageUtilizationPct: z.number().min(0).max(100).optional(),
  idleHours30d: z.number().nonnegative().max(744).optional(),
  commitmentEligible: z.boolean().optional(),
  commitmentCoveragePct: z.number().min(0).max(100).optional(),
  steadyUsageDays30: z.number().nonnegative().max(30).optional(),
  spotEligible: z.boolean().optional(),
  productionCritical: z.boolean().optional(),
  stateful: z.boolean().optional(),
  tags: z.record(z.string(), z.string()).optional()
});

const kubernetesWorkloadSchema = z.object({
  id: z.string().min(1).max(300),
  clusterId: z.string().min(1).max(300),
  namespace: z.string().min(1).max(300),
  workload: z.string().min(1).max(300),
  environment: z.string().min(1).max(100),
  monthlyCost: z.number().nonnegative(),
  requestedCpuMillicores: z.number().nonnegative().optional(),
  usedCpuP95Millicores: z.number().nonnegative().optional(),
  requestedMemoryMiB: z.number().nonnegative().optional(),
  usedMemoryP95MiB: z.number().nonnegative().optional(),
  replicas: z.number().int().nonnegative().optional(),
  hpaEnabled: z.boolean().optional(),
  productionCritical: z.boolean().optional(),
  linkedCloudResourceIds: z.array(z.string().min(1).max(300)).max(200).optional()
});

const inputSchema = z.object({
  organization: z.string().min(1).max(300),
  evaluatedAt: z.number().positive(),
  currency: z.string().regex(/^[A-Z]{3}$/),
  cloudResources: z.array(cloudResourceSchema).max(5000),
  kubernetesWorkloads: z.array(kubernetesWorkloadSchema).max(5000).optional()
}).refine(
  (value) => value.cloudResources.length > 0 || (value.kubernetesWorkloads?.length ?? 0) > 0,
  { message: "at least one cloud resource or Kubernetes workload is required" }
);

const savingsSchema = z.object({
  monthlyLow: z.number(),
  monthlyHigh: z.number(),
  annualLow: z.number(),
  annualHigh: z.number()
});

const opportunitySchema = z.object({
  id: z.string(),
  type: opportunityTypeSchema,
  priority: prioritySchema,
  confidence: confidenceSchema,
  resourceIds: z.array(z.string()),
  affectedMonthlyCost: z.number(),
  savings: savingsSchema,
  excludedFromPortfolioSavings: z.boolean(),
  evidence: z.array(z.string()),
  rationale: z.string(),
  recommendedAction: z.string()
});

const correlationSchema = z.object({
  kubernetesWorkloadId: z.string(),
  linkedCloudResourceIds: z.array(z.string()),
  portfolioSavingsDeduplicated: z.boolean(),
  detail: z.string()
});

const outputSchema = z.object({
  organization: z.string(),
  currency: z.string(),
  analyzedMonthlyCost: z.number(),
  analyzedAnnualCost: z.number(),
  estimatedSavings: savingsSchema,
  estimatedSavingsPctLow: z.number(),
  estimatedSavingsPctHigh: z.number(),
  opportunityCount: z.number(),
  anomalyCount: z.number(),
  opportunities: z.array(opportunitySchema),
  correlations: z.array(correlationSchema),
  evidenceGaps: z.array(z.string()),
  summary: z.string()
});

function ensureEnabled() {
  if (process.env.CLOUD_DEVOPS_MCP_OPSCHUGEX_FINOPS_ENABLED !== "true") {
    throw new Error("OpsChugex commercial advanced FinOps intelligence is disabled.");
  }
}

function endpoint(): string {
  const raw = process.env.CLOUD_DEVOPS_MCP_OPSCHUGEX_FINOPS_URL?.trim();
  if (!raw) throw new Error("CLOUD_DEVOPS_MCP_OPSCHUGEX_FINOPS_URL is required.");

  const url = new URL(raw);
  if (url.username || url.password || url.search || url.hash) {
    throw new Error("OpsChugex FinOps URL cannot contain credentials, query parameters, or fragments.");
  }
  if (
    url.protocol !== "https:" &&
    !(url.protocol === "http:" && ["localhost", "127.0.0.1", "::1"].includes(url.hostname))
  ) {
    throw new Error("OpsChugex FinOps URL must use HTTPS unless localhost.");
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

export async function requestAdvancedFinOpsAssessment(
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
    throw new Error(`OpsChugex FinOps service returned HTTP ${response.status}.`);
  }

  const body = await response.text();
  let parsed: unknown;
  try {
    parsed = JSON.parse(body);
  } catch {
    throw new Error("OpsChugex FinOps service returned invalid JSON.");
  }
  return outputSchema.parse(parsed);
}

export function registerOpsChugexFinOpsTool(server: McpServer) {
  server.registerTool(
    "analyze_advanced_finops",
    {
      title: "Analyze Advanced FinOps",
      description:
        "Send bounded cloud-cost, utilization and Kubernetes allocation evidence to the configured private OpsChugex FinOps service. Returns optimization opportunities, cost anomalies, low/high savings ranges, confidence, cost correlations and evidence gaps. The public MCP contains no proprietary savings factors, anomaly thresholds, prioritization or deduplication logic and accepts no endpoint or credential arguments.",
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
      const payload = await requestAdvancedFinOpsAssessment(input);
      return {
        content: [{ type: "text" as const, text: JSON.stringify(payload, null, 2) }],
        structuredContent: payload
      };
    }
  );
}
