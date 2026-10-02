import type { McpServer } from "@modelcontextprotocol/server";
import * as z from "zod/v4";
import type { OpsChugexFetcher } from "./opschugex.js";

const http: OpsChugexFetcher = (url, init) => fetch(url, init);

const changeDomainSchema = z.enum([
  "terraform",
  "kubernetes",
  "ci_cd",
  "cloud",
  "application"
]);

const changeActionSchema = z.enum([
  "create",
  "update",
  "delete",
  "replace",
  "scale",
  "policy-change",
  "network-change",
  "image-change",
  "config-change"
]);

const criticalitySchema = z.enum(["low", "medium", "high", "critical"]);
const riskLevelSchema = z.enum(["low", "moderate", "high", "critical"]);

const changeItemSchema = z.object({
  id: z.string().min(1).max(300),
  targetId: z.string().min(1).max(300),
  domain: changeDomainSchema,
  action: changeActionSchema,
  destructive: z.boolean().optional(),
  stateful: z.boolean().optional(),
  iamChange: z.boolean().optional(),
  networkChange: z.boolean().optional(),
  publicExposureChange: z.boolean().optional(),
  dataPlaneChange: z.boolean().optional(),
  requiresRestart: z.boolean().optional(),
  summary: z.string().max(2000).optional()
});

const topologyNodeSchema = z.object({
  id: z.string().min(1).max(300),
  kind: z.enum([
    "service",
    "resource",
    "datastore",
    "identity",
    "network",
    "pipeline",
    "cluster",
    "namespace",
    "external"
  ]),
  environment: z.string().min(1).max(100),
  criticality: criticalitySchema,
  stateful: z.boolean().optional(),
  customerFacing: z.boolean().optional(),
  owner: z.string().max(300).optional()
});

const topologyEdgeSchema = z.object({
  from: z.string().min(1).max(300),
  to: z.string().min(1).max(300),
  relation: z.enum([
    "depends-on",
    "routes-to",
    "reads-from",
    "writes-to",
    "authenticates-with",
    "deploys-to",
    "contains",
    "network-path"
  ]),
  propagatesChange: z.boolean().optional()
});

const readinessSchema = z.object({
  hasRollbackPlan: z.boolean().optional(),
  rollbackTested: z.boolean().optional(),
  hasPeerReview: z.boolean().optional(),
  hasAutomatedTests: z.boolean().optional(),
  maintenanceWindowApproved: z.boolean().optional(),
  monitoringReady: z.boolean().optional()
});

const inputSchema = z.object({
  organization: z.string().min(1).max(300),
  evaluatedAt: z.number().positive(),
  changeId: z.string().min(1).max(300),
  environment: z.string().min(1).max(100),
  items: z.array(changeItemSchema).min(1).max(1000),
  topologyNodes: z.array(topologyNodeSchema).min(1).max(5000),
  topologyEdges: z.array(topologyEdgeSchema).max(15000).optional(),
  readiness: readinessSchema.optional()
});

const impactedNodeSchema = z.object({
  id: z.string(),
  environment: z.string(),
  kind: z.enum([
    "service",
    "resource",
    "datastore",
    "identity",
    "network",
    "pipeline",
    "cluster",
    "namespace",
    "external"
  ]),
  criticality: criticalitySchema,
  direct: z.boolean(),
  minimumDepth: z.number().int().nonnegative(),
  customerFacing: z.boolean(),
  stateful: z.boolean(),
  changeItemIds: z.array(z.string()),
  representativePath: z.array(z.string())
});

const blastPathSchema = z.object({
  changeItemId: z.string(),
  targetId: z.string(),
  affectedNodeId: z.string(),
  depth: z.number().int().nonnegative(),
  nodes: z.array(z.string())
});

const blockerSchema = z.object({
  id: z.string(),
  severity: z.enum(["high", "critical"]),
  reason: z.string(),
  relatedChangeItemIds: z.array(z.string()),
  relatedNodeIds: z.array(z.string())
});

const outputSchema = z.object({
  organization: z.string(),
  changeId: z.string(),
  environment: z.string(),
  riskLevel: riskLevelSchema,
  riskScore: z.number(),
  directTargetCount: z.number(),
  impactedNodeCount: z.number(),
  criticalImpactCount: z.number(),
  customerFacingImpactCount: z.number(),
  environmentsAffected: z.array(z.string()),
  blockers: z.array(blockerSchema),
  warnings: z.array(z.string()),
  evidenceGaps: z.array(z.string()),
  impactedNodes: z.array(impactedNodeSchema),
  blastPaths: z.array(blastPathSchema),
  recommendations: z.array(z.string()),
  summary: z.string()
});

function ensureEnabled() {
  if (process.env.CLOUD_DEVOPS_MCP_OPSCHUGEX_CHANGE_INTELLIGENCE_ENABLED !== "true") {
    throw new Error("OpsChugex commercial change intelligence is disabled.");
  }
}

function endpoint(): string {
  const raw = process.env.CLOUD_DEVOPS_MCP_OPSCHUGEX_CHANGE_INTELLIGENCE_URL?.trim();
  if (!raw) {
    throw new Error("CLOUD_DEVOPS_MCP_OPSCHUGEX_CHANGE_INTELLIGENCE_URL is required.");
  }

  const url = new URL(raw);
  if (url.username || url.password || url.search || url.hash) {
    throw new Error(
      "OpsChugex change-intelligence URL cannot contain credentials, query parameters, or fragments."
    );
  }
  if (
    url.protocol !== "https:" &&
    !(url.protocol === "http:" && ["localhost", "127.0.0.1", "::1"].includes(url.hostname))
  ) {
    throw new Error("OpsChugex change-intelligence URL must use HTTPS unless localhost.");
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

export async function requestChangeBlastRadiusAssessment(
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
    throw new Error(
      `OpsChugex change-intelligence service returned HTTP ${response.status}.`
    );
  }

  const body = await response.text();
  let parsed: unknown;
  try {
    parsed = JSON.parse(body);
  } catch {
    throw new Error("OpsChugex change-intelligence service returned invalid JSON.");
  }
  return outputSchema.parse(parsed);
}

export function registerOpsChugexChangeIntelligenceTool(server: McpServer) {
  server.registerTool(
    "analyze_change_blast_radius",
    {
      title: "Analyze Change Blast Radius",
      description:
        "Send bounded planned-change, topology and readiness evidence to the configured private OpsChugex change-intelligence service. Returns change risk, impacted topology nodes, representative blast paths, blockers, warnings and evidence gaps. The public MCP contains no proprietary dependency-propagation algorithm, risk weights or blocker rules and accepts no endpoint or credential arguments.",
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
      const payload = await requestChangeBlastRadiusAssessment(input);
      return {
        content: [{ type: "text" as const, text: JSON.stringify(payload, null, 2) }],
        structuredContent: payload
      };
    }
  );
}
