import type { McpServer } from "@modelcontextprotocol/server";
import * as z from "zod/v4";
import type { OpsChugexFetcher } from "./opschugex.js";

const http: OpsChugexFetcher = (url, init) => fetch(url, init);

const providerSchema = z.enum(["aws", "azure", "gcp", "kubernetes", "generic"]);
const severitySchema = z.enum(["low", "medium", "high", "critical"]);
const riskLevelSchema = z.enum(["low", "moderate", "high", "critical"]);

const assetSchema = z.object({
  id: z.string().min(1).max(300),
  provider: providerSchema,
  resourceType: z.string().min(1).max(300),
  environment: z.string().min(1).max(100),
  internetExposed: z.boolean().optional(),
  sensitiveData: z.boolean().optional(),
  encryptedAtRest: z.boolean().optional(),
  encryptedInTransit: z.boolean().optional(),
  auditLoggingEnabled: z.boolean().optional(),
  publicStorage: z.boolean().optional(),
  openManagementPort: z.boolean().optional(),
  unrestrictedEgress: z.boolean().optional(),
  privilegedIdentityIds: z.array(z.string().min(1).max(300)).max(100).optional()
});

const identitySchema = z.object({
  id: z.string().min(1).max(300),
  provider: providerSchema,
  principalType: z.enum(["user", "role", "service-account", "managed-identity", "workload"]),
  wildcardPermissions: z.boolean().optional(),
  administrativePrivilege: z.boolean().optional(),
  externalPrincipal: z.boolean().optional(),
  mfaRequired: z.boolean().optional(),
  longLivedCredential: z.boolean().optional(),
  attachedAssetIds: z.array(z.string().min(1).max(300)).max(200).optional()
});

const secretSchema = z.object({
  id: z.string().min(1).max(300),
  resourceId: z.string().min(1).max(300).optional(),
  identityId: z.string().min(1).max(300).optional(),
  secretType: z.enum([
    "api-key",
    "access-key",
    "password",
    "token",
    "private-key",
    "connection-string",
    "other"
  ]),
  location: z.string().min(1).max(1000),
  active: z.boolean().optional(),
  externallyReachable: z.boolean().optional(),
  rotated: z.boolean().optional()
});

const edgeSchema = z.object({
  from: z.string().min(1).max(300),
  to: z.string().min(1).max(300),
  reachable: z.boolean(),
  encryptedInTransit: z.boolean().optional(),
  crossesTrustBoundary: z.boolean().optional()
});

const inputSchema = z.object({
  organization: z.string().min(1).max(300),
  evaluatedAt: z.number().positive(),
  assets: z.array(assetSchema).min(1).max(3000),
  identities: z.array(identitySchema).max(3000).optional(),
  secrets: z.array(secretSchema).max(2000).optional(),
  networkEdges: z.array(edgeSchema).max(10000).optional()
});

const findingSchema = z.object({
  id: z.string(),
  category: z.enum([
    "exposure",
    "encryption",
    "logging",
    "identity",
    "secret",
    "network",
    "data-protection"
  ]),
  severity: severitySchema,
  resourceId: z.string(),
  title: z.string(),
  detail: z.string()
});

const attackPathSchema = z.object({
  id: z.string(),
  severity: severitySchema,
  entryPoint: z.string(),
  target: z.string(),
  nodes: z.array(z.string()),
  evidenceFindingIds: z.array(z.string()),
  rationale: z.string()
});

const outputSchema = z.object({
  organization: z.string(),
  riskLevel: riskLevelSchema,
  securityScore: z.number(),
  assetsEvaluated: z.number(),
  identitiesEvaluated: z.number(),
  secretsEvaluated: z.number(),
  findingCount: z.number(),
  criticalFindingCount: z.number(),
  attackPathCount: z.number(),
  findings: z.array(findingSchema),
  attackPaths: z.array(attackPathSchema),
  evidenceGaps: z.array(z.string()),
  recommendations: z.array(z.string())
});

function ensureEnabled() {
  if (process.env.CLOUD_DEVOPS_MCP_OPSCHUGEX_SECURITY_ENABLED !== "true") {
    throw new Error("OpsChugex commercial security posture intelligence is disabled.");
  }
}

function endpoint(): string {
  const raw = process.env.CLOUD_DEVOPS_MCP_OPSCHUGEX_SECURITY_URL?.trim();
  if (!raw) throw new Error("CLOUD_DEVOPS_MCP_OPSCHUGEX_SECURITY_URL is required.");

  const url = new URL(raw);
  if (url.username || url.password || url.search || url.hash) {
    throw new Error("OpsChugex security URL cannot contain credentials, query parameters, or fragments.");
  }
  if (
    url.protocol !== "https:" &&
    !(url.protocol === "http:" && ["localhost", "127.0.0.1", "::1"].includes(url.hostname))
  ) {
    throw new Error("OpsChugex security URL must use HTTPS unless localhost.");
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

export async function requestSecurityPostureAssessment(
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
    throw new Error(`OpsChugex security posture service returned HTTP ${response.status}.`);
  }

  const body = await response.text();
  let parsed: unknown;
  try {
    parsed = JSON.parse(body);
  } catch {
    throw new Error("OpsChugex security posture service returned invalid JSON.");
  }
  return outputSchema.parse(parsed);
}

export function registerOpsChugexSecurityPostureTool(server: McpServer) {
  server.registerTool(
    "assess_cloud_security_posture",
    {
      title: "Assess Cloud Security Posture",
      description:
        "Send bounded cloud, identity, secret and network evidence to the configured private OpsChugex security service. Returns risk level, security score, ordered findings, attack paths, evidence gaps and recommendations. The public MCP contains no proprietary detection thresholds, attack-path algorithm, scoring rules or remediation logic and accepts no endpoint or credential arguments.",
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
      const payload = await requestSecurityPostureAssessment(input);
      return {
        content: [{ type: "text" as const, text: JSON.stringify(payload, null, 2) }],
        structuredContent: payload
      };
    }
  );
}
