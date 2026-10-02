import type { McpServer } from "@modelcontextprotocol/server";
import * as z from "zod/v4";
import type { OpsChugexFetcher } from "./opschugex.js";

const http: OpsChugexFetcher = (url, init) => fetch(url, init);

const profileSchema = z.enum(["development", "staging", "production", "regulated"]);
const providerSchema = z.enum(["aws", "azure", "gcp", "kubernetes", "generic"]);
const decisionSchema = z.enum(["pass", "review", "block"]);
const severitySchema = z.enum(["low", "medium", "high", "critical"]);

const resourceSchema = z.object({
  id: z.string().min(1).max(300).describe("Stable resource identifier."),
  provider: providerSchema.describe("Resource platform or provider."),
  resourceType: z.string().min(1).max(300).describe("Resource type such as rds, storage-account, deployment, or generic."),
  environment: z.string().min(1).max(100).describe("Environment associated with the resource."),
  tags: z.record(z.string(), z.string()).optional().describe("Observed resource tags or labels."),
  encryptedAtRest: z.boolean().optional().describe("Observed encryption-at-rest state when known."),
  publicExposure: z.boolean().optional().describe("Whether the resource is publicly reachable when known."),
  iamWildcard: z.boolean().optional().describe("Whether wildcard IAM scope was observed when known."),
  administrativePrivilege: z.boolean().optional().describe("Whether administrative privilege was observed when known."),
  auditLoggingEnabled: z.boolean().optional().describe("Observed audit-logging state when known."),
  stateful: z.boolean().optional().describe("Whether the resource stores durable state."),
  backupsEnabled: z.boolean().optional().describe("Observed backup state for stateful resources when known."),
  deletionProtectionEnabled: z.boolean().optional().describe("Observed deletion-protection state when known.")
});

const exceptionSchema = z.object({
  controlId: z.string().min(1).max(200).describe("Governance control identifier returned by a prior assessment."),
  resourceId: z.string().min(1).max(300).optional().describe("Optional resource-specific exception scope."),
  owner: z.string().min(1).max(200).describe("Accountable owner for the exception."),
  justification: z.string().min(8).max(2000).describe("Business or engineering justification for the exception."),
  expiresAt: z.number().positive().describe("Exception expiration as Unix seconds.")
});

const inputSchema = z.object({
  organization: z.string().min(1).max(300).describe("Organization or business unit being assessed."),
  profile: profileSchema.describe("Governance profile requested from the private OpsChugex policy engine."),
  evaluatedAt: z.number().positive().describe("Assessment time as Unix seconds, used for deterministic exception expiry."),
  resources: z.array(resourceSchema).min(1).max(2000).describe("Bounded factual resource evidence. Do not include credentials or secrets."),
  exceptions: z.array(exceptionSchema).max(500).optional().describe("Optional pre-approved, time-bounded governance exceptions.")
});

const findingSchema = z.object({
  controlId: z.string(),
  resourceId: z.string(),
  severity: severitySchema,
  title: z.string(),
  detail: z.string(),
  exceptionApplied: z.boolean()
});

const outputSchema = z.object({
  organization: z.string(),
  profile: profileSchema,
  decision: decisionSchema,
  score: z.number(),
  controlsEvaluated: z.number(),
  resourcesEvaluated: z.number(),
  findingCount: z.number(),
  blockedFindingCount: z.number(),
  findings: z.array(findingSchema),
  evidenceGaps: z.array(z.string()),
  expiredExceptions: z.array(z.string()),
  summary: z.string()
});

function ensureGovernanceEnabled() {
  if (process.env.CLOUD_DEVOPS_MCP_OPSCHUGEX_GOVERNANCE_ENABLED !== "true") {
    throw new Error("OpsChugex commercial governance intelligence is disabled.");
  }
}

function governanceEndpoint(): string {
  const raw = process.env.CLOUD_DEVOPS_MCP_OPSCHUGEX_GOVERNANCE_URL?.trim();
  if (!raw) {
    throw new Error("CLOUD_DEVOPS_MCP_OPSCHUGEX_GOVERNANCE_URL is required.");
  }

  const url = new URL(raw);
  if (url.username || url.password || url.search || url.hash) {
    throw new Error(
      "OpsChugex governance URL cannot contain credentials, query parameters, or fragments."
    );
  }
  if (
    url.protocol !== "https:" &&
    !(url.protocol === "http:" && ["localhost", "127.0.0.1", "::1"].includes(url.hostname))
  ) {
    throw new Error("OpsChugex governance URL must use HTTPS unless localhost.");
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

export async function requestGovernanceAssessment(
  input: z.infer<typeof inputSchema>,
  fetcher: OpsChugexFetcher = http
) {
  ensureGovernanceEnabled();
  const response = await fetcher(governanceEndpoint(), {
    method: "POST",
    headers: {
      Accept: "application/json",
      "Content-Type": "application/json",
      Authorization: `Bearer ${bearerToken()}`
    },
    body: JSON.stringify(input)
  });

  if (!response.ok) {
    throw new Error(`OpsChugex governance service returned HTTP ${response.status}.`);
  }

  const body = await response.text();
  let parsed: unknown;
  try {
    parsed = JSON.parse(body);
  } catch {
    throw new Error("OpsChugex governance service returned invalid JSON.");
  }
  return outputSchema.parse(parsed);
}

export function registerOpsChugexGovernanceTool(server: McpServer) {
  server.registerTool(
    "assess_governance_policy",
    {
      title: "Assess Governance Policy",
      description:
        "Send bounded resource evidence and optional time-bounded exceptions to the configured private OpsChugex policy service. Returns pass, review, or block with control findings and evidence gaps. The public MCP contains no proprietary policy rules, scoring weights, profile logic, or enforcement capability and accepts no endpoint or credential arguments.",
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
      const payload = await requestGovernanceAssessment(input);
      return {
        content: [{ type: "text" as const, text: JSON.stringify(payload, null, 2) }],
        structuredContent: payload
      };
    }
  );
}
