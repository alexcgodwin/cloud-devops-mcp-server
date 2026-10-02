import { Client, InMemoryTransport } from "@modelcontextprotocol/client";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { createServer } from "../src/index.js";
import { requestRootCauseDiagnosis, type OpsChugexFetcher } from "../src/opschugex.js";

const token = "x".repeat(40);
const endpoint = "https://api.opschugex.com/v1/root-cause/diagnose";

function response(payload: unknown, status = 200) {
  return {
    ok: status >= 200 && status < 300,
    status,
    async text() {
      return JSON.stringify(payload);
    }
  };
}

function sampleResult() {
  return {
    service: "checkout",
    assessment: "strong",
    evidenceDomainCount: 4,
    rankedCauses: [{
      rank: 1,
      causeType: "deployment_regression",
      title: "Recent deployment or release regression",
      evidenceScore: 88,
      confidence: "strong",
      supportingEvidenceIds: ["ci-1", "k8s-1", "trace-1"],
      contradictingEvidenceIds: [],
      supportingDomains: ["ci_cd", "kubernetes", "traces"],
      reasoningSummary: "Cross-domain evidence supports the hypothesis.",
      nextChecks: ["Validate with rollback or safe canary."]
    }],
    limitations: ["Correlation does not prove causation."]
  };
}

describe("OpsChugex v0.10 commercial root-cause gateway", () => {
  beforeEach(() => {
    process.env.CLOUD_DEVOPS_MCP_OPSCHUGEX_INTELLIGENCE_ENABLED = "true";
    process.env.CLOUD_DEVOPS_MCP_OPSCHUGEX_ROOT_CAUSE_URL = endpoint;
    process.env.CLOUD_DEVOPS_MCP_OPSCHUGEX_TOKEN = token;
  });

  afterEach(() => {
    delete process.env.CLOUD_DEVOPS_MCP_OPSCHUGEX_INTELLIGENCE_ENABLED;
    delete process.env.CLOUD_DEVOPS_MCP_OPSCHUGEX_ROOT_CAUSE_URL;
    delete process.env.CLOUD_DEVOPS_MCP_OPSCHUGEX_TOKEN;
  });

  it("sends bounded evidence to the configured private service", async () => {
    let requestedUrl = "";
    let authorization = "";
    const fetcher: OpsChugexFetcher = async (url, init) => {
      requestedUrl = url;
      authorization = init.headers.Authorization;
      expect(JSON.parse(init.body).incident.service).toBe("checkout");
      return response(sampleResult());
    };

    const result = await requestRootCauseDiagnosis({
      incident: { service: "checkout", startedAt: 1_800_000_000 },
      evidence: [{
        id: "ci-1",
        domain: "ci_cd",
        observedAt: 1_800_000_001,
        entity: "checkout",
        signal: "deployment",
        state: "abnormal",
        severity: "high",
        summary: "A new deployment preceded the incident."
      }]
    }, fetcher);

    expect(requestedUrl).toBe(endpoint);
    expect(authorization).toBe(`Bearer ${token}`);
    expect(result.rankedCauses[0]?.causeType).toBe("deployment_regression");
  });

  it("fails closed when the commercial plane is disabled", async () => {
    process.env.CLOUD_DEVOPS_MCP_OPSCHUGEX_INTELLIGENCE_ENABLED = "false";
    await expect(requestRootCauseDiagnosis({
      incident: { service: "api", startedAt: 1000 },
      evidence: []
    }, async () => response(sampleResult()))).rejects.toThrow(/disabled/i);
  });

  it("rejects insecure remote endpoints", async () => {
    process.env.CLOUD_DEVOPS_MCP_OPSCHUGEX_ROOT_CAUSE_URL =
      "http://api.opschugex.com/v1/root-cause/diagnose";
    await expect(requestRootCauseDiagnosis({
      incident: { service: "api", startedAt: 1000 },
      evidence: []
    }, async () => response(sampleResult()))).rejects.toThrow(/HTTPS/i);
  });

  it("exposes one additional tool only when explicitly enabled", async () => {
    const server = createServer();
    const client = new Client({ name: "opschugex-test", version: "1.0.0" });
    const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
    await server.connect(serverTransport);
    await client.connect(clientTransport);

    try {
      const { tools } = await client.listTools();
      expect(tools).toHaveLength(13);
      const tool = tools.find((item) => item.name === "diagnose_root_cause");
      expect(tool).toBeDefined();
      expect(tool?.annotations?.readOnlyHint).toBe(true);
      expect(tool?.annotations?.destructiveHint).toBe(false);
      expect(tool?.annotations?.idempotentHint).toBe(true);
      expect(tool?.annotations?.openWorldHint).toBe(true);
    } finally {
      await client.close();
      await server.close();
    }
  });
});
