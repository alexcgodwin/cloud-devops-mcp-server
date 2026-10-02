import { Client, InMemoryTransport } from "@modelcontextprotocol/client";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { createServer } from "../src/index.js";
import { requestChangeBlastRadiusAssessment } from "../src/opschugex-change-intelligence.js";
import type { OpsChugexFetcher } from "../src/opschugex.js";

const token = "c".repeat(40);
const endpoint = "https://api.opschugex.com/v1/change/blast-radius";

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
    organization: "OpsChugex",
    changeId: "chg-001",
    environment: "production",
    riskLevel: "critical",
    riskScore: 91,
    directTargetCount: 1,
    impactedNodeCount: 3,
    criticalImpactCount: 2,
    customerFacingImpactCount: 2,
    environmentsAffected: ["production"],
    blockers: [{
      id: "blocker-stateful-rollback-change-db",
      severity: "critical",
      reason: "Rollback evidence is missing.",
      relatedChangeItemIds: ["change-db"],
      relatedNodeIds: ["db:orders"]
    }],
    warnings: ["2 critical topology node(s) are inside the predicted blast radius."],
    evidenceGaps: [],
    impactedNodes: [{
      id: "db:orders",
      environment: "production",
      kind: "datastore",
      criticality: "critical",
      direct: true,
      minimumDepth: 0,
      customerFacing: false,
      stateful: true,
      changeItemIds: ["change-db"],
      representativePath: ["db:orders"]
    }],
    blastPaths: [{
      changeItemId: "change-db",
      targetId: "db:orders",
      affectedNodeId: "service:checkout",
      depth: 1,
      nodes: ["db:orders", "service:checkout"]
    }],
    recommendations: ["Resolve all blockers before approving the change for execution."],
    summary: "Critical blast-radius risk."
  };
}

describe("OpsChugex v0.14 change-intelligence gateway", () => {
  beforeEach(() => {
    process.env.CLOUD_DEVOPS_MCP_OPSCHUGEX_CHANGE_INTELLIGENCE_ENABLED = "true";
    process.env.CLOUD_DEVOPS_MCP_OPSCHUGEX_CHANGE_INTELLIGENCE_URL = endpoint;
    process.env.CLOUD_DEVOPS_MCP_OPSCHUGEX_TOKEN = token;
    delete process.env.CLOUD_DEVOPS_MCP_OPSCHUGEX_INTELLIGENCE_ENABLED;
    delete process.env.CLOUD_DEVOPS_MCP_OPSCHUGEX_GOVERNANCE_ENABLED;
    delete process.env.CLOUD_DEVOPS_MCP_OPSCHUGEX_SECURITY_ENABLED;
    delete process.env.CLOUD_DEVOPS_MCP_OPSCHUGEX_FINOPS_ENABLED;
  });

  afterEach(() => {
    vi.unstubAllGlobals();
    delete process.env.CLOUD_DEVOPS_MCP_OPSCHUGEX_CHANGE_INTELLIGENCE_ENABLED;
    delete process.env.CLOUD_DEVOPS_MCP_OPSCHUGEX_CHANGE_INTELLIGENCE_URL;
    delete process.env.CLOUD_DEVOPS_MCP_OPSCHUGEX_TOKEN;
    delete process.env.CLOUD_DEVOPS_MCP_OPSCHUGEX_INTELLIGENCE_ENABLED;
    delete process.env.CLOUD_DEVOPS_MCP_OPSCHUGEX_GOVERNANCE_ENABLED;
    delete process.env.CLOUD_DEVOPS_MCP_OPSCHUGEX_SECURITY_ENABLED;
    delete process.env.CLOUD_DEVOPS_MCP_OPSCHUGEX_FINOPS_ENABLED;
  });

  it("forwards bounded change evidence to the private service", async () => {
    let requestedUrl = "";
    let authorization = "";
    const fetcher: OpsChugexFetcher = async (url, init) => {
      requestedUrl = url;
      authorization = init.headers.Authorization;
      expect(JSON.parse(init.body).changeId).toBe("chg-001");
      return response(sampleResult());
    };

    const result = await requestChangeBlastRadiusAssessment({
      organization: "OpsChugex",
      evaluatedAt: 1_800_000_000,
      changeId: "chg-001",
      environment: "production",
      items: [{
        id: "change-db",
        targetId: "db:orders",
        domain: "terraform",
        action: "replace",
        destructive: true,
        stateful: true
      }],
      topologyNodes: [{
        id: "db:orders",
        kind: "datastore",
        environment: "production",
        criticality: "critical",
        stateful: true
      }]
    }, fetcher);

    expect(requestedUrl).toBe(endpoint);
    expect(authorization).toBe(`Bearer ${token}`);
    expect(result.riskLevel).toBe("critical");
  });

  it("fails closed when the change-intelligence plane is disabled", async () => {
    process.env.CLOUD_DEVOPS_MCP_OPSCHUGEX_CHANGE_INTELLIGENCE_ENABLED = "false";

    await expect(requestChangeBlastRadiusAssessment({
      organization: "OpsChugex",
      evaluatedAt: 1000,
      changeId: "chg-disabled",
      environment: "development",
      items: [{
        id: "change",
        targetId: "service:api",
        domain: "application",
        action: "config-change"
      }],
      topologyNodes: [{
        id: "service:api",
        kind: "service",
        environment: "development",
        criticality: "low"
      }]
    }, async () => response(sampleResult()))).rejects.toThrow(/disabled/i);
  });

  it("rejects insecure non-loopback change-intelligence endpoints", async () => {
    process.env.CLOUD_DEVOPS_MCP_OPSCHUGEX_CHANGE_INTELLIGENCE_URL =
      "http://api.opschugex.com/v1/change/blast-radius";

    await expect(requestChangeBlastRadiusAssessment({
      organization: "OpsChugex",
      evaluatedAt: 1000,
      changeId: "chg-insecure",
      environment: "development",
      items: [{
        id: "change",
        targetId: "service:api",
        domain: "application",
        action: "update"
      }],
      topologyNodes: [{
        id: "service:api",
        kind: "service",
        environment: "development",
        criticality: "low"
      }]
    }, async () => response(sampleResult()))).rejects.toThrow(/HTTPS/i);
  });

  it("exposes only the change tool when only its gate is enabled", async () => {
    const server = createServer();
    const client = new Client({ name: "change-test", version: "1.0.0" });
    const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
    await server.connect(serverTransport);
    await client.connect(clientTransport);

    try {
      const { tools } = await client.listTools();
      expect(tools).toHaveLength(13);
      expect(tools.some((item) => item.name === "analyze_change_blast_radius")).toBe(true);
      expect(tools.some((item) => item.name === "analyze_advanced_finops")).toBe(false);
      expect(tools.some((item) => item.name === "assess_cloud_security_posture")).toBe(false);

      const tool = tools.find((item) => item.name === "analyze_change_blast_radius");
      expect(tool?.annotations?.readOnlyHint).toBe(true);
      expect(tool?.annotations?.destructiveHint).toBe(false);
      expect(tool?.annotations?.idempotentHint).toBe(true);
      expect(tool?.annotations?.openWorldHint).toBe(true);
    } finally {
      await client.close();
      await server.close();
    }
  });

  it("executes the change MCP handler through the configured private gateway", async () => {
    vi.stubGlobal("fetch", async () => response(sampleResult()));

    const server = createServer();
    const client = new Client({ name: "change-call-test", version: "1.0.0" });
    const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
    await server.connect(serverTransport);
    await client.connect(clientTransport);

    try {
      const result = await client.callTool({
        name: "analyze_change_blast_radius",
        arguments: {
          organization: "OpsChugex",
          evaluatedAt: 1_800_000_000,
          changeId: "chg-001",
          environment: "production",
          items: [{
            id: "change-db",
            targetId: "db:orders",
            domain: "terraform",
            action: "replace",
            destructive: true,
            stateful: true
          }],
          topologyNodes: [{
            id: "db:orders",
            kind: "datastore",
            environment: "production",
            criticality: "critical",
            stateful: true
          }]
        }
      });

      expect(result.structuredContent).toMatchObject({
        organization: "OpsChugex",
        changeId: "chg-001",
        riskLevel: "critical"
      });
    } finally {
      await client.close();
      await server.close();
    }
  });
});
