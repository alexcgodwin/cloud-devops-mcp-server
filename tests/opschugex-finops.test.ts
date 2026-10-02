import { Client, InMemoryTransport } from "@modelcontextprotocol/client";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { createServer } from "../src/index.js";
import { requestAdvancedFinOpsAssessment } from "../src/opschugex-finops.js";
import type { OpsChugexFetcher } from "../src/opschugex.js";

const token = "f".repeat(40);
const endpoint = "https://api.opschugex.com/v1/finops/analyze";

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
    currency: "USD",
    analyzedMonthlyCost: 1000,
    analyzedAnnualCost: 12000,
    estimatedSavings: {
      monthlyLow: 120,
      monthlyHigh: 260,
      annualLow: 1440,
      annualHigh: 3120
    },
    estimatedSavingsPctLow: 12,
    estimatedSavingsPctHigh: 26,
    opportunityCount: 2,
    anomalyCount: 0,
    opportunities: [{
      id: "finops-1",
      type: "rightsize-compute",
      priority: "high",
      confidence: "high",
      resourceIds: ["aws:ec2:api"],
      affectedMonthlyCost: 700,
      savings: {
        monthlyLow: 105,
        monthlyHigh: 245,
        annualLow: 1260,
        annualHigh: 2940
      },
      excludedFromPortfolioSavings: false,
      evidence: ["CPU p95: 25%"],
      rationale: "Capacity headroom is present.",
      recommendedAction: "Test a smaller size."
    }],
    correlations: [],
    evidenceGaps: [],
    summary: "Advanced FinOps assessment."
  };
}

describe("OpsChugex v0.13 advanced FinOps gateway", () => {
  beforeEach(() => {
    process.env.CLOUD_DEVOPS_MCP_OPSCHUGEX_FINOPS_ENABLED = "true";
    process.env.CLOUD_DEVOPS_MCP_OPSCHUGEX_FINOPS_URL = endpoint;
    process.env.CLOUD_DEVOPS_MCP_OPSCHUGEX_TOKEN = token;
    delete process.env.CLOUD_DEVOPS_MCP_OPSCHUGEX_INTELLIGENCE_ENABLED;
    delete process.env.CLOUD_DEVOPS_MCP_OPSCHUGEX_GOVERNANCE_ENABLED;
    delete process.env.CLOUD_DEVOPS_MCP_OPSCHUGEX_SECURITY_ENABLED;
  });

  afterEach(() => {
    vi.unstubAllGlobals();
    delete process.env.CLOUD_DEVOPS_MCP_OPSCHUGEX_FINOPS_ENABLED;
    delete process.env.CLOUD_DEVOPS_MCP_OPSCHUGEX_FINOPS_URL;
    delete process.env.CLOUD_DEVOPS_MCP_OPSCHUGEX_TOKEN;
    delete process.env.CLOUD_DEVOPS_MCP_OPSCHUGEX_INTELLIGENCE_ENABLED;
    delete process.env.CLOUD_DEVOPS_MCP_OPSCHUGEX_GOVERNANCE_ENABLED;
    delete process.env.CLOUD_DEVOPS_MCP_OPSCHUGEX_SECURITY_ENABLED;
  });

  it("forwards bounded FinOps evidence to the private service", async () => {
    let requestedUrl = "";
    let authorization = "";
    const fetcher: OpsChugexFetcher = async (url, init) => {
      requestedUrl = url;
      authorization = init.headers.Authorization;
      expect(JSON.parse(init.body).currency).toBe("USD");
      return response(sampleResult());
    };

    const result = await requestAdvancedFinOpsAssessment({
      organization: "OpsChugex",
      evaluatedAt: 1_800_000_000,
      currency: "USD",
      cloudResources: [{
        id: "aws:ec2:api",
        provider: "aws",
        service: "EC2",
        resourceType: "instance",
        environment: "production",
        monthlyCost: 700,
        cpuP95Pct: 25
      }]
    }, fetcher);

    expect(requestedUrl).toBe(endpoint);
    expect(authorization).toBe(`Bearer ${token}`);
    expect(result.estimatedSavings.monthlyHigh).toBe(260);
  });

  it("fails closed when the FinOps plane is disabled", async () => {
    process.env.CLOUD_DEVOPS_MCP_OPSCHUGEX_FINOPS_ENABLED = "false";

    await expect(requestAdvancedFinOpsAssessment({
      organization: "OpsChugex",
      evaluatedAt: 1000,
      currency: "USD",
      cloudResources: [{
        id: "generic:1",
        provider: "generic",
        service: "compute",
        resourceType: "service",
        environment: "development",
        monthlyCost: 10
      }]
    }, async () => response(sampleResult()))).rejects.toThrow(/disabled/i);
  });

  it("rejects insecure non-loopback FinOps endpoints", async () => {
    process.env.CLOUD_DEVOPS_MCP_OPSCHUGEX_FINOPS_URL =
      "http://api.opschugex.com/v1/finops/analyze";

    await expect(requestAdvancedFinOpsAssessment({
      organization: "OpsChugex",
      evaluatedAt: 1000,
      currency: "USD",
      cloudResources: [{
        id: "generic:1",
        provider: "generic",
        service: "compute",
        resourceType: "service",
        environment: "development",
        monthlyCost: 10
      }]
    }, async () => response(sampleResult()))).rejects.toThrow(/HTTPS/i);
  });

  it("exposes only the FinOps tool when only its gate is enabled", async () => {
    const server = createServer();
    const client = new Client({ name: "finops-test", version: "1.0.0" });
    const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
    await server.connect(serverTransport);
    await client.connect(clientTransport);

    try {
      const { tools } = await client.listTools();
      expect(tools).toHaveLength(13);
      expect(tools.some((item) => item.name === "analyze_advanced_finops")).toBe(true);
      expect(tools.some((item) => item.name === "diagnose_root_cause")).toBe(false);
      expect(tools.some((item) => item.name === "assess_governance_policy")).toBe(false);
      expect(tools.some((item) => item.name === "assess_cloud_security_posture")).toBe(false);

      const tool = tools.find((item) => item.name === "analyze_advanced_finops");
      expect(tool?.annotations?.readOnlyHint).toBe(true);
      expect(tool?.annotations?.destructiveHint).toBe(false);
      expect(tool?.annotations?.idempotentHint).toBe(true);
      expect(tool?.annotations?.openWorldHint).toBe(true);
    } finally {
      await client.close();
      await server.close();
    }
  });

  it("executes the FinOps MCP handler through the configured private gateway", async () => {
    vi.stubGlobal("fetch", async () => response(sampleResult()));

    const server = createServer();
    const client = new Client({ name: "finops-call-test", version: "1.0.0" });
    const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
    await server.connect(serverTransport);
    await client.connect(clientTransport);

    try {
      const result = await client.callTool({
        name: "analyze_advanced_finops",
        arguments: {
          organization: "OpsChugex",
          evaluatedAt: 1_800_000_000,
          currency: "USD",
          cloudResources: [{
            id: "aws:ec2:api",
            provider: "aws",
            service: "EC2",
            resourceType: "instance",
            environment: "production",
            monthlyCost: 700,
            cpuP95Pct: 25
          }]
        }
      });

      expect(result.structuredContent).toMatchObject({
        organization: "OpsChugex",
        currency: "USD",
        opportunityCount: 2
      });
    } finally {
      await client.close();
      await server.close();
    }
  });
});
