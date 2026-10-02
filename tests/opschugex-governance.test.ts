import { Client, InMemoryTransport } from "@modelcontextprotocol/client";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { createServer } from "../src/index.js";
import {
  requestGovernanceAssessment
} from "../src/opschugex-governance.js";
import type { OpsChugexFetcher } from "../src/opschugex.js";

const token = "g".repeat(40);
const endpoint = "https://api.opschugex.com/v1/governance/assess";

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
    profile: "production",
    decision: "block",
    score: 75,
    controlsEvaluated: 10,
    resourcesEvaluated: 1,
    findingCount: 1,
    blockedFindingCount: 1,
    findings: [{
      controlId: "network.public_exposure",
      resourceId: "aws:alb:public",
      severity: "high",
      title: "Public exposure violates the selected profile",
      detail: "The resource is publicly exposed.",
      exceptionApplied: false
    }],
    evidenceGaps: [],
    expiredExceptions: [],
    summary: "production governance assessment: block."
  };
}

describe("OpsChugex v0.11 governance gateway", () => {
  beforeEach(() => {
    process.env.CLOUD_DEVOPS_MCP_OPSCHUGEX_GOVERNANCE_ENABLED = "true";
    process.env.CLOUD_DEVOPS_MCP_OPSCHUGEX_GOVERNANCE_URL = endpoint;
    process.env.CLOUD_DEVOPS_MCP_OPSCHUGEX_TOKEN = token;
    delete process.env.CLOUD_DEVOPS_MCP_OPSCHUGEX_INTELLIGENCE_ENABLED;
  });

  afterEach(() => {
    vi.unstubAllGlobals();
    delete process.env.CLOUD_DEVOPS_MCP_OPSCHUGEX_GOVERNANCE_ENABLED;
    delete process.env.CLOUD_DEVOPS_MCP_OPSCHUGEX_GOVERNANCE_URL;
    delete process.env.CLOUD_DEVOPS_MCP_OPSCHUGEX_TOKEN;
    delete process.env.CLOUD_DEVOPS_MCP_OPSCHUGEX_INTELLIGENCE_ENABLED;
    delete process.env.CLOUD_DEVOPS_MCP_OPSCHUGEX_ROOT_CAUSE_URL;
  });

  it("forwards bounded governance evidence to the private service", async () => {
    let requestedUrl = "";
    let authorization = "";
    const fetcher: OpsChugexFetcher = async (url, init) => {
      requestedUrl = url;
      authorization = init.headers.Authorization;
      expect(JSON.parse(init.body).profile).toBe("production");
      return response(sampleResult());
    };

    const result = await requestGovernanceAssessment({
      organization: "OpsChugex",
      profile: "production",
      evaluatedAt: 1_800_000_000,
      resources: [{
        id: "aws:alb:public",
        provider: "aws",
        resourceType: "application-load-balancer",
        environment: "production",
        publicExposure: true
      }]
    }, fetcher);

    expect(requestedUrl).toBe(endpoint);
    expect(authorization).toBe(`Bearer ${token}`);
    expect(result.decision).toBe("block");
  });

  it("fails closed when governance is disabled", async () => {
    process.env.CLOUD_DEVOPS_MCP_OPSCHUGEX_GOVERNANCE_ENABLED = "false";

    await expect(requestGovernanceAssessment({
      organization: "OpsChugex",
      profile: "production",
      evaluatedAt: 1000,
      resources: [{
        id: "generic:1",
        provider: "generic",
        resourceType: "service",
        environment: "production"
      }]
    }, async () => response(sampleResult()))).rejects.toThrow(/disabled/i);
  });

  it("rejects insecure non-loopback governance endpoints", async () => {
    process.env.CLOUD_DEVOPS_MCP_OPSCHUGEX_GOVERNANCE_URL =
      "http://api.opschugex.com/v1/governance/assess";

    await expect(requestGovernanceAssessment({
      organization: "OpsChugex",
      profile: "production",
      evaluatedAt: 1000,
      resources: [{
        id: "generic:1",
        provider: "generic",
        resourceType: "service",
        environment: "production"
      }]
    }, async () => response(sampleResult()))).rejects.toThrow(/HTTPS/i);
  });

  it("exposes only the governance tool when only its gate is enabled", async () => {
    const server = createServer();
    const client = new Client({ name: "governance-test", version: "1.0.0" });
    const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
    await server.connect(serverTransport);
    await client.connect(clientTransport);

    try {
      const { tools } = await client.listTools();
      expect(tools).toHaveLength(13);
      expect(tools.some((item) => item.name === "assess_governance_policy")).toBe(true);
      expect(tools.some((item) => item.name === "diagnose_root_cause")).toBe(false);

      const tool = tools.find((item) => item.name === "assess_governance_policy");
      expect(tool?.annotations?.readOnlyHint).toBe(true);
      expect(tool?.annotations?.destructiveHint).toBe(false);
      expect(tool?.annotations?.idempotentHint).toBe(true);
      expect(tool?.annotations?.openWorldHint).toBe(true);
    } finally {
      await client.close();
      await server.close();
    }
  });

  it("executes the governance MCP handler through the configured private gateway", async () => {
    vi.stubGlobal("fetch", async () => response(sampleResult()));

    const server = createServer();
    const client = new Client({ name: "governance-call-test", version: "1.0.0" });
    const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
    await server.connect(serverTransport);
    await client.connect(clientTransport);

    try {
      const result = await client.callTool({
        name: "assess_governance_policy",
        arguments: {
          organization: "OpsChugex",
          profile: "production",
          evaluatedAt: 1_800_000_000,
          resources: [{
            id: "aws:alb:public",
            provider: "aws",
            resourceType: "application-load-balancer",
            environment: "production",
            publicExposure: true
          }]
        }
      });

      expect(result.structuredContent).toMatchObject({
        organization: "OpsChugex",
        profile: "production",
        decision: "block"
      });
    } finally {
      await client.close();
      await server.close();
    }
  });

  it("exposes both private-service gateways when both gates are enabled", async () => {
    process.env.CLOUD_DEVOPS_MCP_OPSCHUGEX_INTELLIGENCE_ENABLED = "true";
    process.env.CLOUD_DEVOPS_MCP_OPSCHUGEX_ROOT_CAUSE_URL =
      "https://api.opschugex.com/v1/root-cause/diagnose";

    const server = createServer();
    const client = new Client({ name: "combined-commercial-test", version: "1.0.0" });
    const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
    await server.connect(serverTransport);
    await client.connect(clientTransport);

    try {
      const { tools } = await client.listTools();
      expect(tools).toHaveLength(14);
      expect(tools.some((item) => item.name === "assess_governance_policy")).toBe(true);
      expect(tools.some((item) => item.name === "diagnose_root_cause")).toBe(true);
    } finally {
      await client.close();
      await server.close();
    }
  });
});
