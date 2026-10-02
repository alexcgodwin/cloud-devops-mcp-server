import { Client, InMemoryTransport } from "@modelcontextprotocol/client";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { createServer } from "../src/index.js";
import { requestSecurityPostureAssessment } from "../src/opschugex-security.js";
import type { OpsChugexFetcher } from "../src/opschugex.js";

const token = "s".repeat(40);
const endpoint = "https://api.opschugex.com/v1/security/posture";

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
    riskLevel: "critical",
    securityScore: 25,
    assetsEvaluated: 2,
    identitiesEvaluated: 1,
    secretsEvaluated: 1,
    findingCount: 4,
    criticalFindingCount: 2,
    attackPathCount: 1,
    findings: [{
      id: "exposure.internet:aws:alb:public",
      category: "exposure",
      severity: "high",
      resourceId: "aws:alb:public",
      title: "Internet-exposed resource",
      detail: "aws:alb:public is reachable from the public internet."
    }],
    attackPaths: [{
      id: "attack-path-1",
      severity: "critical",
      entryPoint: "aws:alb:public",
      target: "aws:rds:orders",
      nodes: ["aws:alb:public", "aws:rds:orders"],
      evidenceFindingIds: ["exposure.internet:aws:alb:public"],
      rationale: "Internet-exposed entry point has a reachable path to sensitive data."
    }],
    evidenceGaps: [],
    recommendations: ["Break correlated attack paths."]
  };
}

describe("OpsChugex v0.12 security posture gateway", () => {
  beforeEach(() => {
    process.env.CLOUD_DEVOPS_MCP_OPSCHUGEX_SECURITY_ENABLED = "true";
    process.env.CLOUD_DEVOPS_MCP_OPSCHUGEX_SECURITY_URL = endpoint;
    process.env.CLOUD_DEVOPS_MCP_OPSCHUGEX_TOKEN = token;
    delete process.env.CLOUD_DEVOPS_MCP_OPSCHUGEX_INTELLIGENCE_ENABLED;
    delete process.env.CLOUD_DEVOPS_MCP_OPSCHUGEX_GOVERNANCE_ENABLED;
  });

  afterEach(() => {
    vi.unstubAllGlobals();
    delete process.env.CLOUD_DEVOPS_MCP_OPSCHUGEX_SECURITY_ENABLED;
    delete process.env.CLOUD_DEVOPS_MCP_OPSCHUGEX_SECURITY_URL;
    delete process.env.CLOUD_DEVOPS_MCP_OPSCHUGEX_TOKEN;
    delete process.env.CLOUD_DEVOPS_MCP_OPSCHUGEX_INTELLIGENCE_ENABLED;
    delete process.env.CLOUD_DEVOPS_MCP_OPSCHUGEX_GOVERNANCE_ENABLED;
    delete process.env.CLOUD_DEVOPS_MCP_OPSCHUGEX_ROOT_CAUSE_URL;
    delete process.env.CLOUD_DEVOPS_MCP_OPSCHUGEX_GOVERNANCE_URL;
  });

  it("forwards bounded security evidence to the private service", async () => {
    let requestedUrl = "";
    let authorization = "";
    const fetcher: OpsChugexFetcher = async (url, init) => {
      requestedUrl = url;
      authorization = init.headers.Authorization;
      expect(JSON.parse(init.body).organization).toBe("OpsChugex");
      return response(sampleResult());
    };

    const result = await requestSecurityPostureAssessment({
      organization: "OpsChugex",
      evaluatedAt: 1_800_000_000,
      assets: [{
        id: "aws:alb:public",
        provider: "aws",
        resourceType: "application-load-balancer",
        environment: "production",
        internetExposed: true
      }]
    }, fetcher);

    expect(requestedUrl).toBe(endpoint);
    expect(authorization).toBe(`Bearer ${token}`);
    expect(result.riskLevel).toBe("critical");
  });

  it("fails closed when the security plane is disabled", async () => {
    process.env.CLOUD_DEVOPS_MCP_OPSCHUGEX_SECURITY_ENABLED = "false";

    await expect(requestSecurityPostureAssessment({
      organization: "OpsChugex",
      evaluatedAt: 1000,
      assets: [{
        id: "generic:service:1",
        provider: "generic",
        resourceType: "service",
        environment: "production"
      }]
    }, async () => response(sampleResult()))).rejects.toThrow(/disabled/i);
  });

  it("rejects insecure non-loopback security endpoints", async () => {
    process.env.CLOUD_DEVOPS_MCP_OPSCHUGEX_SECURITY_URL =
      "http://api.opschugex.com/v1/security/posture";

    await expect(requestSecurityPostureAssessment({
      organization: "OpsChugex",
      evaluatedAt: 1000,
      assets: [{
        id: "generic:service:1",
        provider: "generic",
        resourceType: "service",
        environment: "production"
      }]
    }, async () => response(sampleResult()))).rejects.toThrow(/HTTPS/i);
  });

  it("exposes only the security tool when only its gate is enabled", async () => {
    const server = createServer();
    const client = new Client({ name: "security-test", version: "1.0.0" });
    const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
    await server.connect(serverTransport);
    await client.connect(clientTransport);

    try {
      const { tools } = await client.listTools();
      expect(tools).toHaveLength(13);
      expect(tools.some((item) => item.name === "assess_cloud_security_posture")).toBe(true);
      expect(tools.some((item) => item.name === "diagnose_root_cause")).toBe(false);
      expect(tools.some((item) => item.name === "assess_governance_policy")).toBe(false);

      const tool = tools.find((item) => item.name === "assess_cloud_security_posture");
      expect(tool?.annotations?.readOnlyHint).toBe(true);
      expect(tool?.annotations?.destructiveHint).toBe(false);
      expect(tool?.annotations?.idempotentHint).toBe(true);
      expect(tool?.annotations?.openWorldHint).toBe(true);
    } finally {
      await client.close();
      await server.close();
    }
  });

  it("executes the security MCP handler through the configured private gateway", async () => {
    vi.stubGlobal("fetch", async () => response(sampleResult()));

    const server = createServer();
    const client = new Client({ name: "security-call-test", version: "1.0.0" });
    const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
    await server.connect(serverTransport);
    await client.connect(clientTransport);

    try {
      const result = await client.callTool({
        name: "assess_cloud_security_posture",
        arguments: {
          organization: "OpsChugex",
          evaluatedAt: 1_800_000_000,
          assets: [{
            id: "aws:alb:public",
            provider: "aws",
            resourceType: "application-load-balancer",
            environment: "production",
            internetExposed: true
          }]
        }
      });

      expect(result.structuredContent).toMatchObject({
        organization: "OpsChugex",
        riskLevel: "critical"
      });
    } finally {
      await client.close();
      await server.close();
    }
  });
});
