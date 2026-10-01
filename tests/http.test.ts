import type { AddressInfo } from "node:net";
import { Client, StreamableHTTPClientTransport } from "@modelcontextprotocol/client";
import { describe, expect, it } from "vitest";
import { createHttpApp } from "../src/http.js";
import { createServer } from "../src/index.js";

describe("authenticated Streamable HTTP", () => {
  it("rejects invalid bearer tokens and serves all tools to an authenticated MCP client", async () => {
    const token = "a".repeat(48);
    const app = createHttpApp(createServer, {
      host: "127.0.0.1",
      bearerToken: token
    });

    await app.listen({ host: "127.0.0.1", port: 0 });
    const address = app.server.address() as AddressInfo;
    const url = new URL(`http://127.0.0.1:${address.port}/mcp`);

    try {
      const rejected = await app.inject({
        method: "POST",
        url: "/mcp",
        headers: {
          "content-type": "application/json",
          accept: "application/json, text/event-stream"
        },
        payload: {
          jsonrpc: "2.0",
          id: 1,
          method: "tools/list"
        }
      });

      expect(rejected.statusCode).toBe(401);
      expect(rejected.headers["www-authenticate"]).toContain("Bearer");

      const client = new Client(
        { name: "http-security-test", version: "1.0.0" },
        { versionNegotiation: { mode: "auto" } }
      );
      const transport = new StreamableHTTPClientTransport(url, {
        requestInit: {
          headers: {
            Authorization: `Bearer ${token}`
          }
        }
      });

      await client.connect(transport);
      try {
        const { tools } = await client.listTools();
        expect(tools).toHaveLength(12);
        expect(tools.map((tool) => tool.name)).toEqual(
          expect.arrayContaining([
            "review_cloud_identity_policy",
            "review_terraform_security",
            "review_kubernetes_security",
            "review_software_supply_chain"
          ])
        );

        const result = await client.callTool({
          name: "review_cloud_identity_policy",
          arguments: {
            provider: "gcp",
            policyName: "test-policy",
            policyJson: JSON.stringify({
              bindings: [{
                role: "roles/viewer",
                members: ["serviceAccount:viewer@example.iam.gserviceaccount.com"],
                condition: { title: "bounded" }
              }]
            })
          }
        });

        expect(result.isError).not.toBe(true);
        expect(result.structuredContent).toMatchObject({
          provider: "gcp",
          policyPack: "gcp-identity-v1"
        });
      } finally {
        await client.close();
      }
    } finally {
      await app.close();
    }
  }, 15_000);

  it("requires a strong bearer token", () => {
    expect(() => createHttpApp(createServer, {
      host: "127.0.0.1",
      bearerToken: "short"
    })).toThrow("at least 32 characters");
  });

  it("requires an explicit Host allowlist for non-local bindings", () => {
    expect(() => createHttpApp(createServer, {
      host: "0.0.0.0",
      bearerToken: "b".repeat(48)
    })).toThrow("CLOUD_DEVOPS_MCP_ALLOWED_HOSTS");
  });

  it("requires HTTPS public routing for non-local bindings", () => {
    expect(() => createHttpApp(createServer, {
      host: "0.0.0.0",
      bearerToken: "c".repeat(48),
      allowedHosts: ["mcp.example.com"]
    })).toThrow("CLOUD_DEVOPS_MCP_PUBLIC_BASE_URL");

    expect(() => createHttpApp(createServer, {
      host: "0.0.0.0",
      bearerToken: "d".repeat(48),
      allowedHosts: ["mcp.example.com"],
      publicBaseUrl: "http://mcp.example.com"
    })).toThrow("requires HTTPS");

    const app = createHttpApp(createServer, {
      host: "0.0.0.0",
      bearerToken: "e".repeat(48),
      allowedHosts: ["mcp.example.com"],
      allowedOrigins: ["mcp.example.com"],
      publicBaseUrl: "https://mcp.example.com"
    });
    expect(app).toBeDefined();
  });
});
