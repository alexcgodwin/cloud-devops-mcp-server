import { timingSafeEqual } from "node:crypto";
import { createMcpFastifyApp } from "@modelcontextprotocol/fastify";
import { toNodeHandler } from "@modelcontextprotocol/node";
import { createMcpHandler, type AuthInfo, type McpServer } from "@modelcontextprotocol/server";

function splitCsv(value: string | undefined): string[] | undefined {
  const items = value?.split(",").map((item) => item.trim()).filter(Boolean);
  return items && items.length > 0 ? items : undefined;
}

function equalSecret(provided: string, expected: string): boolean {
  const left = Buffer.from(provided);
  const right = Buffer.from(expected);
  if (left.length !== right.length) return false;
  return timingSafeEqual(left, right);
}

function extractBearer(header: string | undefined): string | undefined {
  if (!header) return undefined;
  const match = /^Bearer\s+(.+)$/i.exec(header.trim());
  return match?.[1];
}

export interface HttpServerOptions {
  host?: string;
  port?: number;
  bearerToken?: string;
  allowedHosts?: string[];
  allowedOrigins?: string[];
  publicBaseUrl?: string;
}

function resolveHttpOptions(options: HttpServerOptions = {}) {
  const host = options.host ?? process.env.CLOUD_DEVOPS_MCP_HOST ?? "127.0.0.1";
  const bearerToken = options.bearerToken ?? process.env.CLOUD_DEVOPS_MCP_BEARER_TOKEN;
  const allowedHosts = options.allowedHosts ?? splitCsv(process.env.CLOUD_DEVOPS_MCP_ALLOWED_HOSTS);
  const allowedOrigins = options.allowedOrigins ?? splitCsv(process.env.CLOUD_DEVOPS_MCP_ALLOWED_ORIGINS);
  const publicBaseUrl = options.publicBaseUrl ?? process.env.CLOUD_DEVOPS_MCP_PUBLIC_BASE_URL;

  if (!bearerToken || bearerToken.length < 32) {
    throw new Error("HTTP mode requires CLOUD_DEVOPS_MCP_BEARER_TOKEN with at least 32 characters.");
  }
  const isLocal = ["127.0.0.1", "localhost", "::1"].includes(host);
  if (!isLocal && !allowedHosts?.length) {
    throw new Error("Non-local HTTP binding requires CLOUD_DEVOPS_MCP_ALLOWED_HOSTS.");
  }
  if (!isLocal) {
    if (!publicBaseUrl) {
      throw new Error("Non-local HTTP binding requires CLOUD_DEVOPS_MCP_PUBLIC_BASE_URL.");
    }
    let parsed: URL;
    try {
      parsed = new URL(publicBaseUrl);
    } catch {
      throw new Error("CLOUD_DEVOPS_MCP_PUBLIC_BASE_URL must be a valid HTTPS URL.");
    }
    if (parsed.protocol !== "https:") {
      throw new Error("Remote HTTP mode requires HTTPS at the public reverse proxy or gateway.");
    }
  }

  return { host, bearerToken, allowedHosts, allowedOrigins, publicBaseUrl };
}

export function createHttpApp(
  serverFactory: () => McpServer,
  options: HttpServerOptions = {}
) {
  const { host, bearerToken, allowedHosts, allowedOrigins } = resolveHttpOptions(options);
  const app = createMcpFastifyApp({ host, allowedHosts, allowedOrigins });
  const handler = createMcpHandler(() => serverFactory());
  const nodeHandler = toNodeHandler(handler);

  app.get("/healthz", async () => ({
    status: "ok",
    transport: "streamable-http",
    authentication: "bearer"
  }));

  app.all("/mcp", async (request, reply) => {
    const supplied = extractBearer(request.headers.authorization);
    if (!supplied || !equalSecret(supplied, bearerToken)) {
      return reply
        .code(401)
        .header("www-authenticate", 'Bearer realm="cloud-devops-mcp"')
        .send({
          error: "unauthorized",
          message: "A valid Bearer token is required."
        });
    }

    const auth: AuthInfo = {
      token: supplied,
      clientId: "static-bearer-client",
      scopes: ["mcp"]
    };

    Object.assign(request.raw, { auth });
    return nodeHandler(request.raw, reply.raw, request.body);
  });

  return app;
}

export async function startHttpServer(
  serverFactory: () => McpServer,
  options: HttpServerOptions = {}
) {
  const port = options.port ?? Number(process.env.CLOUD_DEVOPS_MCP_PORT ?? "3000");
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    throw new Error("CLOUD_DEVOPS_MCP_PORT must be an integer from 1 to 65535.");
  }

  const resolved = resolveHttpOptions(options);
  const app = createHttpApp(serverFactory, options);
  await app.listen({ port, host: resolved.host });
  return app;
}
