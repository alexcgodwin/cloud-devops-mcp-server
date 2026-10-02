import { mkdtemp, mkdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Client, InMemoryTransport } from "@modelcontextprotocol/client";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { createServer } from "../src/index.js";
import {
  kubectlCurrentContext,
  kubectlGetResources,
  kubectlRolloutStatus,
  summarizeTerraformPlanJson,
  terraformFmtCheck,
  terraformPlanSummary,
  terraformValidate,
  type CommandRunner
} from "../src/infrastructure.js";

let repo = "";

function sequenceRunner(results: Array<{ stdout?: string; stderr?: string; exitCode?: number }>) {
  const calls: Array<{ executable: string; args: string[]; cwd: string }> = [];
  const runner: CommandRunner = async (executable, args, cwd) => {
    calls.push({ executable, args, cwd });
    const next = results.shift() ?? {};
    return {
      stdout: next.stdout ?? "",
      stderr: next.stderr ?? "",
      exitCode: next.exitCode ?? 0
    };
  };
  return { runner, calls };
}

describe("infrastructure operations", () => {
  beforeEach(async () => {
    repo = await mkdtemp(join(tmpdir(), "cloud-devops-infra-"));
    await mkdir(join(repo, "infra"));
    process.env.CLOUD_DEVOPS_MCP_INFRASTRUCTURE_OPERATIONS_ENABLED = "true";
    process.env.CLOUD_DEVOPS_MCP_ALLOWED_REPOSITORIES = repo;
    process.env.CLOUD_DEVOPS_MCP_ALLOWED_KUBE_CONTEXTS = "dev-cluster,prod-cluster";
    process.env.CLOUD_DEVOPS_MCP_ALLOWED_KUBE_NAMESPACES = "default,platform";
  });

  afterEach(async () => {
    for (const key of Object.keys(process.env)) {
      if (key.startsWith("CLOUD_DEVOPS_MCP_")) delete process.env[key];
    }
    await rm(repo, { recursive: true, force: true });
  });

  it("summarizes Terraform plan actions", () => {
    const summary = summarizeTerraformPlanJson({
      resource_changes: [
        { change: { actions: ["create"] } },
        { change: { actions: ["update"] } },
        { change: { actions: ["delete"] } },
        { change: { actions: ["delete", "create"] } },
        { change: { actions: ["read"] } },
        { change: { actions: ["no-op"] } }
      ]
    });
    expect(summary).toEqual({
      resourceChangeCount: 6,
      counts: { create: 1, update: 1, delete: 1, replace: 1, read: 1, noOp: 1 }
    });
  });

  it("checks Terraform formatting and validates JSON diagnostics without changing files", async () => {
    const fmt = sequenceRunner([{ stdout: "main.tf\n", exitCode: 3 }]);
    const fmtResult = await terraformFmtCheck({ repositoryPath: repo, workingDirectory: "infra" }, fmt.runner);
    expect(fmtResult).toMatchObject({ formatted: false, exitCode: 3 });
    expect(fmt.calls[0].args).toEqual(["fmt", "-check", "-recursive", "-diff"]);

    const validate = sequenceRunner([{
      stdout: JSON.stringify({
        valid: false,
        error_count: 1,
        warning_count: 1,
        diagnostics: [{ severity: "error", summary: "Invalid block", detail: "Example diagnostic" }]
      })
    }]);
    const validation = await terraformValidate({ repositoryPath: repo, workingDirectory: "infra" }, validate.runner);
    expect(validation).toMatchObject({ valid: false, errorCount: 1, warningCount: 1 });
    expect(validation.diagnostics[0].summary).toBe("Invalid block");
  });

  it("returns a bounded Terraform plan summary and never calls apply", async () => {
    const fake = sequenceRunner([
      { exitCode: 2 },
      {
        stdout: JSON.stringify({
          resource_changes: [
            { change: { actions: ["create"] } },
            { change: { actions: ["update"] } },
            { change: { actions: ["delete", "create"] } }
          ]
        })
      }
    ]);
    const result = await terraformPlanSummary({ repositoryPath: repo, workingDirectory: "infra" }, fake.runner);
    expect(result).toMatchObject({
      planSucceeded: true,
      hasChanges: true,
      resourceChangeCount: 3,
      counts: { create: 1, update: 1, replace: 1 }
    });
    expect(fake.calls[0].args).toEqual(expect.arrayContaining(["plan", "-input=false", "-lock=false", "-refresh=false", "-detailed-exitcode"]));
    expect(fake.calls.flatMap((call) => call.args)).not.toContain("apply");
  });

  it("returns a controlled plan failure without exposing a full plan", async () => {
    const fake = sequenceRunner([{ exitCode: 1, stderr: "provider configuration missing" }]);
    const result = await terraformPlanSummary({ repositoryPath: repo, workingDirectory: "infra" }, fake.runner);
    expect(result).toMatchObject({
      planSucceeded: false,
      hasChanges: false,
      exitCode: 1,
      resourceChangeCount: 0
    });
    expect(result.diagnostic).toContain("provider configuration missing");
  });

  it("reads only allowlisted Kubernetes contexts, resources and namespaces", async () => {
    const current = sequenceRunner([{ stdout: "dev-cluster" }]);
    await expect(kubectlCurrentContext({ repositoryPath: repo }, current.runner))
      .resolves.toMatchObject({ context: "dev-cluster", allowed: true });

    const get = sequenceRunner([{
      stdout: JSON.stringify({
        items: [
          { kind: "Pod", metadata: { name: "api-1", namespace: "platform" }, status: { phase: "Running" } },
          { kind: "Pod", metadata: { name: "api-2", namespace: "platform" }, status: { phase: "Pending" } }
        ]
      })
    }]);
    const resources = await kubectlGetResources({
      repositoryPath: repo,
      context: "dev-cluster",
      namespace: "platform",
      resource: "pods",
      labelSelector: "app=api"
    }, get.runner);
    expect(resources).toMatchObject({ context: "dev-cluster", namespace: "platform", resource: "pods", count: 2 });
    expect(get.calls[0].args).toEqual(expect.arrayContaining(["--context", "dev-cluster", "--namespace", "platform", "get", "pods", "-o", "json"]));
  });

  it("reads rollout status and rejects secret or unapproved cluster access", async () => {
    const rollout = sequenceRunner([{ stdout: "deployment \"api\" successfully rolled out" }]);
    const result = await kubectlRolloutStatus({
      repositoryPath: repo,
      context: "prod-cluster",
      namespace: "platform",
      kind: "deployment",
      name: "api"
    }, rollout.runner);
    expect(result).toMatchObject({ ready: true, resource: "deployment/api" });

    const never: CommandRunner = async () => ({ stdout: "", stderr: "", exitCode: 0 });
    await expect(kubectlGetResources({
      repositoryPath: repo,
      context: "dev-cluster",
      namespace: "platform",
      resource: "secrets"
    }, never)).rejects.toThrow(/resource type is not allowlisted/i);

    await expect(kubectlGetResources({
      repositoryPath: repo,
      context: "unknown-cluster",
      namespace: "platform",
      resource: "pods"
    }, never)).rejects.toThrow(/context is not in/i);

    await expect(kubectlGetResources({
      repositoryPath: repo,
      context: "dev-cluster",
      namespace: "kube-system",
      resource: "pods"
    }, never)).rejects.toThrow(/namespace is not in/i);
  });
});
