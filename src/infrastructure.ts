import { execFile } from "node:child_process";
import { appendFile, realpath, rm, stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import { isAbsolute, relative, resolve } from "node:path";

const DEFAULT_KUBE_RESOURCES = [
  "pods",
  "deployments",
  "statefulsets",
  "daemonsets",
  "services",
  "ingresses",
  "jobs",
  "cronjobs",
  "namespaces",
  "nodes"
];
const ROLLOUT_KINDS = new Set(["deployment", "statefulset", "daemonset"]);

export type CommandResult = {
  stdout: string;
  stderr: string;
  exitCode: number;
};

export type CommandRunner = (
  executable: string,
  args: string[],
  cwd: string,
  allowFailure?: boolean
) => Promise<CommandResult>;

function csv(name: string, fallback: string[] = []): string[] {
  const raw = process.env[name]?.trim();
  return raw ? raw.split(",").map((value) => value.trim()).filter(Boolean) : fallback;
}

function infrastructureEnabled(): boolean {
  return process.env.CLOUD_DEVOPS_MCP_INFRASTRUCTURE_OPERATIONS_ENABLED === "true";
}

function ensureInfrastructureEnabled(): void {
  if (!infrastructureEnabled()) {
    throw new Error(
      "Infrastructure operations are disabled. Set CLOUD_DEVOPS_MCP_INFRASTRUCTURE_OPERATIONS_ENABLED=true to enable them."
    );
  }
}

function redact(value: string): string {
  return value
    .replace(/gh[pousr]_[A-Za-z0-9_]{20,}/g, "[REDACTED_GITHUB_TOKEN]")
    .replace(/github_pat_[A-Za-z0-9_]{20,}/g, "[REDACTED_GITHUB_TOKEN]")
    .replace(/(token|password|secret|client_secret)\s*[=:]\s*[^\s,;]+/gi, "$1=[REDACTED]");
}

async function audit(action: string, repositoryPath: string, outcome: "success" | "failure", detail?: string): Promise<void> {
  const record = JSON.stringify({
    timestamp: new Date().toISOString(),
    action,
    repositoryPath,
    outcome,
    detail: detail ? redact(detail).slice(0, 2000) : undefined
  });
  const auditPath = process.env.CLOUD_DEVOPS_MCP_AUDIT_LOG || resolve(tmpdir(), "cloud-devops-mcp-audit.jsonl");
  await appendFile(auditPath, record + "\n", "utf8").catch(() => undefined);
}

export const defaultCommandRunner: CommandRunner = async (executable, args, cwd, allowFailure = false) =>
  new Promise((resolvePromise, reject) => {
    execFile(
      executable,
      args,
      {
        cwd,
        timeout: 60_000,
        maxBuffer: 4 * 1024 * 1024,
        windowsHide: true,
        env: { ...process.env, TF_IN_AUTOMATION: "1" }
      },
      (error, stdout, stderr) => {
        const result = {
          stdout: redact(stdout ?? "").trim(),
          stderr: redact(stderr ?? "").trim(),
          exitCode: error && typeof (error as any).code === "number" ? (error as any).code : error ? 1 : 0
        };
        if (error && !allowFailure) {
          reject(new Error(result.stderr || result.stdout || String(error.message)));
          return;
        }
        resolvePromise(result);
      }
    );
  });

async function canonicalRepository(repositoryPath: string): Promise<string> {
  ensureInfrastructureEnabled();
  if (!isAbsolute(repositoryPath)) throw new Error("repositoryPath must be absolute.");
  const canonical = await realpath(repositoryPath);
  const info = await stat(canonical);
  if (!info.isDirectory()) throw new Error("repositoryPath must point to a directory.");

  const allowed = csv("CLOUD_DEVOPS_MCP_ALLOWED_REPOSITORIES");
  if (allowed.length === 0) {
    throw new Error("No repositories are allowlisted. Set CLOUD_DEVOPS_MCP_ALLOWED_REPOSITORIES.");
  }
  const allowedCanonical = await Promise.all(
    allowed.map(async (entry) => realpath(entry).catch(() => resolve(entry)))
  );
  const ok = allowedCanonical.some((entry) =>
    process.platform === "win32"
      ? entry.toLowerCase() === canonical.toLowerCase()
      : entry === canonical
  );
  if (!ok) throw new Error("Repository is not in CLOUD_DEVOPS_MCP_ALLOWED_REPOSITORIES.");
  return canonical;
}

async function targetDirectory(repositoryPath: string, workingDirectory?: string): Promise<{ repositoryPath: string; targetPath: string }> {
  const repository = await canonicalRepository(repositoryPath);
  const requested = workingDirectory?.trim() || ".";
  if (isAbsolute(requested)) throw new Error("workingDirectory must be relative to repositoryPath.");
  const resolved = resolve(repository, requested);
  const target = await realpath(resolved);
  const rel = relative(repository, target);
  if (rel.startsWith("..") || isAbsolute(rel)) {
    throw new Error("workingDirectory escapes the allowlisted repository.");
  }
  const info = await stat(target);
  if (!info.isDirectory()) throw new Error("workingDirectory must point to a directory.");
  return { repositoryPath: repository, targetPath: target };
}

async function resolveVarFiles(targetPath: string, varFiles: string[] = []): Promise<string[]> {
  const resolved: string[] = [];
  for (const file of varFiles) {
    const value = file.replace(/\\/g, "/").trim();
    if (!value || isAbsolute(value) || (!value.endsWith(".tfvars") && !value.endsWith(".tfvars.json"))) {
      throw new Error(`Invalid Terraform var-file path: ${file}`);
    }
    const full = await realpath(resolve(targetPath, value));
    const rel = relative(targetPath, full);
    if (rel.startsWith("..") || isAbsolute(rel)) {
      throw new Error(`Terraform var-file escapes workingDirectory: ${file}`);
    }
    const info = await stat(full);
    if (!info.isFile()) throw new Error(`Terraform var-file is not a file: ${file}`);
    resolved.push(full);
  }
  return resolved;
}

function parseTerraformDiagnostics(payload: any): Array<{ severity: string; summary: string; detail: string }> {
  return Array.isArray(payload?.diagnostics)
    ? payload.diagnostics.slice(0, 100).map((item: any) => ({
        severity: String(item?.severity ?? "unknown"),
        summary: String(item?.summary ?? "").slice(0, 500),
        detail: String(item?.detail ?? "").slice(0, 2000)
      }))
    : [];
}

export function summarizeTerraformPlanJson(plan: any) {
  const counts = {
    create: 0,
    update: 0,
    delete: 0,
    replace: 0,
    read: 0,
    noOp: 0
  };

  const changes = Array.isArray(plan?.resource_changes) ? plan.resource_changes : [];
  for (const resource of changes) {
    const actions = Array.isArray(resource?.change?.actions) ? resource.change.actions : [];
    if (actions.includes("create") && actions.includes("delete")) counts.replace += 1;
    else if (actions.length === 1 && actions[0] === "create") counts.create += 1;
    else if (actions.length === 1 && actions[0] === "update") counts.update += 1;
    else if (actions.length === 1 && actions[0] === "delete") counts.delete += 1;
    else if (actions.length === 1 && actions[0] === "read") counts.read += 1;
    else if (actions.length === 1 && actions[0] === "no-op") counts.noOp += 1;
  }
  return {
    resourceChangeCount: changes.length,
    counts
  };
}

export async function terraformFmtCheck(
  input: { repositoryPath: string; workingDirectory?: string },
  runner: CommandRunner = defaultCommandRunner
) {
  const { repositoryPath, targetPath } = await targetDirectory(input.repositoryPath, input.workingDirectory);
  try {
    const result = await runner("terraform", ["fmt", "-check", "-recursive", "-diff"], targetPath, true);
    const formatted = result.exitCode === 0;
    if (!formatted && result.exitCode !== 3) {
      throw new Error(result.stderr || result.stdout || "terraform fmt check failed.");
    }
    await audit("terraform_fmt_check", repositoryPath, "success", targetPath);
    return {
      repositoryPath,
      workingDirectory: relative(repositoryPath, targetPath) || ".",
      formatted,
      exitCode: result.exitCode,
      diff: result.stdout.slice(0, 20_000)
    };
  } catch (error: any) {
    await audit("terraform_fmt_check", repositoryPath, "failure", error.message);
    throw error;
  }
}

export async function terraformValidate(
  input: { repositoryPath: string; workingDirectory?: string },
  runner: CommandRunner = defaultCommandRunner
) {
  const { repositoryPath, targetPath } = await targetDirectory(input.repositoryPath, input.workingDirectory);
  try {
    const result = await runner("terraform", ["validate", "-json"], targetPath, true);
    let payload: any;
    try {
      payload = JSON.parse(result.stdout || "{}");
    } catch {
      throw new Error(result.stderr || "terraform validate did not return valid JSON.");
    }
    await audit("terraform_validate", repositoryPath, "success", targetPath);
    return {
      repositoryPath,
      workingDirectory: relative(repositoryPath, targetPath) || ".",
      valid: Boolean(payload.valid),
      errorCount: Number(payload.error_count ?? 0),
      warningCount: Number(payload.warning_count ?? 0),
      diagnostics: parseTerraformDiagnostics(payload)
    };
  } catch (error: any) {
    await audit("terraform_validate", repositoryPath, "failure", error.message);
    throw error;
  }
}

export async function terraformPlanSummary(
  input: { repositoryPath: string; workingDirectory?: string; varFiles?: string[] },
  runner: CommandRunner = defaultCommandRunner
) {
  const { repositoryPath, targetPath } = await targetDirectory(input.repositoryPath, input.workingDirectory);
  const varFiles = await resolveVarFiles(targetPath, input.varFiles);
  const planPath = resolve(tmpdir(), `cloud-devops-mcp-${process.pid}-${Date.now()}.tfplan`);
  try {
    const args = [
      "plan",
      "-input=false",
      "-lock=false",
      "-refresh=false",
      "-detailed-exitcode",
      `-out=${planPath}`,
      ...varFiles.flatMap((file) => ["-var-file", file])
    ];
    const plan = await runner("terraform", args, targetPath, true);
    if (![0, 2].includes(plan.exitCode)) {
      await audit("terraform_plan_summary", repositoryPath, "failure", plan.stderr || plan.stdout);
      return {
        repositoryPath,
        workingDirectory: relative(repositoryPath, targetPath) || ".",
        planSucceeded: false,
        hasChanges: false,
        exitCode: plan.exitCode,
        resourceChangeCount: 0,
        counts: { create: 0, update: 0, delete: 0, replace: 0, read: 0, noOp: 0 },
        diagnostic: (plan.stderr || plan.stdout).slice(0, 4000)
      };
    }

    const shown = await runner("terraform", ["show", "-json", planPath], targetPath);
    const payload = JSON.parse(shown.stdout || "{}");
    const summary = summarizeTerraformPlanJson(payload);
    await audit("terraform_plan_summary", repositoryPath, "success", targetPath);
    return {
      repositoryPath,
      workingDirectory: relative(repositoryPath, targetPath) || ".",
      planSucceeded: true,
      hasChanges: plan.exitCode === 2,
      exitCode: plan.exitCode,
      ...summary,
      diagnostic: ""
    };
  } catch (error: any) {
    await audit("terraform_plan_summary", repositoryPath, "failure", error.message);
    throw error;
  } finally {
    await rm(planPath, { force: true }).catch(() => undefined);
  }
}

function allowedKubeContext(context: string): string {
  const value = context.trim();
  if (!value || value.startsWith("-") || !/^[A-Za-z0-9._:@/-]{1,250}$/.test(value)) {
    throw new Error("Invalid Kubernetes context.");
  }
  const allowed = csv("CLOUD_DEVOPS_MCP_ALLOWED_KUBE_CONTEXTS");
  if (allowed.length === 0 || !allowed.includes(value)) {
    throw new Error("Kubernetes context is not in CLOUD_DEVOPS_MCP_ALLOWED_KUBE_CONTEXTS.");
  }
  return value;
}

function allowedNamespace(namespace?: string): string | undefined {
  if (!namespace) return undefined;
  const value = namespace.trim();
  if (!/^[a-z0-9]([-a-z0-9]*[a-z0-9])?$/.test(value)) throw new Error("Invalid Kubernetes namespace.");
  const allowed = csv("CLOUD_DEVOPS_MCP_ALLOWED_KUBE_NAMESPACES");
  if (allowed.length === 0 || !allowed.includes(value)) {
    throw new Error("Kubernetes namespace is not in CLOUD_DEVOPS_MCP_ALLOWED_KUBE_NAMESPACES.");
  }
  return value;
}

function allowedResource(resource: string): string {
  const value = resource.trim().toLowerCase();
  const allowed = csv("CLOUD_DEVOPS_MCP_ALLOWED_KUBE_RESOURCES", DEFAULT_KUBE_RESOURCES).map((item) => item.toLowerCase());
  if (!allowed.includes(value)) throw new Error("Kubernetes resource type is not allowlisted.");
  return value;
}

function safeResourceName(name?: string): string | undefined {
  if (!name) return undefined;
  const value = name.trim();
  if (!/^[a-z0-9]([-a-z0-9.]*[a-z0-9])?$/.test(value)) throw new Error("Invalid Kubernetes resource name.");
  return value;
}

export async function kubectlCurrentContext(
  input: { repositoryPath: string },
  runner: CommandRunner = defaultCommandRunner
) {
  const repositoryPath = await canonicalRepository(input.repositoryPath);
  try {
    const result = await runner("kubectl", ["config", "current-context"], repositoryPath);
    const context = allowedKubeContext(result.stdout);
    await audit("kubectl_current_context", repositoryPath, "success", context);
    return { repositoryPath, context, allowed: true };
  } catch (error: any) {
    await audit("kubectl_current_context", repositoryPath, "failure", error.message);
    throw error;
  }
}

export async function kubectlGetResources(
  input: {
    repositoryPath: string;
    context: string;
    resource: string;
    namespace?: string;
    name?: string;
    labelSelector?: string;
  },
  runner: CommandRunner = defaultCommandRunner
) {
  const repositoryPath = await canonicalRepository(input.repositoryPath);
  const context = allowedKubeContext(input.context);
  const resource = allowedResource(input.resource);
  const namespace = allowedNamespace(input.namespace);
  const name = safeResourceName(input.name);
  const labelSelector = input.labelSelector?.trim();
  if (labelSelector && (!/^[A-Za-z0-9_.=,!()\-\/]{1,300}$/.test(labelSelector) || labelSelector.startsWith("-"))) {
    throw new Error("Invalid Kubernetes label selector.");
  }

  const args = ["--context", context];
  if (namespace) args.push("--namespace", namespace);
  args.push("get", resource);
  if (name) args.push(name);
  if (labelSelector) args.push("--selector", labelSelector);
  args.push("-o", "json", "--request-timeout=15s");

  try {
    const result = await runner("kubectl", args, repositoryPath);
    const payload = JSON.parse(result.stdout || "{}");
    const objects = Array.isArray(payload.items) ? payload.items : [payload];
    const summaries = objects
      .filter((item: any) => item && typeof item === "object")
      .slice(0, 200)
      .map((item: any) => ({
        kind: String(item.kind ?? ""),
        name: String(item.metadata?.name ?? ""),
        namespace: String(item.metadata?.namespace ?? ""),
        phase: item.status?.phase ? String(item.status.phase) : undefined,
        replicas: typeof item.status?.replicas === "number" ? item.status.replicas : undefined,
        readyReplicas: typeof item.status?.readyReplicas === "number" ? item.status.readyReplicas : undefined
      }));

    await audit("kubectl_get_resources", repositoryPath, "success", `${context}:${resource}`);
    return { repositoryPath, context, namespace: namespace ?? "", resource, count: summaries.length, objects: summaries };
  } catch (error: any) {
    await audit("kubectl_get_resources", repositoryPath, "failure", error.message);
    throw error;
  }
}

export async function kubectlRolloutStatus(
  input: { repositoryPath: string; context: string; namespace: string; kind: string; name: string },
  runner: CommandRunner = defaultCommandRunner
) {
  const repositoryPath = await canonicalRepository(input.repositoryPath);
  const context = allowedKubeContext(input.context);
  const namespace = allowedNamespace(input.namespace);
  const kind = input.kind.trim().toLowerCase();
  if (!ROLLOUT_KINDS.has(kind)) throw new Error("Rollout status supports deployment, statefulset or daemonset only.");
  const name = safeResourceName(input.name)!;

  try {
    const result = await runner(
      "kubectl",
      ["--context", context, "--namespace", namespace!, "rollout", "status", `${kind}/${name}`, "--watch=false", "--timeout=15s"],
      repositoryPath,
      true
    );
    await audit("kubectl_rollout_status", repositoryPath, result.exitCode === 0 ? "success" : "failure", result.stderr || result.stdout);
    return {
      repositoryPath,
      context,
      namespace,
      resource: `${kind}/${name}`,
      ready: result.exitCode === 0,
      exitCode: result.exitCode,
      message: (result.stdout || result.stderr).slice(0, 4000)
    };
  } catch (error: any) {
    await audit("kubectl_rollout_status", repositoryPath, "failure", error.message);
    throw error;
  }
}
