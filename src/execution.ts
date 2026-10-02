import { execFile } from "node:child_process";
import { appendFile, realpath, stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import { resolve, relative, isAbsolute } from "node:path";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);
const DEFAULT_PROTECTED_BRANCHES = ["main", "master", "production", "prod", "release"];
const DEFAULT_BRANCH_PREFIXES = ["feature/", "feat/", "fix/", "chore/", "docs/", "test/"];
const SUCCESSFUL_CHECK_CONCLUSIONS = new Set(["success", "neutral", "skipped"]);

export type GitExecutionResult = Record<string, unknown>;

function csv(name: string, fallback: string[] = []): string[] {
  const raw = process.env[name]?.trim();
  return raw ? raw.split(",").map((value) => value.trim()).filter(Boolean) : fallback;
}

function executionEnabled(): boolean {
  return process.env.CLOUD_DEVOPS_MCP_EXECUTION_ENABLED === "true";
}

function ensureExecutionEnabled(): void {
  if (!executionEnabled()) {
    throw new Error("Controlled execution is disabled. Set CLOUD_DEVOPS_MCP_EXECUTION_ENABLED=true to enable it.");
  }
}

function redact(value: string): string {
  return value
    .replace(/gh[pousr]_[A-Za-z0-9_]{20,}/g, "[REDACTED_GITHUB_TOKEN]")
    .replace(/github_pat_[A-Za-z0-9_]{20,}/g, "[REDACTED_GITHUB_TOKEN]")
    .replace(/(https?:\/\/)[^\s/@:]+:[^\s/@]+@/g, "$1[REDACTED]@");
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

async function canonicalRepository(repositoryPath: string): Promise<string> {
  ensureExecutionEnabled();
  if (!isAbsolute(repositoryPath)) throw new Error("repositoryPath must be absolute.");
  const canonical = await realpath(repositoryPath);
  const info = await stat(canonical);
  if (!info.isDirectory()) throw new Error("repositoryPath must point to a directory.");

  const allowed = csv("CLOUD_DEVOPS_MCP_ALLOWED_REPOSITORIES");
  if (allowed.length === 0) throw new Error("No repositories are allowlisted. Set CLOUD_DEVOPS_MCP_ALLOWED_REPOSITORIES.");

  const allowedCanonical = await Promise.all(allowed.map(async (entry) => realpath(entry).catch(() => resolve(entry))));
  const ok = allowedCanonical.some((entry) => process.platform === "win32"
    ? entry.toLowerCase() === canonical.toLowerCase()
    : entry === canonical);
  if (!ok) throw new Error("Repository is not in CLOUD_DEVOPS_MCP_ALLOWED_REPOSITORIES.");
  return canonical;
}

async function runGit(repositoryPath: string, args: string[], allowFailure = false): Promise<{ stdout: string; stderr: string }> {
  try {
    const result = await execFileAsync("git", ["-C", repositoryPath, ...args], {
      timeout: 30_000,
      maxBuffer: 2 * 1024 * 1024,
      windowsHide: true,
      env: { ...process.env, GIT_TERMINAL_PROMPT: "0" }
    });
    return { stdout: redact(result.stdout ?? "").trim(), stderr: redact(result.stderr ?? "").trim() };
  } catch (error: any) {
    const stdout = redact(String(error?.stdout ?? "")).trim();
    const stderr = redact(String(error?.stderr ?? error?.message ?? error)).trim();
    if (allowFailure) return { stdout, stderr };
    throw new Error(stderr || stdout || "Git command failed.");
  }
}

function validateBranchName(branch: string): string {
  const value = branch.trim();
  if (!value || value.startsWith("-") || value.endsWith(".lock") || value.includes("..") || value.includes("@{") ||
      value.includes("//") || !/^[A-Za-z0-9._/-]{1,200}$/.test(value)) throw new Error("Invalid branch name.");
  return value;
}

function protectedBranches(): string[] {
  return csv("CLOUD_DEVOPS_MCP_PROTECTED_BRANCHES", DEFAULT_PROTECTED_BRANCHES).map((value) => value.toLowerCase());
}

function ensureNotProtected(branch: string): void {
  if (protectedBranches().includes(branch.toLowerCase())) throw new Error(`Direct mutation of protected branch "${branch}" is blocked.`);
}

function ensureAllowedNewBranch(branch: string): void {
  ensureNotProtected(branch);
  const prefixes = csv("CLOUD_DEVOPS_MCP_ALLOWED_BRANCH_PREFIXES", DEFAULT_BRANCH_PREFIXES);
  if (prefixes.length > 0 && !prefixes.some((prefix) => branch.startsWith(prefix))) {
    throw new Error(`Branch must start with one of: ${prefixes.join(", ")}`);
  }
}

function validateRemote(remote: string): string {
  const value = remote.trim();
  if (!/^[A-Za-z0-9._-]{1,100}$/.test(value)) throw new Error("Invalid remote name.");
  const allowed = csv("CLOUD_DEVOPS_MCP_ALLOWED_REMOTES", ["origin"]);
  if (!allowed.includes(value)) throw new Error(`Remote "${value}" is not allowlisted.`);
  return value;
}

function validateRelativePaths(repositoryPath: string, files: string[]): string[] {
  if (!files.length) throw new Error("At least one file path is required.");
  return files.map((file) => {
    const clean = file.replace(/\\/g, "/").trim();
    if (!clean || clean.startsWith("/") || clean.includes("\0")) throw new Error(`Invalid file path: ${file}`);
    const full = resolve(repositoryPath, clean);
    const rel = relative(repositoryPath, full);
    if (!rel || rel.startsWith("..") || isAbsolute(rel)) throw new Error(`Path escapes repository: ${file}`);
    return clean;
  });
}

async function currentBranch(repositoryPath: string): Promise<string> {
  const { stdout } = await runGit(repositoryPath, ["rev-parse", "--abbrev-ref", "HEAD"]);
  if (!stdout || stdout === "HEAD") throw new Error("Repository is in detached HEAD state.");
  return stdout;
}

async function requireClean(repositoryPath: string): Promise<void> {
  const { stdout } = await runGit(repositoryPath, ["status", "--porcelain"]);
  if (stdout) throw new Error("Working tree must be clean for this operation.");
}

function parseChangedPaths(porcelain: string): string[] {
  return porcelain.split(/\r?\n/).filter(Boolean).map((line) => line.slice(3).trim()).filter(Boolean);
}

export async function gitStatus(input: { repositoryPath: string }): Promise<GitExecutionResult> {
  const repositoryPath = await canonicalRepository(input.repositoryPath);
  try {
    const branch = await currentBranch(repositoryPath);
    const { stdout } = await runGit(repositoryPath, ["status", "--porcelain"]);
    const upstream = await runGit(repositoryPath, ["rev-list", "--left-right", "--count", "@{upstream}...HEAD"], true);
    const [behind, ahead] = upstream.stdout ? upstream.stdout.split(/\s+/).map(Number) : [null, null];
    await audit("git_status", repositoryPath, "success");
    return { repositoryPath, branch, clean: !stdout, changedPaths: parseChangedPaths(stdout), ahead, behind };
  } catch (error: any) {
    await audit("git_status", repositoryPath, "failure", error.message);
    throw error;
  }
}

export async function gitFetch(input: { repositoryPath: string; remote?: string; prune?: boolean }): Promise<GitExecutionResult> {
  const repositoryPath = await canonicalRepository(input.repositoryPath);
  const remote = validateRemote(input.remote ?? "origin");
  try {
    const args = ["fetch"];
    if (input.prune !== false) args.push("--prune");
    args.push(remote);
    const result = await runGit(repositoryPath, args);
    await audit("git_fetch", repositoryPath, "success");
    return { repositoryPath, remote, fetched: true, output: result.stderr || result.stdout };
  } catch (error: any) {
    await audit("git_fetch", repositoryPath, "failure", error.message);
    throw error;
  }
}

export async function gitPullFfOnly(input: { repositoryPath: string; remote?: string; branch?: string }): Promise<GitExecutionResult> {
  const repositoryPath = await canonicalRepository(input.repositoryPath);
  const remote = validateRemote(input.remote ?? "origin");
  await requireClean(repositoryPath);
  const branch = input.branch ? validateBranchName(input.branch) : await currentBranch(repositoryPath);
  const current = await currentBranch(repositoryPath);
  if (branch !== current) throw new Error("git_pull_ff_only only pulls the currently checked-out branch.");
  try {
    const result = await runGit(repositoryPath, ["pull", "--ff-only", remote, branch]);
    await audit("git_pull_ff_only", repositoryPath, "success");
    return { repositoryPath, remote, branch, updated: true, output: result.stdout || result.stderr };
  } catch (error: any) {
    await audit("git_pull_ff_only", repositoryPath, "failure", error.message);
    throw error;
  }
}

export async function gitCreateBranch(input: { repositoryPath: string; branch: string; startPoint?: string }): Promise<GitExecutionResult> {
  const repositoryPath = await canonicalRepository(input.repositoryPath);
  await requireClean(repositoryPath);
  const branch = validateBranchName(input.branch);
  ensureAllowedNewBranch(branch);
  const startPoint = input.startPoint?.trim() || "HEAD";
  if (startPoint.startsWith("-") || !/^[A-Za-z0-9._/@{}^-]{1,200}$/.test(startPoint)) throw new Error("Invalid startPoint.");
  try {
    await runGit(repositoryPath, ["switch", "-c", branch, startPoint]);
    await audit("git_create_branch", repositoryPath, "success", branch);
    return { repositoryPath, branch, created: true, startPoint };
  } catch (error: any) {
    await audit("git_create_branch", repositoryPath, "failure", error.message);
    throw error;
  }
}

export async function gitCommit(input: { repositoryPath: string; files: string[]; message: string; dryRun?: boolean }): Promise<GitExecutionResult> {
  const repositoryPath = await canonicalRepository(input.repositoryPath);
  const branch = await currentBranch(repositoryPath);
  ensureNotProtected(branch);
  const files = validateRelativePaths(repositoryPath, input.files);
  const message = input.message.trim();
  if (!message || message.length > 160 || /[\r\n]/.test(message)) throw new Error("Commit message must be one line and at most 160 characters.");

  const preStaged = await runGit(repositoryPath, ["diff", "--cached", "--name-only"]);
  const requested = new Set(files.map((file) => file.toLowerCase()));
  const unexpected = preStaged.stdout.split(/\r?\n/).filter(Boolean).filter((file) => !requested.has(file.toLowerCase()));
  if (unexpected.length) throw new Error(`Unexpected pre-staged files are present: ${unexpected.join(", ")}`);

  if (input.dryRun) {
    const preview = await runGit(repositoryPath, ["status", "--short", "--", ...files]);
    await audit("git_commit_dry_run", repositoryPath, "success");
    return { repositoryPath, branch, dryRun: true, files, preview: preview.stdout };
  }

  try {
    await runGit(repositoryPath, ["add", "--", ...files]);
    const staged = await runGit(repositoryPath, ["diff", "--cached", "--name-only"]);
    const stagedFiles = staged.stdout.split(/\r?\n/).filter(Boolean);
    if (!stagedFiles.length) throw new Error("No staged changes to commit.");
    const extra = stagedFiles.filter((file) => !requested.has(file.toLowerCase()));
    if (extra.length) throw new Error(`Refusing commit because unrequested files are staged: ${extra.join(", ")}`);
    await runGit(repositoryPath, ["commit", "-m", message]);
    const { stdout: commitSha } = await runGit(repositoryPath, ["rev-parse", "HEAD"]);
    await audit("git_commit", repositoryPath, "success", commitSha);
    return { repositoryPath, branch, committed: true, commitSha, files: stagedFiles };
  } catch (error: any) {
    await audit("git_commit", repositoryPath, "failure", error.message);
    throw error;
  }
}

export async function gitPush(input: { repositoryPath: string; remote?: string; dryRun?: boolean }): Promise<GitExecutionResult> {
  const repositoryPath = await canonicalRepository(input.repositoryPath);
  const remote = validateRemote(input.remote ?? "origin");
  const branch = await currentBranch(repositoryPath);
  ensureNotProtected(branch);
  try {
    const args = ["push"];
    if (input.dryRun) args.push("--dry-run");
    args.push("--set-upstream", remote, branch);
    const result = await runGit(repositoryPath, args);
    await audit(input.dryRun ? "git_push_dry_run" : "git_push", repositoryPath, "success");
    return { repositoryPath, remote, branch, dryRun: Boolean(input.dryRun), pushed: !input.dryRun, output: result.stderr || result.stdout };
  } catch (error: any) {
    await audit("git_push", repositoryPath, "failure", error.message);
    throw error;
  }
}

async function githubRepository(repositoryPath: string): Promise<{ repositoryPath: string; fullName: string; token: string }> {
  const canonical = await canonicalRepository(repositoryPath);
  const { stdout: origin } = await runGit(canonical, ["remote", "get-url", "origin"]);
  const match = origin.match(/github\.com[/:]([^/\s]+)\/([^/\s]+?)(?:\.git)?$/i);
  if (!match) throw new Error("Origin must be a github.com repository.");
  const fullName = `${match[1]}/${match[2]}`;
  const allowed = csv("CLOUD_DEVOPS_MCP_ALLOWED_GITHUB_REPOSITORIES");
  if (!allowed.some((entry) => entry.toLowerCase() === fullName.toLowerCase())) throw new Error("GitHub repository is not in CLOUD_DEVOPS_MCP_ALLOWED_GITHUB_REPOSITORIES.");
  const token = process.env.CLOUD_DEVOPS_MCP_GITHUB_TOKEN?.trim();
  if (!token) throw new Error("CLOUD_DEVOPS_MCP_GITHUB_TOKEN is required for GitHub actions.");
  return { repositoryPath: canonical, fullName, token };
}

async function githubApi<T>(fullName: string, token: string, path: string, init: RequestInit = {}): Promise<T> {
  const response = await fetch(`https://api.github.com/repos/${fullName}${path}`, {
    ...init,
    headers: {
      Accept: "application/vnd.github+json",
      Authorization: `Bearer ${token}`,
      "X-GitHub-Api-Version": "2022-11-28",
      "User-Agent": "cloud-devops-mcp-server",
      ...(init.headers ?? {})
    },
    signal: AbortSignal.timeout(30_000)
  });
  const text = await response.text();
  if (!response.ok) throw new Error(`GitHub API ${response.status}: ${redact(text).slice(0, 1000)}`);
  return (text ? JSON.parse(text) : {}) as T;
}

export async function githubCreatePullRequest(input: { repositoryPath: string; title: string; body?: string; base?: string; draft?: boolean }): Promise<GitExecutionResult> {
  const { repositoryPath, fullName, token } = await githubRepository(input.repositoryPath);
  const head = await currentBranch(repositoryPath);
  ensureNotProtected(head);
  const base = validateBranchName(input.base ?? "main");
  const title = input.title.trim();
  if (!title || title.length > 256) throw new Error("Pull request title must be 1-256 characters.");
  try {
    const pr = await githubApi<any>(fullName, token, "/pulls", { method: "POST", body: JSON.stringify({ title, body: input.body ?? "", head, base, draft: Boolean(input.draft) }) });
    await audit("github_create_pull_request", repositoryPath, "success", `#${pr.number}`);
    return { repositoryPath, repository: fullName, number: pr.number, url: pr.html_url, state: pr.state, head, base, draft: pr.draft };
  } catch (error: any) {
    await audit("github_create_pull_request", repositoryPath, "failure", error.message);
    throw error;
  }
}

export async function githubCheckPullRequest(input: { repositoryPath: string; pullRequestNumber: number }): Promise<GitExecutionResult> {
  const { repositoryPath, fullName, token } = await githubRepository(input.repositoryPath);
  const number = input.pullRequestNumber;
  if (!Number.isInteger(number) || number < 1) throw new Error("pullRequestNumber must be a positive integer.");
  const pr = await githubApi<any>(fullName, token, `/pulls/${number}`);
  const checks = await githubApi<any>(fullName, token, `/commits/${pr.head.sha}/check-runs?per_page=100`);
  const items = (checks.check_runs ?? []).map((check: any) => ({ name: check.name, status: check.status, conclusion: check.conclusion }));
  const allChecksPassed = items.length > 0 && items.every((check: any) => check.status === "completed" && SUCCESSFUL_CHECK_CONCLUSIONS.has(check.conclusion));
  await audit("github_check_pull_request", repositoryPath, "success", `#${number}`);
  return { repositoryPath, repository: fullName, number, url: pr.html_url, state: pr.state, draft: pr.draft, mergeable: pr.mergeable, mergeableState: pr.mergeable_state, headSha: pr.head.sha, base: pr.base.ref, checks: items, allChecksPassed };
}

export async function githubMergePullRequest(input: { repositoryPath: string; pullRequestNumber: number; confirm: string; method?: "merge" | "squash" | "rebase" }): Promise<GitExecutionResult> {
  if (input.confirm !== "MERGE") throw new Error('Explicit confirmation required: confirm must equal "MERGE".');
  const { repositoryPath, fullName, token } = await githubRepository(input.repositoryPath);
  const status = await githubCheckPullRequest({ repositoryPath, pullRequestNumber: input.pullRequestNumber });
  if (status.state !== "open") throw new Error("Pull request is not open.");
  if (status.draft === true) throw new Error("Draft pull requests cannot be merged.");
  if (status.mergeable === false) throw new Error("Pull request is not mergeable.");
  const checks = status.checks as any[];
  const allowNoChecks = process.env.CLOUD_DEVOPS_MCP_ALLOW_MERGE_WITHOUT_CHECKS === "true";
  if (!status.allChecksPassed && !(allowNoChecks && checks.length === 0)) throw new Error("Required CI checks have not all passed.");
  try {
    const result = await githubApi<any>(fullName, token, `/pulls/${input.pullRequestNumber}/merge`, { method: "PUT", body: JSON.stringify({ merge_method: input.method ?? "squash" }) });
    if (!result.merged) throw new Error(result.message || "GitHub did not merge the pull request.");
    await audit("github_merge_pull_request", repositoryPath, "success", `#${input.pullRequestNumber}`);
    return { repositoryPath, repository: fullName, number: input.pullRequestNumber, merged: true, commitSha: result.sha, message: result.message };
  } catch (error: any) {
    await audit("github_merge_pull_request", repositoryPath, "failure", error.message);
    throw error;
  }
}

export async function githubTriggerWorkflow(input: { repositoryPath: string; workflow: string; ref: string; inputs?: Record<string, string>; confirm: string }): Promise<GitExecutionResult> {
  if (input.confirm !== "TRIGGER") throw new Error('Explicit confirmation required: confirm must equal "TRIGGER".');
  const { repositoryPath, fullName, token } = await githubRepository(input.repositoryPath);
  const workflow = input.workflow.trim();
  const allowedWorkflows = csv("CLOUD_DEVOPS_MCP_ALLOWED_WORKFLOWS");
  if (!allowedWorkflows.includes(workflow)) throw new Error("Workflow is not in CLOUD_DEVOPS_MCP_ALLOWED_WORKFLOWS.");
  const ref = validateBranchName(input.ref);
  try {
    await githubApi<any>(fullName, token, `/actions/workflows/${encodeURIComponent(workflow)}/dispatches`, { method: "POST", body: JSON.stringify({ ref, inputs: input.inputs ?? {} }) });
    await audit("github_trigger_workflow", repositoryPath, "success", `${workflow}@${ref}`);
    return { repositoryPath, repository: fullName, workflow, ref, triggered: true };
  } catch (error: any) {
    await audit("github_trigger_workflow", repositoryPath, "failure", error.message);
    throw error;
  }
}
