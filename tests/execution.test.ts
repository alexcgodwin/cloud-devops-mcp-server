import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { Client, InMemoryTransport } from "@modelcontextprotocol/client";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  gitCommit, gitCreateBranch, gitFetch, gitPullFfOnly, gitPush, gitStatus,
  githubCheckPullRequest, githubCreatePullRequest, githubMergePullRequest, githubTriggerWorkflow
} from "../src/execution.js";
import { createServer } from "../src/index.js";

const exec = promisify(execFile);
let repo = "";
let remote = "";

async function git(...args: string[]) {
  return exec("git", ["-C", repo, ...args], { windowsHide: true });
}

function mockResponse(status: number, body: unknown = {}) {
  return {
    ok: status >= 200 && status < 300,
    status,
    text: async () => status === 204 ? "" : JSON.stringify(body)
  } as Response;
}

describe("controlled execution", () => {
  beforeEach(async () => {
    repo = await mkdtemp(join(tmpdir(), "cloud-devops-mcp-"));
    remote = await mkdtemp(join(tmpdir(), "cloud-devops-remote-"));
    await exec("git", ["init", "--bare", remote], { windowsHide: true });
    await git("init", "-b", "main");
    await git("config", "user.name", "Test User");
    await git("config", "user.email", "test@example.com");
    await writeFile(join(repo, "README.md"), "initial\n");
    await git("add", "README.md");
    await git("commit", "-m", "initial");
    await git("remote", "add", "origin", remote);
    process.env.CLOUD_DEVOPS_MCP_EXECUTION_ENABLED = "true";
    process.env.CLOUD_DEVOPS_MCP_ALLOWED_REPOSITORIES = repo;
  });

  afterEach(async () => {
    vi.unstubAllGlobals();
    for (const key of Object.keys(process.env)) {
      if (key.startsWith("CLOUD_DEVOPS_MCP_")) delete process.env[key];
    }
    await rm(repo, { recursive: true, force: true });
    await rm(remote, { recursive: true, force: true });
  });

  it("reports status, creates a safe branch, previews and commits selected files", async () => {
    expect(await gitStatus({ repositoryPath: repo })).toMatchObject({ branch: "main", clean: true });
    await gitCreateBranch({ repositoryPath: repo, branch: "feature/test-execution" });
    await writeFile(join(repo, "README.md"), "changed\n");
    expect(await gitCommit({ repositoryPath: repo, files: ["README.md"], message: "test", dryRun: true }))
      .toMatchObject({ branch: "feature/test-execution", dryRun: true });
    const committed = await gitCommit({ repositoryPath: repo, files: ["README.md"], message: "test" });
    expect(committed.committed).toBe(true);
  });

  it("blocks commits on protected branches and repositories outside the allowlist", async () => {
    await writeFile(join(repo, "README.md"), "changed\n");
    await expect(gitCommit({ repositoryPath: repo, files: ["README.md"], message: "fail" })).rejects.toThrow(/protected branch/i);
    process.env.CLOUD_DEVOPS_MCP_ALLOWED_REPOSITORIES = join(repo, "other");
    await expect(gitStatus({ repositoryPath: repo })).rejects.toThrow(/not in CLOUD_DEVOPS_MCP_ALLOWED_REPOSITORIES/);
  });

  it("fetches, pushes without force, and only fast-forward pulls the current branch", async () => {
    await gitCreateBranch({ repositoryPath: repo, branch: "feature/sync" });
    await gitFetch({ repositoryPath: repo });
    const preview = await gitPush({ repositoryPath: repo, dryRun: true });
    expect(preview).toMatchObject({ dryRun: true, pushed: false });
    expect(await gitPush({ repositoryPath: repo })).toMatchObject({ pushed: true });
    expect(await gitPullFfOnly({ repositoryPath: repo })).toMatchObject({ branch: "feature/sync", updated: true });
    await expect(gitPullFfOnly({ repositoryPath: repo, branch: "main" })).rejects.toThrow(/currently checked-out branch/);
  });

  it("exposes ten execution tools only when execution is enabled", async () => {
    const server = createServer();
    const client = new Client({ name: "execution-test", version: "1.0.0" });
    const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
    await server.connect(serverTransport);
    await client.connect(clientTransport);
    try {
      const { tools } = await client.listTools();
      expect(tools).toHaveLength(22);
      expect(tools.map((tool) => tool.name)).toEqual(expect.arrayContaining([
        "git_status", "git_fetch", "git_pull_ff_only", "git_create_branch", "git_commit", "git_push",
        "github_create_pull_request", "github_check_pull_request", "github_merge_pull_request", "github_trigger_workflow"
      ]));
    } finally {
      await client.close();
      await server.close();
    }
  });

  it("creates and checks pull requests through an allowlisted GitHub repository", async () => {
    await git("remote", "set-url", "origin", "https://github.com/example/test-repo.git");
    await gitCreateBranch({ repositoryPath: repo, branch: "feature/github" });
    process.env.CLOUD_DEVOPS_MCP_ALLOWED_GITHUB_REPOSITORIES = "example/test-repo";
    process.env.CLOUD_DEVOPS_MCP_GITHUB_TOKEN = "github_pat_" + "a".repeat(30);

    const fetchMock = vi.fn()
      .mockResolvedValueOnce(mockResponse(201, { number: 7, html_url: "https://github.com/example/test-repo/pull/7", state: "open", draft: false }))
      .mockResolvedValueOnce(mockResponse(200, { html_url: "https://github.com/example/test-repo/pull/7", state: "open", draft: false, mergeable: true, mergeable_state: "clean", head: { sha: "a".repeat(40) }, base: { ref: "main" } }))
      .mockResolvedValueOnce(mockResponse(200, { check_runs: [{ name: "CI", status: "completed", conclusion: "success" }] }));
    vi.stubGlobal("fetch", fetchMock);

    expect(await githubCreatePullRequest({ repositoryPath: repo, title: "Test PR" })).toMatchObject({ number: 7, head: "feature/github" });
    expect(await githubCheckPullRequest({ repositoryPath: repo, pullRequestNumber: 7 })).toMatchObject({ allChecksPassed: true, mergeable: true });
    expect(fetchMock).toHaveBeenCalledTimes(3);
  });

  it("requires explicit merge/workflow confirmation and passing checks", async () => {
    await git("remote", "set-url", "origin", "https://github.com/example/test-repo.git");
    process.env.CLOUD_DEVOPS_MCP_ALLOWED_GITHUB_REPOSITORIES = "example/test-repo";
    process.env.CLOUD_DEVOPS_MCP_GITHUB_TOKEN = "github_pat_" + "b".repeat(30);
    process.env.CLOUD_DEVOPS_MCP_ALLOWED_WORKFLOWS = "ci.yml";

    await expect(githubMergePullRequest({ repositoryPath: repo, pullRequestNumber: 2, confirm: "NO" }))
      .rejects.toThrow(/Explicit confirmation/);
    await expect(githubTriggerWorkflow({ repositoryPath: repo, workflow: "ci.yml", ref: "main", confirm: "NO" }))
      .rejects.toThrow(/Explicit confirmation/);

    const fetchMock = vi.fn()
      .mockResolvedValueOnce(mockResponse(200, { html_url: "https://github.com/example/test-repo/pull/2", state: "open", draft: false, mergeable: true, mergeable_state: "clean", head: { sha: "b".repeat(40) }, base: { ref: "main" } }))
      .mockResolvedValueOnce(mockResponse(200, { check_runs: [{ name: "CI", status: "completed", conclusion: "success" }] }))
      .mockResolvedValueOnce(mockResponse(200, { merged: true, sha: "c".repeat(40), message: "merged" }))
      .mockResolvedValueOnce(mockResponse(204));
    vi.stubGlobal("fetch", fetchMock);

    expect(await githubMergePullRequest({ repositoryPath: repo, pullRequestNumber: 2, confirm: "MERGE" })).toMatchObject({ merged: true });
    expect(await githubTriggerWorkflow({ repositoryPath: repo, workflow: "ci.yml", ref: "main", confirm: "TRIGGER" })).toMatchObject({ triggered: true });
  });
});
