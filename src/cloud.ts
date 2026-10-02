import { appendFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { resolve } from "node:path";
import { defaultCommandRunner, type CommandRunner } from "./infrastructure.js";

export type CloudProvider = "aws" | "azure" | "gcp";

type ScopeInput = {
  provider: CloudProvider;
  region?: string;
  profile?: string;
  subscriptionId?: string;
  projectId?: string;
};

type NormalizedResource = {
  id: string;
  name: string;
  type: string;
  location: string;
  state?: string;
};

function csv(name: string): string[] {
  const raw = process.env[name]?.trim();
  return raw ? raw.split(",").map((value) => value.trim()).filter(Boolean) : [];
}

function ensureEnabled(): void {
  if (process.env.CLOUD_DEVOPS_MCP_CLOUD_INVENTORY_ENABLED !== "true") {
    throw new Error(
      "Live cloud inventory is disabled. Set CLOUD_DEVOPS_MCP_CLOUD_INVENTORY_ENABLED=true to enable it."
    );
  }
}

function redact(value: string): string {
  return value
    .replace(/AKIA[0-9A-Z]{16}/g, "[REDACTED_AWS_ACCESS_KEY]")
    .replace(/(token|password|secret|client_secret|access_key)\s*[=:]\s*[^\s,;]+/gi, "$1=[REDACTED]")
    .replace(/Bearer\s+[A-Za-z0-9._~+\/-]+=*/gi, "Bearer [REDACTED]");
}

async function audit(action: string, scope: string, outcome: "success" | "failure", detail?: string): Promise<void> {
  const record = JSON.stringify({
    timestamp: new Date().toISOString(),
    action,
    scope,
    outcome,
    detail: detail ? redact(detail).slice(0, 2000) : undefined
  });
  const auditPath = process.env.CLOUD_DEVOPS_MCP_AUDIT_LOG || resolve(tmpdir(), "cloud-devops-mcp-audit.jsonl");
  await appendFile(auditPath, record + "\n", "utf8").catch(() => undefined);
}

function safeIdentifier(value: string, label: string, pattern: RegExp): string {
  const trimmed = value.trim();
  if (!trimmed || trimmed.startsWith("-") || !pattern.test(trimmed)) {
    throw new Error(`Invalid ${label}.`);
  }
  return trimmed;
}

function safeRegion(region?: string): string {
  if (!region) throw new Error("AWS region is required.");
  const value = safeIdentifier(region, "AWS region", /^[a-z]{2}(?:-gov)?-[a-z]+-\d$/);
  const allowed = csv("CLOUD_DEVOPS_MCP_ALLOWED_AWS_REGIONS");
  if (!allowed.includes(value)) throw new Error("AWS region is not in CLOUD_DEVOPS_MCP_ALLOWED_AWS_REGIONS.");
  return value;
}

function safeProfile(profile?: string): string | undefined {
  if (!profile) return undefined;
  const value = safeIdentifier(profile, "AWS profile", /^[A-Za-z0-9._-]{1,128}$/);
  const allowed = csv("CLOUD_DEVOPS_MCP_ALLOWED_AWS_PROFILES");
  if (!allowed.includes(value)) throw new Error("AWS profile is not in CLOUD_DEVOPS_MCP_ALLOWED_AWS_PROFILES.");
  return value;
}

function safeSubscription(subscriptionId?: string): string {
  if (!subscriptionId) throw new Error("Azure subscriptionId is required.");
  const value = safeIdentifier(subscriptionId, "Azure subscription ID", /^[0-9a-fA-F-]{36}$/);
  const allowed = csv("CLOUD_DEVOPS_MCP_ALLOWED_AZURE_SUBSCRIPTIONS").map((item) => item.toLowerCase());
  if (!allowed.includes(value.toLowerCase())) {
    throw new Error("Azure subscription is not in CLOUD_DEVOPS_MCP_ALLOWED_AZURE_SUBSCRIPTIONS.");
  }
  return value;
}

function safeProject(projectId?: string): string {
  if (!projectId) throw new Error("GCP projectId is required.");
  const value = safeIdentifier(projectId, "GCP project ID", /^[a-z][a-z0-9-]{4,28}[a-z0-9]$/);
  const allowed = csv("CLOUD_DEVOPS_MCP_ALLOWED_GCP_PROJECTS");
  if (!allowed.includes(value)) throw new Error("GCP project is not in CLOUD_DEVOPS_MCP_ALLOWED_GCP_PROJECTS.");
  return value;
}

function parseJson(stdout: string, label: string): any {
  try {
    return JSON.parse(stdout || "{}");
  } catch {
    throw new Error(`${label} did not return valid JSON.`);
  }
}

function awsBaseArgs(input: ScopeInput): string[] {
  const args: string[] = [];
  const profile = safeProfile(input.profile);
  if (profile) args.push("--profile", profile);
  args.push("--region", safeRegion(input.region));
  return args;
}

async function assertAwsAccount(input: ScopeInput, runner: CommandRunner): Promise<{ accountId: string; arn: string }> {
  const result = await runner(
    "aws",
    [...awsBaseArgs(input), "sts", "get-caller-identity", "--output", "json", "--no-cli-pager"],
    process.cwd()
  );
  const payload = parseJson(result.stdout, "aws sts get-caller-identity");
  const accountId = String(payload.Account ?? "");
  const arn = String(payload.Arn ?? "");
  const allowed = csv("CLOUD_DEVOPS_MCP_ALLOWED_AWS_ACCOUNTS");
  if (!allowed.includes(accountId)) throw new Error("AWS account is not in CLOUD_DEVOPS_MCP_ALLOWED_AWS_ACCOUNTS.");
  return { accountId, arn };
}

function normalizeAwsResources(payload: any, region: string): NormalizedResource[] {
  const mappings = Array.isArray(payload?.ResourceTagMappingList) ? payload.ResourceTagMappingList : [];
  return mappings.slice(0, 500).map((item: any) => {
    const arn = String(item?.ResourceARN ?? "");
    const tags = Array.isArray(item?.Tags) ? item.Tags : [];
    const nameTag = tags.find((tag: any) => tag?.Key === "Name")?.Value;
    const parts = arn.split(/[:/]/).filter(Boolean);
    const type = parts.length > 4 ? parts.slice(5, 7).join("/") || parts[5] || "resource" : "resource";
    return {
      id: arn,
      name: String(nameTag ?? parts.at(-1) ?? arn),
      type,
      location: region
    };
  });
}

function normalizeAzureResources(payload: any[]): NormalizedResource[] {
  return payload.slice(0, 500).map((item: any) => ({
    id: String(item?.id ?? ""),
    name: String(item?.name ?? ""),
    type: String(item?.type ?? ""),
    location: String(item?.location ?? "")
  }));
}

function normalizeGcpResources(payload: any[]): NormalizedResource[] {
  return payload.slice(0, 500).map((item: any) => ({
    id: String(item?.name ?? ""),
    name: String(item?.displayName ?? item?.name?.split("/").at(-1) ?? ""),
    type: String(item?.assetType ?? ""),
    location: String(item?.location ?? item?.additionalAttributes?.location ?? "")
  }));
}

async function inventoryForScope(input: ScopeInput, runner: CommandRunner): Promise<{ scope: string; resources: NormalizedResource[]; source: string }> {
  if (input.provider === "aws") {
    const region = safeRegion(input.region);
    const identity = await assertAwsAccount(input, runner);
    const result = await runner(
      "aws",
      [
        ...awsBaseArgs(input),
        "resourcegroupstaggingapi",
        "get-resources",
        "--resources-per-page",
        "100",
        "--output",
        "json",
        "--no-cli-pager"
      ],
      process.cwd()
    );
    return {
      scope: `${identity.accountId}:${region}`,
      resources: normalizeAwsResources(parseJson(result.stdout, "AWS inventory"), region),
      source: "aws-resource-groups-tagging-api"
    };
  }

  if (input.provider === "azure") {
    const subscriptionId = safeSubscription(input.subscriptionId);
    const result = await runner(
      "az",
      ["resource", "list", "--subscription", subscriptionId, "--output", "json", "--only-show-errors"],
      process.cwd()
    );
    const payload = parseJson(result.stdout, "Azure inventory");
    return {
      scope: subscriptionId,
      resources: normalizeAzureResources(Array.isArray(payload) ? payload : []),
      source: "azure-resource-manager"
    };
  }

  const projectId = safeProject(input.projectId);
  const result = await runner(
    "gcloud",
    [
      "asset",
      "search-all-resources",
      `--scope=projects/${projectId}`,
      "--format=json",
      "--limit=500",
      "--quiet"
    ],
    process.cwd()
  );
  const payload = parseJson(result.stdout, "GCP inventory");
  return {
    scope: projectId,
    resources: normalizeGcpResources(Array.isArray(payload) ? payload : []),
    source: "gcp-cloud-asset-inventory"
  };
}

export async function cloudWhoAmI(input: ScopeInput, runner: CommandRunner = defaultCommandRunner) {
  ensureEnabled();
  try {
    if (input.provider === "aws") {
      const region = safeRegion(input.region);
      const identity = await assertAwsAccount(input, runner);
      const result = {
        provider: "aws" as const,
        scope: `${identity.accountId}:${region}`,
        subject: identity.arn,
        region
      };
      await audit("cloud_whoami", result.scope, "success");
      return result;
    }

    if (input.provider === "azure") {
      const subscriptionId = safeSubscription(input.subscriptionId);
      const response = await runner(
        "az",
        ["account", "show", "--subscription", subscriptionId, "--output", "json", "--only-show-errors"],
        process.cwd()
      );
      const payload = parseJson(response.stdout, "Azure account");
      const result = {
        provider: "azure" as const,
        scope: subscriptionId,
        subject: String(payload.user?.name ?? payload.tenantId ?? ""),
        region: ""
      };
      await audit("cloud_whoami", result.scope, "success");
      return result;
    }

    const projectId = safeProject(input.projectId);
    const response = await runner(
      "gcloud",
      ["auth", "list", "--filter=status:ACTIVE", "--format=json(account)", "--quiet"],
      process.cwd()
    );
    const payload = parseJson(response.stdout, "GCP auth");
    const subject = Array.isArray(payload) && payload[0] ? String(payload[0].account ?? "") : "";
    const result = { provider: "gcp" as const, scope: projectId, subject, region: "" };
    await audit("cloud_whoami", result.scope, "success");
    return result;
  } catch (error: any) {
    await audit("cloud_whoami", input.provider, "failure", error.message);
    throw error;
  }
}

export async function cloudInventorySummary(input: ScopeInput, runner: CommandRunner = defaultCommandRunner) {
  ensureEnabled();
  try {
    const inventory = await inventoryForScope(input, runner);
    const typeCounts: Record<string, number> = {};
    for (const resource of inventory.resources) {
      const type = resource.type || "unknown";
      typeCounts[type] = (typeCounts[type] ?? 0) + 1;
    }
    const result = {
      provider: input.provider,
      scope: inventory.scope,
      source: inventory.source,
      resourceCount: inventory.resources.length,
      typeCounts,
      resources: inventory.resources.slice(0, 200)
    };
    await audit("cloud_inventory_summary", inventory.scope, "success", `${result.resourceCount} resources`);
    return result;
  } catch (error: any) {
    await audit("cloud_inventory_summary", input.provider, "failure", error.message);
    throw error;
  }
}

export async function cloudKubernetesClusters(input: ScopeInput, runner: CommandRunner = defaultCommandRunner) {
  ensureEnabled();
  try {
    if (input.provider === "aws") {
      const region = safeRegion(input.region);
      const identity = await assertAwsAccount(input, runner);
      const response = await runner(
        "aws",
        [...awsBaseArgs(input), "eks", "list-clusters", "--output", "json", "--no-cli-pager"],
        process.cwd()
      );
      const payload = parseJson(response.stdout, "AWS EKS inventory");
      const clusters = (Array.isArray(payload.clusters) ? payload.clusters : []).slice(0, 100).map((name: any) => ({
        name: String(name),
        location: region,
        state: "listed"
      }));
      await audit("cloud_kubernetes_clusters", `${identity.accountId}:${region}`, "success");
      return { provider: "aws" as const, scope: `${identity.accountId}:${region}`, clusterCount: clusters.length, clusters };
    }

    if (input.provider === "azure") {
      const subscriptionId = safeSubscription(input.subscriptionId);
      const response = await runner(
        "az",
        ["aks", "list", "--subscription", subscriptionId, "--output", "json", "--only-show-errors"],
        process.cwd()
      );
      const payload = parseJson(response.stdout, "Azure AKS inventory");
      const clusters = (Array.isArray(payload) ? payload : []).slice(0, 100).map((item: any) => ({
        name: String(item?.name ?? ""),
        location: String(item?.location ?? ""),
        state: String(item?.provisioningState ?? "")
      }));
      await audit("cloud_kubernetes_clusters", subscriptionId, "success");
      return { provider: "azure" as const, scope: subscriptionId, clusterCount: clusters.length, clusters };
    }

    const projectId = safeProject(input.projectId);
    const response = await runner(
      "gcloud",
      ["container", "clusters", "list", "--project", projectId, "--format=json", "--quiet"],
      process.cwd()
    );
    const payload = parseJson(response.stdout, "GCP GKE inventory");
    const clusters = (Array.isArray(payload) ? payload : []).slice(0, 100).map((item: any) => ({
      name: String(item?.name ?? ""),
      location: String(item?.location ?? item?.zone ?? ""),
      state: String(item?.status ?? "")
    }));
    await audit("cloud_kubernetes_clusters", projectId, "success");
    return { provider: "gcp" as const, scope: projectId, clusterCount: clusters.length, clusters };
  } catch (error: any) {
    await audit("cloud_kubernetes_clusters", input.provider, "failure", error.message);
    throw error;
  }
}

export async function cloudObservabilitySummary(input: ScopeInput, runner: CommandRunner = defaultCommandRunner) {
  ensureEnabled();
  try {
    if (input.provider === "aws") {
      const region = safeRegion(input.region);
      const identity = await assertAwsAccount(input, runner);
      const response = await runner(
        "aws",
        [...awsBaseArgs(input), "cloudwatch", "describe-alarms", "--output", "json", "--no-cli-pager"],
        process.cwd()
      );
      const payload = parseJson(response.stdout, "AWS CloudWatch alarms");
      const alarms = [
        ...(Array.isArray(payload.MetricAlarms) ? payload.MetricAlarms : []),
        ...(Array.isArray(payload.CompositeAlarms) ? payload.CompositeAlarms : [])
      ].slice(0, 200);
      const states: Record<string, number> = {};
      for (const alarm of alarms) {
        const state = String(alarm?.StateValue ?? "UNKNOWN");
        states[state] = (states[state] ?? 0) + 1;
      }
      const scope = `${identity.accountId}:${region}`;
      await audit("cloud_observability_summary", scope, "success");
      return { provider: "aws" as const, scope, signalType: "cloudwatch-alarms", configuredCount: alarms.length, stateCounts: states };
    }

    if (input.provider === "azure") {
      const subscriptionId = safeSubscription(input.subscriptionId);
      const response = await runner(
        "az",
        ["monitor", "metrics", "alert", "list", "--subscription", subscriptionId, "--output", "json", "--only-show-errors"],
        process.cwd()
      );
      const payload = parseJson(response.stdout, "Azure metric alerts");
      const alerts = Array.isArray(payload) ? payload.slice(0, 200) : [];
      const enabled = alerts.filter((item: any) => item?.enabled === true).length;
      await audit("cloud_observability_summary", subscriptionId, "success");
      return {
        provider: "azure" as const,
        scope: subscriptionId,
        signalType: "azure-metric-alerts",
        configuredCount: alerts.length,
        stateCounts: { enabled, disabled: alerts.length - enabled }
      };
    }

    const projectId = safeProject(input.projectId);
    const response = await runner(
      "gcloud",
      ["logging", "sinks", "list", "--project", projectId, "--format=json", "--quiet"],
      process.cwd()
    );
    const payload = parseJson(response.stdout, "GCP logging sinks");
    const sinks = Array.isArray(payload) ? payload.slice(0, 200) : [];
    await audit("cloud_observability_summary", projectId, "success");
    return {
      provider: "gcp" as const,
      scope: projectId,
      signalType: "gcp-logging-sinks",
      configuredCount: sinks.length,
      stateCounts: { configured: sinks.length }
    };
  } catch (error: any) {
    await audit("cloud_observability_summary", input.provider, "failure", error.message);
    throw error;
  }
}

export async function cloudFinOpsSignals(input: ScopeInput, runner: CommandRunner = defaultCommandRunner) {
  ensureEnabled();
  try {
    if (input.provider === "aws") {
      const region = safeRegion(input.region);
      const identity = await assertAwsAccount(input, runner);
      const volumesResponse = await runner(
        "aws",
        [...awsBaseArgs(input), "ec2", "describe-volumes", "--filters", "Name=status,Values=available", "--output", "json", "--no-cli-pager"],
        process.cwd()
      );
      const addressesResponse = await runner(
        "aws",
        [...awsBaseArgs(input), "ec2", "describe-addresses", "--output", "json", "--no-cli-pager"],
        process.cwd()
      );
      const volumes = parseJson(volumesResponse.stdout, "AWS volumes").Volumes ?? [];
      const addresses = parseJson(addressesResponse.stdout, "AWS addresses").Addresses ?? [];
      const findings = [
        ...volumes.slice(0, 100).map((item: any) => ({
          ruleId: "AWS_UNUSED_EBS_VOLUME",
          resourceId: String(item?.VolumeId ?? ""),
          detail: `Available EBS volume ${String(item?.Size ?? "?")} GiB`
        })),
        ...addresses.filter((item: any) => !item?.AssociationId).slice(0, 100).map((item: any) => ({
          ruleId: "AWS_UNASSOCIATED_ELASTIC_IP",
          resourceId: String(item?.AllocationId ?? item?.PublicIp ?? ""),
          detail: "Elastic IP is not associated with a resource."
        }))
      ];
      const scope = `${identity.accountId}:${region}`;
      await audit("cloud_finops_signals", scope, "success", `${findings.length} findings`);
      return { provider: "aws" as const, scope, findingCount: findings.length, findings };
    }

    if (input.provider === "azure") {
      const subscriptionId = safeSubscription(input.subscriptionId);
      const disksResponse = await runner(
        "az",
        ["disk", "list", "--subscription", subscriptionId, "--output", "json", "--only-show-errors"],
        process.cwd()
      );
      const ipsResponse = await runner(
        "az",
        ["network", "public-ip", "list", "--subscription", subscriptionId, "--output", "json", "--only-show-errors"],
        process.cwd()
      );
      const disks = parseJson(disksResponse.stdout, "Azure disks");
      const ips = parseJson(ipsResponse.stdout, "Azure public IPs");
      const findings = [
        ...(Array.isArray(disks) ? disks : []).filter((item: any) => !item?.managedBy && String(item?.diskState ?? "").toLowerCase() === "unattached").slice(0, 100).map((item: any) => ({
          ruleId: "AZURE_UNATTACHED_DISK",
          resourceId: String(item?.id ?? item?.name ?? ""),
          detail: "Managed disk is unattached."
        })),
        ...(Array.isArray(ips) ? ips : []).filter((item: any) => !item?.ipConfiguration).slice(0, 100).map((item: any) => ({
          ruleId: "AZURE_UNASSOCIATED_PUBLIC_IP",
          resourceId: String(item?.id ?? item?.name ?? ""),
          detail: "Public IP has no IP configuration association."
        }))
      ];
      await audit("cloud_finops_signals", subscriptionId, "success", `${findings.length} findings`);
      return { provider: "azure" as const, scope: subscriptionId, findingCount: findings.length, findings };
    }

    const projectId = safeProject(input.projectId);
    const disksResponse = await runner(
      "gcloud",
      ["compute", "disks", "list", "--project", projectId, "--format=json", "--quiet"],
      process.cwd()
    );
    const addressesResponse = await runner(
      "gcloud",
      ["compute", "addresses", "list", "--project", projectId, "--format=json", "--quiet"],
      process.cwd()
    );
    const disks = parseJson(disksResponse.stdout, "GCP disks");
    const addresses = parseJson(addressesResponse.stdout, "GCP addresses");
    const findings = [
      ...(Array.isArray(disks) ? disks : []).filter((item: any) => !Array.isArray(item?.users) || item.users.length === 0).slice(0, 100).map((item: any) => ({
        ruleId: "GCP_UNUSED_DISK",
        resourceId: String(item?.selfLink ?? item?.name ?? ""),
        detail: "Persistent disk has no attached users."
      })),
      ...(Array.isArray(addresses) ? addresses : []).filter((item: any) => String(item?.status ?? "").toUpperCase() === "RESERVED").slice(0, 100).map((item: any) => ({
        ruleId: "GCP_UNUSED_STATIC_ADDRESS",
        resourceId: String(item?.selfLink ?? item?.name ?? ""),
        detail: "Static IP address is reserved but not in use."
      }))
    ];
    await audit("cloud_finops_signals", projectId, "success", `${findings.length} findings`);
    return { provider: "gcp" as const, scope: projectId, findingCount: findings.length, findings };
  } catch (error: any) {
    await audit("cloud_finops_signals", input.provider, "failure", error.message);
    throw error;
  }
}

export async function cloudDriftCompare(
  input: ScopeInput & { expectedResourceIds: string[]; includeUnexpected?: boolean },
  runner: CommandRunner = defaultCommandRunner
) {
  ensureEnabled();
  if (!input.expectedResourceIds.length || input.expectedResourceIds.length > 500) {
    throw new Error("expectedResourceIds must contain between 1 and 500 entries.");
  }
  const expected = [...new Set(input.expectedResourceIds.map((item) => item.trim()).filter(Boolean))];
  if (expected.some((item) => item.length > 1000 || /[\r\n\0]/.test(item))) {
    throw new Error("Invalid expected resource identifier.");
  }

  try {
    const inventory = await inventoryForScope(input, runner);
    const liveIds = new Set(inventory.resources.flatMap((resource) => [resource.id, resource.name]).filter(Boolean));
    const expectedSet = new Set(expected);
    const missingExpected = expected.filter((item) => !liveIds.has(item));
    const unexpectedLive = input.includeUnexpected === false
      ? []
      : inventory.resources
          .filter((resource) => !expectedSet.has(resource.id) && !expectedSet.has(resource.name))
          .slice(0, 200)
          .map((resource) => resource.id || resource.name);

    const result = {
      provider: input.provider,
      scope: inventory.scope,
      expectedCount: expected.length,
      liveCount: inventory.resources.length,
      missingExpected,
      unexpectedLive,
      driftDetected: missingExpected.length > 0 || unexpectedLive.length > 0
    };
    await audit("cloud_drift_compare", inventory.scope, "success", `missing=${missingExpected.length},unexpected=${unexpectedLive.length}`);
    return result;
  } catch (error: any) {
    await audit("cloud_drift_compare", input.provider, "failure", error.message);
    throw error;
  }
}
