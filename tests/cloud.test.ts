import { Client, InMemoryTransport } from "@modelcontextprotocol/client";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { createServer } from "../src/index.js";
import {
  cloudDriftCompare,
  cloudFinOpsSignals,
  cloudInventorySummary,
  cloudKubernetesClusters,
  cloudObservabilitySummary,
  cloudWhoAmI
} from "../src/cloud.js";
import type { CommandRunner } from "../src/infrastructure.js";

function sequenceRunner(results: Array<{ stdout?: string; stderr?: string; exitCode?: number }>) {
  const calls: Array<{ executable: string; args: string[] }> = [];
  const runner: CommandRunner = async (executable, args) => {
    calls.push({ executable, args });
    const next = results.shift() ?? {};
    return {
      stdout: next.stdout ?? "",
      stderr: next.stderr ?? "",
      exitCode: next.exitCode ?? 0
    };
  };
  return { runner, calls };
}

const awsScope = { provider: "aws" as const, region: "ca-central-1", profile: "dev" };
const azureScope = { provider: "azure" as const, subscriptionId: "11111111-1111-1111-1111-111111111111" };
const gcpScope = { provider: "gcp" as const, projectId: "test-project" };

describe("live multi-cloud inventory", () => {
  beforeEach(() => {
    process.env.CLOUD_DEVOPS_MCP_CLOUD_INVENTORY_ENABLED = "true";
    process.env.CLOUD_DEVOPS_MCP_ALLOWED_AWS_ACCOUNTS = "123456789012";
    process.env.CLOUD_DEVOPS_MCP_ALLOWED_AWS_REGIONS = "ca-central-1,us-east-1";
    process.env.CLOUD_DEVOPS_MCP_ALLOWED_AWS_PROFILES = "dev";
    process.env.CLOUD_DEVOPS_MCP_ALLOWED_AZURE_SUBSCRIPTIONS = azureScope.subscriptionId;
    process.env.CLOUD_DEVOPS_MCP_ALLOWED_GCP_PROJECTS = gcpScope.projectId;
  });

  afterEach(() => {
    for (const key of Object.keys(process.env)) {
      if (key.startsWith("CLOUD_DEVOPS_MCP_")) delete process.env[key];
    }
  });

  it("verifies allowlisted identities for AWS, Azure and GCP", async () => {
    const aws = sequenceRunner([{
      stdout: JSON.stringify({ Account: "123456789012", Arn: "arn:aws:iam::123456789012:user/test" })
    }]);
    expect(await cloudWhoAmI(awsScope, aws.runner)).toMatchObject({
      provider: "aws",
      scope: "123456789012:ca-central-1"
    });
    expect(aws.calls[0]).toMatchObject({ executable: "aws" });
    expect(aws.calls[0].args).toEqual(expect.arrayContaining(["sts", "get-caller-identity", "--region", "ca-central-1"]));

    const azure = sequenceRunner([{
      stdout: JSON.stringify({ tenantId: "tenant", user: { name: "engineer@example.com" } })
    }]);
    expect(await cloudWhoAmI(azureScope, azure.runner)).toMatchObject({
      provider: "azure",
      scope: azureScope.subscriptionId,
      subject: "engineer@example.com"
    });

    const gcp = sequenceRunner([{ stdout: JSON.stringify([{ account: "svc@test-project.iam.gserviceaccount.com" }]) }]);
    expect(await cloudWhoAmI(gcpScope, gcp.runner)).toMatchObject({
      provider: "gcp",
      scope: "test-project",
      subject: "svc@test-project.iam.gserviceaccount.com"
    });
  });

  it("normalizes live inventories across AWS, Azure and GCP", async () => {
    const aws = sequenceRunner([
      { stdout: JSON.stringify({ Account: "123456789012", Arn: "arn:aws:sts::123456789012:assumed-role/Test/session" }) },
      { stdout: JSON.stringify({ ResourceTagMappingList: [
        { ResourceARN: "arn:aws:ec2:ca-central-1:123456789012:instance/i-123", Tags: [{ Key: "Name", Value: "api" }] },
        { ResourceARN: "arn:aws:rds:ca-central-1:123456789012:db:app", Tags: [] }
      ] }) }
    ]);
    const awsResult = await cloudInventorySummary(awsScope, aws.runner);
    expect(awsResult).toMatchObject({ provider: "aws", resourceCount: 2, source: "aws-resource-groups-tagging-api" });
    expect(awsResult.resources[0].name).toBe("api");

    const azure = sequenceRunner([{ stdout: JSON.stringify([
      { id: "/subscriptions/1/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm1", name: "vm1", type: "Microsoft.Compute/virtualMachines", location: "canadacentral" }
    ]) }]);
    expect(await cloudInventorySummary(azureScope, azure.runner)).toMatchObject({
      provider: "azure",
      resourceCount: 1,
      typeCounts: { "Microsoft.Compute/virtualMachines": 1 }
    });

    const gcp = sequenceRunner([{ stdout: JSON.stringify([
      { name: "//compute.googleapis.com/projects/test-project/zones/a/instances/vm1", displayName: "vm1", assetType: "compute.googleapis.com/Instance", location: "northamerica-northeast2-a" }
    ]) }]);
    expect(await cloudInventorySummary(gcpScope, gcp.runner)).toMatchObject({
      provider: "gcp",
      resourceCount: 1,
      source: "gcp-cloud-asset-inventory"
    });
  });

  it("lists managed Kubernetes clusters across providers", async () => {
    const aws = sequenceRunner([
      { stdout: JSON.stringify({ Account: "123456789012", Arn: "arn:aws:iam::123456789012:role/test" }) },
      { stdout: JSON.stringify({ clusters: ["prod-eks", "dev-eks"] }) }
    ]);
    expect(await cloudKubernetesClusters(awsScope, aws.runner)).toMatchObject({ provider: "aws", clusterCount: 2 });

    const azure = sequenceRunner([{ stdout: JSON.stringify([
      { name: "prod-aks", location: "canadacentral", provisioningState: "Succeeded" }
    ]) }]);
    expect(await cloudKubernetesClusters(azureScope, azure.runner)).toMatchObject({
      provider: "azure",
      clusterCount: 1,
      clusters: [{ name: "prod-aks", location: "canadacentral", state: "Succeeded" }]
    });

    const gcp = sequenceRunner([{ stdout: JSON.stringify([
      { name: "prod-gke", location: "northamerica-northeast2", status: "RUNNING" }
    ]) }]);
    expect(await cloudKubernetesClusters(gcpScope, gcp.runner)).toMatchObject({
      provider: "gcp",
      clusterCount: 1
    });
  });

  it("summarizes cloud observability configuration without changing it", async () => {
    const aws = sequenceRunner([
      { stdout: JSON.stringify({ Account: "123456789012", Arn: "arn:aws:iam::123456789012:role/test" }) },
      { stdout: JSON.stringify({
        MetricAlarms: [{ StateValue: "OK" }, { StateValue: "ALARM" }],
        CompositeAlarms: [{ StateValue: "OK" }]
      }) }
    ]);
    expect(await cloudObservabilitySummary(awsScope, aws.runner)).toMatchObject({
      signalType: "cloudwatch-alarms",
      configuredCount: 3,
      stateCounts: { OK: 2, ALARM: 1 }
    });

    const azure = sequenceRunner([{ stdout: JSON.stringify([{ enabled: true }, { enabled: false }, { enabled: true }]) }]);
    expect(await cloudObservabilitySummary(azureScope, azure.runner)).toMatchObject({
      signalType: "azure-metric-alerts",
      configuredCount: 3,
      stateCounts: { enabled: 2, disabled: 1 }
    });

    const gcp = sequenceRunner([{ stdout: JSON.stringify([{ name: "audit-sink" }, { name: "security-sink" }]) }]);
    expect(await cloudObservabilitySummary(gcpScope, gcp.runner)).toMatchObject({
      signalType: "gcp-logging-sinks",
      configuredCount: 2
    });
  });

  it("detects read-only FinOps waste signals across providers", async () => {
    const aws = sequenceRunner([
      { stdout: JSON.stringify({ Account: "123456789012", Arn: "arn:aws:iam::123456789012:role/test" }) },
      { stdout: JSON.stringify({ Volumes: [{ VolumeId: "vol-1", Size: 100 }] }) },
      { stdout: JSON.stringify({ Addresses: [{ AllocationId: "eipalloc-1" }, { AllocationId: "eipalloc-2", AssociationId: "eipassoc-1" }] }) }
    ]);
    const awsResult = await cloudFinOpsSignals(awsScope, aws.runner);
    expect(awsResult.findingCount).toBe(2);
    expect(awsResult.findings.map((item) => item.ruleId)).toEqual(expect.arrayContaining([
      "AWS_UNUSED_EBS_VOLUME",
      "AWS_UNASSOCIATED_ELASTIC_IP"
    ]));

    const azure = sequenceRunner([
      { stdout: JSON.stringify([{ id: "/disk/1", diskState: "Unattached", managedBy: null }, { id: "/disk/2", diskState: "Attached", managedBy: "/vm/1" }]) },
      { stdout: JSON.stringify([{ id: "/ip/1", ipConfiguration: null }, { id: "/ip/2", ipConfiguration: { id: "/nic/1" } }]) }
    ]);
    expect(await cloudFinOpsSignals(azureScope, azure.runner)).toMatchObject({ provider: "azure", findingCount: 2 });

    const gcp = sequenceRunner([
      { stdout: JSON.stringify([{ name: "disk-1", users: [] }, { name: "disk-2", users: ["vm-1"] }]) },
      { stdout: JSON.stringify([{ name: "ip-1", status: "RESERVED" }, { name: "ip-2", status: "IN_USE" }]) }
    ]);
    expect(await cloudFinOpsSignals(gcpScope, gcp.runner)).toMatchObject({ provider: "gcp", findingCount: 2 });
  });

  it("compares expected resources with live inventory without reconciling drift", async () => {
    const azure = sequenceRunner([{ stdout: JSON.stringify([
      { id: "/resource/a", name: "a", type: "type/a", location: "canadacentral" },
      { id: "/resource/b", name: "b", type: "type/b", location: "canadacentral" }
    ]) }]);
    const result = await cloudDriftCompare({
      ...azureScope,
      expectedResourceIds: ["/resource/a", "/resource/missing"],
      includeUnexpected: true
    }, azure.runner);
    expect(result).toMatchObject({
      driftDetected: true,
      missingExpected: ["/resource/missing"],
      unexpectedLive: ["/resource/b"]
    });

    const hiddenUnexpected = sequenceRunner([{ stdout: JSON.stringify([{ id: "/resource/a", name: "a", type: "type/a", location: "canadacentral" }]) }]);
    expect(await cloudDriftCompare({
      ...azureScope,
      expectedResourceIds: ["/resource/a"],
      includeUnexpected: false
    }, hiddenUnexpected.runner)).toMatchObject({
      driftDetected: false,
      unexpectedLive: []
    });
  });

  it("fails closed for disabled or unapproved cloud scopes", async () => {
    const never: CommandRunner = async () => ({ stdout: "{}", stderr: "", exitCode: 0 });

    process.env.CLOUD_DEVOPS_MCP_CLOUD_INVENTORY_ENABLED = "false";
    await expect(cloudInventorySummary(azureScope, never)).rejects.toThrow(/disabled/i);
    process.env.CLOUD_DEVOPS_MCP_CLOUD_INVENTORY_ENABLED = "true";

    await expect(cloudInventorySummary({ ...awsScope, region: "eu-west-1" }, never)).rejects.toThrow(/AWS region is not/i);
    await expect(cloudInventorySummary({ ...awsScope, profile: "prod" }, never)).rejects.toThrow(/AWS profile is not/i);
    await expect(cloudInventorySummary({ ...azureScope, subscriptionId: "22222222-2222-2222-2222-222222222222" }, never)).rejects.toThrow(/Azure subscription is not/i);
    await expect(cloudInventorySummary({ ...gcpScope, projectId: "other-project" }, never)).rejects.toThrow(/GCP project is not/i);
    await expect(cloudDriftCompare({ ...gcpScope, expectedResourceIds: [] }, never)).rejects.toThrow(/between 1 and 500/i);

    const wrongAws = sequenceRunner([{ stdout: JSON.stringify({ Account: "999999999999", Arn: "arn:aws:iam::999999999999:role/nope" }) }]);
    await expect(cloudWhoAmI(awsScope, wrongAws.runner)).rejects.toThrow(/AWS account is not/i);
  });

  it("exposes six live cloud tools only when the cloud gate is enabled", async () => {
    const server = createServer();
    const client = new Client({ name: "cloud-test", version: "1.0.0" });
    const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
    await server.connect(serverTransport);
    await client.connect(clientTransport);
    try {
      const { tools } = await client.listTools();
      expect(tools).toHaveLength(18);
      expect(tools.map((tool) => tool.name)).toEqual(expect.arrayContaining([
        "cloud_whoami",
        "cloud_inventory_summary",
        "cloud_kubernetes_clusters",
        "cloud_observability_summary",
        "cloud_finops_signals",
        "cloud_drift_compare"
      ]));
    } finally {
      await client.close();
      await server.close();
    }

    process.env.CLOUD_DEVOPS_MCP_EXECUTION_ENABLED = "true";
    process.env.CLOUD_DEVOPS_MCP_INFRASTRUCTURE_OPERATIONS_ENABLED = "true";
    const combined = createServer();
    const combinedClient = new Client({ name: "combined-test", version: "1.0.0" });
    const [ct, st] = InMemoryTransport.createLinkedPair();
    await combined.connect(st);
    await combinedClient.connect(ct);
    try {
      const { tools } = await combinedClient.listTools();
      expect(tools).toHaveLength(34);
    } finally {
      await combinedClient.close();
      await combined.close();
    }
  });
});
