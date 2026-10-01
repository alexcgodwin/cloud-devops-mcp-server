import { Client, InMemoryTransport } from "@modelcontextprotocol/client";
import { describe, expect, it } from "vitest";
import { createServer } from "../src/index.js";

describe("MCP server contract", () => {
  it("lists all tools with schemas and executes every registered handler", async () => {
    const server = createServer();
    const client = new Client({ name: "cloud-devops-test", version: "1.0.0" });
    const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();

    await server.connect(serverTransport);
    await client.connect(clientTransport);

    try {
      const { tools } = await client.listTools();
      expect(tools).toHaveLength(12);

      for (const tool of tools) {
        expect(tool.outputSchema).toBeDefined();
        expect(tool.annotations?.readOnlyHint).toBe(true);
        expect(tool.annotations?.destructiveHint).toBe(false);
        expect(tool.annotations?.idempotentHint).toBe(true);
      }

      const calls = [
        {
          name: "assess_cloud_change_bundle",
          arguments: {
            changeName: "contract-test",
            environment: "staging",
            terraform: {
              changedResources: ["compute"],
              hasRollbackPlan: true,
              hasPeerReview: true,
              hasTerraformPlan: true
            },
            kubernetesWorkloads: [
              {
                workloadName: "api",
                namespace: "staging",
                replicas: 2,
                hasReadinessProbe: true,
                hasLivenessProbe: true,
                hasResourceRequests: true,
                hasResourceLimits: true,
                hasPodDisruptionBudget: true,
                usesLatestTag: false,
                runsAsRoot: false,
                exposesPublicService: false
              }
            ]
          }
        },
        {
          name: "assess_terraform_change",
          arguments: {
            changedResources: ["compute"],
            hasRollbackPlan: true,
            hasPeerReview: true,
            hasTerraformPlan: true
          }
        },
        {
          name: "build_incident_runbook",
          arguments: {
            service: "api",
            environment: "staging",
            severity: "sev3",
            symptom: "latency above baseline"
          }
        },
        {
          name: "review_cicd_pipeline",
          arguments: {
            pipelineName: "release",
            deploymentStrategy: "rolling",
            environments: ["staging", "production"],
            hasAutomatedTests: true,
            hasSecurityScan: true,
            hasRollback: true,
            hasArtifactVersioning: true,
            hasManualApprovalForProduction: true
          }
        },
        {
          name: "estimate_slo_error_budget",
          arguments: {
            sloTargetPercent: 99.9,
            periodDays: 30,
            observedDowntimeMinutes: 10
          }
        },
        {
          name: "review_iam_policy",
          arguments: {
            policyName: "reader",
            actions: ["s3:GetObject"],
            resources: ["arn:aws:s3:::example-bucket/object"],
            hasConditionBlocks: true,
            usedByProduction: false
          }
        },
        {
          name: "review_kubernetes_deployment",
          arguments: {
            workloadName: "api",
            namespace: "staging",
            replicas: 2,
            hasReadinessProbe: true,
            hasLivenessProbe: true,
            hasResourceRequests: true,
            hasResourceLimits: true,
            hasPodDisruptionBudget: true,
            usesLatestTag: false,
            runsAsRoot: false,
            exposesPublicService: false
          }
        },
        {
          name: "review_github_actions_workflow",
          arguments: {
            workflowName: "ci",
            triggers: ["push"],
            deploysToProduction: false,
            usesPinnedActions: true,
            hasLeastPrivilegePermissions: true,
            hasSecretScanning: true,
            hasDependencyCaching: true,
            hasEnvironmentProtection: true,
            hasConcurrencyControl: true
          }
        },
        {
          name: "review_cloud_identity_policy",
          arguments: {
            provider: "aws",
            policyName: "reader",
            policyJson: JSON.stringify({
              Version: "2012-10-17",
              Statement: [{
                Effect: "Allow",
                Action: ["s3:GetObject"],
                Resource: ["arn:aws:s3:::example-bucket/*"],
                Condition: { StringEquals: { "aws:PrincipalOrgID": "o-example" } }
              }]
            }),
            environment: "staging"
          }
        },
        {
          name: "review_terraform_security",
          arguments: {
            environment: "staging",
            terraformPlanJson: JSON.stringify({
              resource_changes: [{
                address: "aws_instance.api",
                type: "aws_instance",
                change: {
                  actions: ["update"],
                  before: { instance_type: "t3.small" },
                  after: { instance_type: "t3.medium" }
                }
              }]
            })
          }
        },
        {
          name: "review_kubernetes_security",
          arguments: {
            environment: "staging",
            manifestYaml: `apiVersion: apps/v1
kind: Deployment
metadata:
  name: api
spec:
  template:
    spec:
      serviceAccountName: api
      automountServiceAccountToken: false
      securityContext:
        runAsNonRoot: true
        seccompProfile:
          type: RuntimeDefault
      containers:
        - name: api
          image: example/api@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
          securityContext:
            runAsNonRoot: true
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            capabilities:
              drop: ["ALL"]
`
          }
        },
        {
          name: "review_software_supply_chain",
          arguments: {
            environment: "staging",
            artifactSigned: true,
            hasProvenance: true,
            sbomJson: JSON.stringify({
              bomFormat: "CycloneDX",
              specVersion: "1.6",
              components: [{
                type: "library",
                name: "example",
                version: "1.0.0",
                purl: "pkg:npm/example@1.0.0",
                hashes: [{ alg: "SHA-256", content: "abc" }],
                licenses: [{ license: { id: "MIT" } }]
              }]
            })
          }
        }
      ];

      for (const call of calls) {
        const result = await client.callTool(call);
        expect(result.isError).not.toBe(true);
        expect(result.structuredContent).toBeDefined();
      }

      const slo = await client.callTool({
        name: "estimate_slo_error_budget",
        arguments: {
          sloTargetPercent: 99.9,
          periodDays: 30,
          observedDowntimeMinutes: 10
        }
      });

      expect(slo.structuredContent).toMatchObject({
        allowedDowntimeMinutes: 43.2,
        budgetStatus: "within-budget"
      });
    } finally {
      await client.close();
      await server.close();
    }
  });
});
