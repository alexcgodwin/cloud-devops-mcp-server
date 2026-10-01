import { describe, expect, it } from "vitest";
import {
  assessCloudChangeBundle,
  assessTerraformChange,
  buildIncidentRunbook,
  estimateSloBudget,
  reviewGitHubActionsWorkflow,
  reviewIamPolicy,
  reviewKubernetesDeployment,
  reviewPipeline
} from "../src/logic.js";

describe("assessTerraformChange", () => {
  it("raises risk for public ingress, IAM and explicit missing controls", () => {
    const result = assessTerraformChange({
      changedResources: ["network", "iam"],
      includesIamChanges: true,
      includesPublicIngress: true,
      hasRollbackPlan: false,
      hasPeerReview: false,
      hasTerraformPlan: false
    });

    expect(result.riskLevel).toBe("critical");
    expect(result.checklist.join(" ")).toContain("least privilege");
  });

  it("does not treat omitted controls as false", () => {
    const result = assessTerraformChange({ changedResources: ["compute"] });

    expect(result.riskScore).toBe(8);
    expect(result.uncertainties).toHaveLength(3);
    expect(result.assessmentConfidence).toBe("low");
  });

  it("derives evidence from Terraform plan JSON", () => {
    const terraformPlanJson = JSON.stringify({
      resource_changes: [
        {
          address: "aws_security_group.web",
          type: "aws_security_group",
          change: { actions: ["update"], after: { ingress: [{ cidr_blocks: ["0.0.0.0/0"] }] } }
        },
        {
          address: "aws_iam_role.app",
          type: "aws_iam_role",
          change: { actions: ["update"], after: {} }
        },
        {
          address: "aws_db_instance.main",
          type: "aws_db_instance",
          change: { actions: ["update"], after: {} }
        }
      ]
    });

    const result = assessTerraformChange({
      terraformPlanJson,
      hasRollbackPlan: true,
      hasPeerReview: true
    });

    expect(result.changedResources).toEqual(expect.arrayContaining(["network", "iam", "database"]));
    expect(result.evidence.some((item) => item.ruleId === "TF-PUBLIC-INGRESS")).toBe(true);
    expect(result.evidence.some((item) => item.ruleId === "TF-STATEFUL")).toBe(true);
  });

  it("rejects an assessment with no change evidence", () => {
    expect(() => assessTerraformChange({})).toThrow("Provide changedResources or terraformPlanJson.");
  });
});

describe("buildIncidentRunbook", () => {
  it("creates urgent production communication guidance", () => {
    const result = buildIncidentRunbook({
      service: "payments-api",
      environment: "production",
      severity: "sev1",
      symptom: "elevated 5xx errors",
      signals: [" error rate above 12 percent ", ""]
    });

    expect(result.communication[0]).toContain("15 minutes");
    expect(result.mitigation[0]).toContain("production");
    expect(result.context.signals).toEqual(["error rate above 12 percent"]);
  });
});

describe("reviewPipeline", () => {
  it("scores a fully evidenced hardened pipeline as production ready", () => {
    const result = reviewPipeline({
      pipelineName: "platform-release",
      deploymentStrategy: "canary",
      environments: ["dev", "staging", "production"],
      hasAutomatedTests: true,
      hasSecurityScan: true,
      hasRollback: true,
      hasArtifactVersioning: true,
      hasManualApprovalForProduction: true
    });

    expect(result.readinessLevel).toBe("production-ready");
    expect(result.readinessScore).toBe(100);
    expect(result.assessmentConfidence).toBe("high");
  });

  it("uses needs-review when evidence is missing instead of failing it", () => {
    const result = reviewPipeline({
      pipelineName: "platform-release",
      deploymentStrategy: "canary",
      environments: ["staging", "production"]
    });

    expect(result.readinessScore).toBe(100);
    expect(result.readinessLevel).toBe("needs-review");
    expect(result.uncertainties.length).toBeGreaterThan(0);
  });
});

describe("estimateSloBudget", () => {
  it("calculates downtime and request budgets", () => {
    const result = estimateSloBudget({
      sloTargetPercent: 99.9,
      periodDays: 30,
      observedDowntimeMinutes: 12,
      requestVolume: 1_000_000,
      failedRequests: 250
    });

    expect(result.allowedDowntimeMinutes).toBe(43.2);
    expect(result.budgetStatus).toBe("within-budget");
    expect(result.failedRequests).toBe(250);
  });

  it("rejects partial request-budget inputs", () => {
    expect(() =>
      estimateSloBudget({
        sloTargetPercent: 99.9,
        periodDays: 30,
        observedDowntimeMinutes: 0,
        requestVolume: 100
      })
    ).toThrow("provided together");
  });

  it("rejects failed requests above request volume", () => {
    expect(() =>
      estimateSloBudget({
        sloTargetPercent: 99.9,
        periodDays: 30,
        observedDowntimeMinutes: 0,
        requestVolume: 100,
        failedRequests: 101
      })
    ).toThrow("cannot exceed");
  });
});

describe("reviewIamPolicy", () => {
  it("flags wildcard and privilege escalation from raw policy JSON", () => {
    const policyJson = JSON.stringify({
      Version: "2012-10-17",
      Statement: [
        {
          Effect: "Allow",
          Action: ["iam:*", "iam:PassRole", "s3:GetObject"],
          Resource: ["arn:aws:s3:::example-bucket/*", "*"]
        }
      ]
    });

    const result = reviewIamPolicy({
      policyName: "platform-admin",
      policyJson,
      usedByProduction: true
    });

    expect(result.riskLevel).toBe("critical");
    expect(result.findings.join(" ")).toContain("privilege-escalation");
    expect(result.evidence.some((item) => item.ruleId === "IAM-PRIV-ESC")).toBe(true);
    expect(result.evidence.some((item) => item.ruleId === "IAM-WILDCARD-RESOURCE")).toBe(true);
  });

  it("automatically detects escalation from action strings without a boolean hint", () => {
    const result = reviewIamPolicy({
      policyName: "role-pass",
      actions: ["iam:PassRole"],
      resources: ["arn:aws:iam::123456789012:role/app"],
      hasWildcardActions: false,
      hasWildcardResources: false,
      hasConditionBlocks: true,
      usedByProduction: false
    });

    expect(result.riskScore).toBe(26);
    expect(result.findings.join(" ")).toContain("privilege-escalation");
  });
});

describe("reviewKubernetesDeployment", () => {
  const manifest = `
apiVersion: apps/v1
kind: Deployment
metadata:
  name: payments-api
  namespace: production
spec:
  replicas: 1
  template:
    spec:
      containers:
        - name: api
          image: example/payments:latest
          securityContext:
            runAsUser: 0
          resources:
            requests:
              cpu: 100m
              memory: 128Mi
---
apiVersion: v1
kind: Service
metadata:
  name: payments-api
spec:
  type: LoadBalancer
`;

  it("parses workload evidence directly from Kubernetes YAML", () => {
    const result = reviewKubernetesDeployment({ manifestYaml: manifest });

    expect(result.workloadName).toBe("payments-api");
    expect(result.namespace).toBe("production");
    expect(result.readinessLevel).toBe("not-ready");
    expect(result.findings.join(" ")).toContain("latest");
    expect(result.findings.join(" ")).toContain("non-root");
    expect(result.evidence.some((item) => item.ruleId === "K8S-PUBLIC")).toBe(true);
  });

  it("marks a fully evidenced workload as production ready", () => {
    const result = reviewKubernetesDeployment({
      workloadName: "payments-api",
      namespace: "production",
      replicas: 3,
      hasReadinessProbe: true,
      hasLivenessProbe: true,
      hasResourceRequests: true,
      hasResourceLimits: true,
      hasPodDisruptionBudget: true,
      usesLatestTag: false,
      runsAsRoot: false,
      exposesPublicService: false
    });

    expect(result.readinessLevel).toBe("production-ready");
    expect(result.assessmentConfidence).toBe("high");
  });
});

describe("reviewGitHubActionsWorkflow", () => {
  it("parses risky workflow YAML and detects mutable action refs", () => {
    const workflowYaml = `
name: Deploy
on:
  pull_request_target:
  push:
permissions:
  contents: read
jobs:
  deploy:
    environment: production
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          cache: npm
`;

    const result = reviewGitHubActionsWorkflow({
      workflowName: "production-deploy",
      workflowYaml,
      hasEnvironmentProtection: false
    });

    expect(result.triggers).toEqual(expect.arrayContaining(["pull_request_target", "push"]));
    expect(result.findings.join(" ")).toContain("full commit SHAs");
    expect(result.findings.join(" ")).toContain("protected environments");
    expect(result.evidence.some((item) => item.ruleId === "GHA-PR-TARGET")).toBe(true);
  });

  it("accepts immutable full-SHA action pins", () => {
    const workflowYaml = `
name: CI
on: [push]
permissions:
  contents: read
concurrency:
  group: ci
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683
`;

    const result = reviewGitHubActionsWorkflow({
      workflowName: "ci",
      workflowYaml,
      hasSecretScanning: true
    });

    expect(result.findings.join(" ")).not.toContain("full commit SHAs");
    expect(result.strengths.join(" ")).toContain("immutable commit SHAs");
  });
});


describe("assessCloudChangeBundle", () => {
  it("correlates public exposure, IAM privilege and unprotected production delivery", () => {
    const terraformPlanJson = JSON.stringify({
      resource_changes: [
        {
          address: "aws_security_group.web",
          type: "aws_security_group",
          change: {
            actions: ["update"],
            after: { ingress: [{ cidr_blocks: ["0.0.0.0/0"] }] }
          }
        },
        {
          address: "aws_iam_role.app",
          type: "aws_iam_role",
          change: { actions: ["update"], after: {} }
        }
      ]
    });

    const iamPolicyJson = JSON.stringify({
      Version: "2012-10-17",
      Statement: [
        {
          Effect: "Allow",
          Action: ["iam:PassRole"],
          Resource: "*"
        }
      ]
    });

    const kubernetesManifest = `
apiVersion: apps/v1
kind: Deployment
metadata:
  name: payments-api
  namespace: production
spec:
  replicas: 1
  template:
    spec:
      containers:
        - name: api
          image: example/payments:latest
          securityContext:
            runAsUser: 0
---
apiVersion: v1
kind: Service
metadata:
  name: payments-api
spec:
  type: LoadBalancer
`;

    const workflowYaml = `
name: Deploy
on:
  push:
jobs:
  deploy:
    environment: production
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
`;

    const result = assessCloudChangeBundle({
      changeName: "payments-production-release",
      environment: "production",
      terraform: {
        terraformPlanJson,
        hasRollbackPlan: true,
        hasPeerReview: true
      },
      iamPolicies: [
        {
          policyName: "payments-deployer",
          policyJson: iamPolicyJson,
          usedByProduction: true
        }
      ],
      kubernetesWorkloads: [
        {
          manifestYaml: kubernetesManifest
        }
      ],
      githubWorkflows: [
        {
          workflowName: "deploy",
          workflowYaml,
          hasEnvironmentProtection: false
        }
      ]
    });

    expect(result.bundleRiskLevel).toBe("critical");
    expect(result.releaseGate).toBe("hold-for-remediation");
    expect(result.suppliedDomains).toHaveLength(4);
    expect(result.correlatedFindings.map((finding) => finding.ruleId)).toEqual(
      expect.arrayContaining([
        "BUNDLE-PUBLIC-EXPOSURE",
        "BUNDLE-PRIVILEGED-PROD-DELIVERY",
        "BUNDLE-MUTABLE-SUPPLY-CHAIN",
        "BUNDLE-PUBLIC-PRIVILEGE-BLAST-RADIUS",
        "BUNDLE-PUBLIC-ROOT-WORKLOAD",
        "BUNDLE-IAC-IAM-HIGH-RISK"
      ])
    );
    expect(result.changePaths.length).toBe(result.correlatedFindingCount);
  });

  it("keeps a well-controlled multi-domain change low risk", () => {
    const result = assessCloudChangeBundle({
      changeName: "internal-worker",
      environment: "dev",
      terraform: {
        changedResources: ["compute"],
        hasRollbackPlan: true,
        hasPeerReview: true,
        hasTerraformPlan: true
      },
      kubernetesWorkloads: [
        {
          workloadName: "worker",
          namespace: "dev",
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
    });

    expect(result.bundleRiskLevel).toBe("low");
    expect(result.releaseGate).toBe("standard-review");
    expect(result.correlatedFindingCount).toBe(0);
    expect(result.assessmentConfidence).toBe("high");
  });

  it("requires at least two evidence domains", () => {
    expect(() =>
      assessCloudChangeBundle({
        changeName: "single-domain",
        environment: "staging",
        terraform: {
          changedResources: ["compute"]
        }
      })
    ).toThrow("at least two domains");
  });
});
