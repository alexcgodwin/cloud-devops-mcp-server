import { describe, expect, it } from "vitest";
import {
  reviewCloudIdentityPolicy,
  reviewKubernetesSecurity,
  reviewSoftwareSupplyChain,
  reviewTerraformSecurity
} from "../src/intelligence.js";

describe("reviewCloudIdentityPolicy", () => {
  it("detects AWS administrative wildcard and PassRole risk", () => {
    const result = reviewCloudIdentityPolicy({
      provider: "aws",
      policyName: "deployer",
      environment: "production",
      policyJson: JSON.stringify({
        Version: "2012-10-17",
        Statement: [{
          Effect: "Allow",
          Action: ["*", "iam:PassRole"],
          Resource: "*"
        }]
      })
    });

    expect(result.riskLevel).toBe("critical");
    expect(result.findings.map((finding) => finding.ruleId)).toEqual(
      expect.arrayContaining(["AWS-IAM-ADMIN-WILDCARD", "AWS-IAM-PASSROLE-WILDCARD"])
    );
  });

  it("detects Azure RBAC wildcard and root-scope risk", () => {
    const result = reviewCloudIdentityPolicy({
      provider: "azure",
      policyName: "platform-owner",
      policyJson: JSON.stringify({
        properties: {
          roleName: "Owner",
          assignableScopes: ["/"],
          permissions: [{
            actions: ["*"],
            dataActions: []
          }]
        }
      })
    });

    expect(result.riskLevel).toBe("critical");
    expect(result.findings.map((finding) => finding.ruleId)).toEqual(
      expect.arrayContaining(["AZURE-RBAC-WILDCARD", "AZURE-RBAC-OWNER", "AZURE-RBAC-TENANT-SCOPE"])
    );
  });

  it("detects GCP public and token-creator bindings", () => {
    const result = reviewCloudIdentityPolicy({
      provider: "gcp",
      policyName: "project-policy",
      policyJson: JSON.stringify({
        bindings: [{
          role: "roles/iam.serviceAccountTokenCreator",
          members: ["allUsers"]
        }]
      })
    });

    expect(result.riskLevel).toBe("critical");
    expect(result.findings.map((finding) => finding.ruleId)).toEqual(
      expect.arrayContaining(["GCP-IAM-SA-TOKEN-CREATOR", "GCP-IAM-PUBLIC-MEMBER"])
    );
  });
});

describe("reviewTerraformSecurity", () => {
  it("detects destructive stateful changes and public sensitive ports", () => {
    const result = reviewTerraformSecurity({
      environment: "production",
      terraformPlanJson: JSON.stringify({
        resource_changes: [
          {
            address: "aws_db_instance.main",
            type: "aws_db_instance",
            change: {
              actions: ["delete", "create"],
              before: { id: "db" },
              after: {
                publicly_accessible: true,
                storage_encrypted: false,
                deletion_protection: false
              }
            }
          },
          {
            address: "aws_security_group.admin",
            type: "aws_security_group",
            change: {
              actions: ["update"],
              before: {},
              after: {
                ingress: [{
                  from_port: 22,
                  to_port: 22,
                  cidr_blocks: ["0.0.0.0/0"]
                }]
              }
            }
          }
        ]
      })
    });

    expect(result.destructiveChanges).toBe(1);
    expect(result.replacements).toBe(1);
    expect(result.riskLevel).toBe("critical");
    expect(result.findings.map((finding) => finding.ruleId)).toEqual(
      expect.arrayContaining([
        "TF-SEC-STATEFUL-DESTRUCTIVE",
        "TF-SEC-PUBLIC-DATA-SERVICE",
        "TF-SEC-ENCRYPTION-DISABLED",
        "TF-SEC-DELETION-PROTECTION",
        "TF-SEC-PUBLIC-SENSITIVE-PORT"
      ])
    );
  });

  it("rejects plans with no actionable changes", () => {
    expect(() => reviewTerraformSecurity({
      terraformPlanJson: JSON.stringify({
        resource_changes: [{
          address: "aws_instance.read",
          type: "aws_instance",
          change: { actions: ["read"], before: {}, after: {} }
        }]
      })
    })).toThrow("no actionable");
  });
});

describe("reviewKubernetesSecurity", () => {
  it("detects privileged workload, host access and missing network policy", () => {
    const result = reviewKubernetesSecurity({
      environment: "production",
      manifestYaml: `
apiVersion: apps/v1
kind: Deployment
metadata:
  name: dangerous-api
spec:
  template:
    spec:
      hostNetwork: true
      volumes:
        - name: host
          hostPath:
            path: /
      containers:
        - name: api
          image: example/api:latest
          securityContext:
            privileged: true
            allowPrivilegeEscalation: true
            runAsUser: 0
            capabilities:
              add: ["SYS_ADMIN"]
          ports:
            - containerPort: 8080
              hostPort: 8080
---
apiVersion: v1
kind: Service
metadata:
  name: dangerous-api
spec:
  type: LoadBalancer
`
    });

    expect(result.riskLevel).toBe("critical");
    expect(result.networkPolicyPresent).toBe(false);
    expect(result.findings.map((finding) => finding.ruleId)).toEqual(
      expect.arrayContaining([
        "K8S-SEC-HOST-NAMESPACE",
        "K8S-SEC-HOSTPATH",
        "K8S-SEC-PRIVILEGED",
        "K8S-SEC-PRIV-ESC",
        "K8S-SEC-ROOT",
        "K8S-SEC-DANGEROUS-CAP",
        "K8S-SEC-HOSTPORT",
        "K8S-SEC-READONLY-FS",
        "K8S-SEC-SECCOMP",
        "K8S-SEC-PUBLIC-NO-NETPOL"
      ])
    );
  });

  it("keeps a hardened workload at low risk", () => {
    const result = reviewKubernetesSecurity({
      environment: "production",
      manifestYaml: `
apiVersion: apps/v1
kind: Deployment
metadata:
  name: hardened-api
spec:
  template:
    spec:
      serviceAccountName: hardened-api
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
    });

    expect(result.riskLevel).toBe("low");
    expect(result.findingCount).toBe(0);
  });
});

describe("reviewSoftwareSupplyChain", () => {
  it("correlates mutable CI and runtime artifacts with missing trust evidence", () => {
    const result = reviewSoftwareSupplyChain({
      environment: "production",
      artifactSigned: false,
      hasProvenance: false,
      sbomJson: JSON.stringify({
        bomFormat: "CycloneDX",
        specVersion: "1.6",
        components: [{
          type: "library",
          name: "example-lib",
          version: "1.0.0",
          purl: "pkg:npm/example-lib@1.0.0",
          hashes: [{ alg: "SHA-256", content: "abc" }],
          licenses: [{ license: { id: "MIT" } }]
        }]
      }),
      workflowYaml: `
name: CI
on: [push]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
`,
      kubernetesManifestYaml: `
apiVersion: apps/v1
kind: Deployment
metadata:
  name: api
spec:
  template:
    spec:
      containers:
        - name: api
          image: example/api:latest
`
    });

    expect(result.riskLevel).toBe("critical");
    expect(result.correlationPaths.map((path) => path.pathId)).toEqual(
      expect.arrayContaining(["SC-CORR-MUTABLE-BUILD-RUNTIME", "SC-CORR-UNVERIFIED-ARTIFACT"])
    );
  });

  it("parses SPDX component metadata", () => {
    const result = reviewSoftwareSupplyChain({
      sbomJson: JSON.stringify({
        spdxVersion: "SPDX-2.3",
        packages: [{
          name: "example",
          versionInfo: "1.0.0",
          checksums: [{ algorithm: "SHA256", checksumValue: "abc" }],
          externalRefs: [{
            referenceType: "purl",
            referenceLocator: "pkg:npm/example@1.0.0"
          }],
          licenseDeclared: "MIT"
        }]
      }),
      artifactSigned: true,
      hasProvenance: true
    });

    expect(result.sbomFormat).toBe("SPDX");
    expect(result.componentCount).toBe(1);
    expect(result.riskLevel).toBe("low");
  });
});
