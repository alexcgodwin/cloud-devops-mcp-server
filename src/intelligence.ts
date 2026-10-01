import { parseAllDocuments, parse as parseYaml } from "yaml";

export type SecuritySeverity = "low" | "medium" | "high" | "critical";
export type CloudProvider = "aws" | "azure" | "gcp";

export interface SecurityFinding {
  ruleId: string;
  severity: Exclude<SecuritySeverity, "low">;
  title: string;
  evidence: string[];
  remediation: string[];
}

export interface CloudIdentityPolicyInput {
  provider: CloudProvider;
  policyName: string;
  policyJson: string;
  environment?: "dev" | "staging" | "production";
}

export interface TerraformSecurityInput {
  terraformPlanJson: string;
  environment?: "dev" | "staging" | "production";
}

export interface KubernetesSecurityInput {
  manifestYaml: string;
  environment?: "dev" | "staging" | "production";
}

export interface SupplyChainInput {
  sbomJson: string;
  workflowYaml?: string;
  kubernetesManifestYaml?: string;
  artifactSigned?: boolean;
  hasProvenance?: boolean;
  environment?: "dev" | "staging" | "production";
}

function parseJsonObject(input: string, label: string): Record<string, any> {
  let parsed: unknown;
  try {
    parsed = JSON.parse(input);
  } catch {
    throw new Error(`${label} must be valid JSON.`);
  }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new Error(`${label} must be a JSON object.`);
  }
  return parsed as Record<string, any>;
}

function strings(value: unknown): string[] {
  if (typeof value === "string") return [value];
  if (Array.isArray(value)) return value.filter((item): item is string => typeof item === "string");
  return [];
}

function severityScore(severity: SecurityFinding["severity"]): number {
  if (severity === "critical") return 35;
  if (severity === "high") return 22;
  return 10;
}

function level(score: number): SecuritySeverity {
  if (score >= 75) return "critical";
  if (score >= 50) return "high";
  if (score >= 25) return "medium";
  return "low";
}

function summarize(findings: SecurityFinding[], uncertaintyCount = 0) {
  const riskScore = Math.min(
    100,
    findings.reduce((total, finding) => total + severityScore(finding.severity), 0)
  );
  return {
    riskScore,
    riskLevel: level(riskScore),
    findingCount: findings.length,
    criticalFindings: findings.filter((finding) => finding.severity === "critical").length,
    highFindings: findings.filter((finding) => finding.severity === "high").length,
    mediumFindings: findings.filter((finding) => finding.severity === "medium").length,
    assessmentConfidence: uncertaintyCount === 0 ? "high" : uncertaintyCount <= 2 ? "medium" : "low"
  } as const;
}

function addFinding(
  findings: SecurityFinding[],
  ruleId: string,
  severity: SecurityFinding["severity"],
  title: string,
  evidence: string[],
  remediation: string[]
) {
  if (findings.some((finding) => finding.ruleId === ruleId && finding.title === title)) return;
  findings.push({ ruleId, severity, title, evidence, remediation });
}

export function reviewCloudIdentityPolicy(input: CloudIdentityPolicyInput) {
  const policy = parseJsonObject(input.policyJson, "policyJson");
  const findings: SecurityFinding[] = [];
  const environment = input.environment ?? "production";
  const facts: string[] = [];

  if (input.provider === "aws") {
    const statements = Array.isArray(policy.Statement) ? policy.Statement : policy.Statement ? [policy.Statement] : [];
    if (statements.length === 0) throw new Error("AWS policy must contain Statement.");

    for (const [index, raw] of statements.entries()) {
      if (!raw || typeof raw !== "object") continue;
      const statement = raw as Record<string, any>;
      if ((statement.Effect ?? "Allow") !== "Allow") continue;
      const actions = strings(statement.Action);
      const resources = strings(statement.Resource);
      const actionLower = actions.map((action) => action.toLowerCase());
      const wildcardAction = actions.some((action) => action === "*" || action.includes("*"));
      const wildcardResource = resources.some((resource) => resource === "*" || resource.includes("*"));
      const conditionPresent = Boolean(statement.Condition);

      facts.push(`Statement ${index + 1}: ${actions.length} actions, ${resources.length} resources.`);

      if (wildcardAction && wildcardResource) {
        addFinding(findings, "AWS-IAM-ADMIN-WILDCARD", "critical", "Policy grants wildcard actions on wildcard resources",
          [`Statement ${index + 1} contains Action and Resource wildcards.`],
          ["Replace administrative wildcards with explicit actions and resource ARNs.", "Use separate break-glass administration roles for exceptional access."]);
      }

      if (actionLower.includes("iam:passrole") && wildcardResource) {
        addFinding(findings, "AWS-IAM-PASSROLE-WILDCARD", "critical", "iam:PassRole is granted against wildcard resources",
          [`Statement ${index + 1} permits iam:PassRole with broad resource scope.`],
          ["Scope iam:PassRole to named roles and constrain iam:PassedToService where possible."]);
      }

      if (actionLower.includes("sts:assumerole") && wildcardResource) {
        addFinding(findings, "AWS-STS-ASSUMEROLE-WILDCARD", "high", "sts:AssumeRole has wildcard resource scope",
          [`Statement ${index + 1} permits sts:AssumeRole against broad resources.`],
          ["Limit role assumption to approved role ARNs and use conditions for account, principal and external ID boundaries."]);
      }

      if (actionLower.some((action) =>
        action.startsWith("iam:attach") ||
        action.startsWith("iam:put") ||
        action === "iam:createaccesskey" ||
        action === "iam:updateassumerolepolicy"
      )) {
        addFinding(findings, "AWS-IAM-PRIVILEGE-MUTATION", "high", "Policy can modify identity permissions or credentials",
          [`Statement ${index + 1} includes IAM permission-mutation actions.`],
          ["Separate identity administration from workload execution identities.", "Require peer review and short-lived credentials for IAM administration."]);
      }

      if ((wildcardAction || wildcardResource) && !conditionPresent) {
        addFinding(findings, "AWS-IAM-BROAD-NO-CONDITION", "medium", "Broad AWS IAM grant has no condition boundary",
          [`Statement ${index + 1} is broad and has no Condition block.`],
          ["Add conditions for resource tags, source identity, organization/account, region or network context where supported."]);
      }
    }
  }

  if (input.provider === "azure") {
    const properties = policy.properties ?? policy;
    const roleName = String(properties.roleName ?? properties.name ?? input.policyName);
    const permissions = Array.isArray(properties.permissions) ? properties.permissions : [];
    const assignableScopes = strings(properties.assignableScopes ?? policy.assignableScopes);
    const allActions = permissions.flatMap((permission: any) => strings(permission?.actions ?? permission?.Actions));
    const dataActions = permissions.flatMap((permission: any) => strings(permission?.dataActions ?? permission?.DataActions));
    const normalized = [...allActions, ...dataActions].map((action) => action.toLowerCase());

    facts.push(`Role ${roleName}: ${allActions.length} control-plane actions, ${dataActions.length} data actions.`);

    if (allActions.includes("*") || dataActions.includes("*")) {
      addFinding(findings, "AZURE-RBAC-WILDCARD", "critical", "Azure role grants wildcard control-plane or data-plane permissions",
        ["Role permissions include wildcard actions."],
        ["Replace wildcard permissions with the smallest required Microsoft.* action set.", "Separate data-plane and control-plane administration."]);
    }

    if (/^owner$/i.test(roleName)) {
      addFinding(findings, "AZURE-RBAC-OWNER", "critical", "Azure Owner-level role detected", [`Role name is ${roleName}.`],
        ["Use narrower built-in roles or a custom role instead of Owner for routine workloads."]);
    } else if (/contributor/i.test(roleName)) {
      addFinding(findings, "AZURE-RBAC-CONTRIBUTOR", "high", "Azure Contributor-level role detected", [`Role name is ${roleName}.`],
        ["Scope Contributor access to the smallest resource group or resource and prefer workload-specific custom roles."]);
    }

    if (/user access administrator/i.test(roleName) ||
      normalized.some((action) => action.includes("microsoft.authorization/roleassignments/write") || action.includes("microsoft.authorization/roledefinitions/write"))) {
      addFinding(findings, "AZURE-RBAC-ROLE-MUTATION", "critical", "Role can create or modify Azure RBAC assignments",
        ["Role includes authorization role-assignment or role-definition mutation capability."],
        ["Keep RBAC administration in a dedicated identity-management role with approval and PIM/JIT controls."]);
    }

    if (assignableScopes.includes("/")) {
      addFinding(findings, "AZURE-RBAC-TENANT-SCOPE", "high", "Role is assignable at tenant/root scope", ["Assignable scopes include '/'."],
        ["Constrain assignableScopes to the smallest management group, subscription, resource group or resource required."]);
    }
  }

  if (input.provider === "gcp") {
    const bindings = Array.isArray(policy.bindings) ? policy.bindings : [];
    const includedPermissions = strings(policy.includedPermissions ?? policy.permissions);
    if (bindings.length === 0 && includedPermissions.length === 0) {
      throw new Error("GCP policy must contain bindings or includedPermissions.");
    }

    for (const binding of bindings) {
      if (!binding || typeof binding !== "object") continue;
      const role = String(binding.role ?? "");
      const members = strings(binding.members);
      const conditionPresent = Boolean(binding.condition);
      facts.push(`${role}: ${members.length} members.`);

      if (role === "roles/owner") {
        addFinding(findings, "GCP-IAM-OWNER", "critical", "GCP Owner role binding detected", [role], ["Replace Owner with task-specific predefined or custom roles."]);
      } else if (role === "roles/editor") {
        addFinding(findings, "GCP-IAM-EDITOR", "high", "GCP Editor role binding detected", [role], ["Replace Editor with least-privilege predefined roles."]);
      }

      if (role === "roles/iam.serviceAccountTokenCreator") {
        addFinding(findings, "GCP-IAM-SA-TOKEN-CREATOR", "critical", "Service Account Token Creator binding detected", [role],
          ["Restrict token-creation capability to tightly controlled automation identities and specific service accounts."]);
      }

      if (role === "roles/iam.serviceAccountUser") {
        addFinding(findings, "GCP-IAM-SA-USER", "high", "Service Account User binding can enable workload impersonation", [role],
          ["Limit serviceAccountUser to specific service accounts and approved deployment principals."]);
      }

      if (members.some((member) => member === "allUsers" || member === "allAuthenticatedUsers")) {
        addFinding(findings, "GCP-IAM-PUBLIC-MEMBER", "critical", "IAM binding grants access to a public member",
          [`${role} includes allUsers or allAuthenticatedUsers.`],
          ["Remove public IAM members unless public access is explicitly required and compensated by service-level controls."]);
      }

      if (!conditionPresent && ["roles/owner", "roles/editor", "roles/iam.serviceAccountTokenCreator"].includes(role)) {
        addFinding(findings, "GCP-IAM-PRIVILEGED-NO-CONDITION", "medium", "Privileged GCP IAM binding has no condition",
          [`${role} binding has no condition.`], ["Use IAM Conditions for resource, time or request-context restrictions where applicable."]);
      }
    }

    const permissionLower = includedPermissions.map((permission) => permission.toLowerCase());
    if (permissionLower.some((permission) =>
      permission.endsWith(".setiampolicy") ||
      permission.includes("serviceaccountkeys.create") ||
      permission.includes("serviceaccounts.getaccesstoken")
    )) {
      addFinding(findings, "GCP-IAM-CUSTOM-PRIVILEGE", "high", "Custom GCP role includes identity-escalation capability",
        [includedPermissions.join(", ")],
        ["Remove IAM-policy mutation, service-account key creation and token minting unless strictly required."]);
    }
  }

  if (environment === "production" && findings.some((finding) => finding.severity === "critical")) {
    facts.push("Production context increases the operational importance of the critical identity findings.");
  }

  const summary = summarize(findings);
  return {
    provider: input.provider,
    policyPack: `${input.provider}-identity-v1`,
    policyName: input.policyName,
    environment,
    ...summary,
    facts,
    findings,
    recommendedGate: summary.riskScore >= 75 ? "block" : summary.riskScore >= 50 ? "security-review" : "standard-review"
  };
}

const statefulTerraformPatterns = /(rds|db_instance|db_cluster|database|sql_|dynamodb|cosmos|storage|disk|volume|efs|bucket|redis|elasticache|kafka|queue|sqs)/i;

export function reviewTerraformSecurity(input: TerraformSecurityInput) {
  const plan = parseJsonObject(input.terraformPlanJson, "terraformPlanJson");
  const changes = Array.isArray(plan.resource_changes) ? plan.resource_changes : [];
  const findings: SecurityFinding[] = [];
  const environment = input.environment ?? "production";
  let changed = 0;
  let destructive = 0;
  let replacements = 0;

  for (const raw of changes) {
    if (!raw || typeof raw !== "object") continue;
    const item = raw as Record<string, any>;
    const change = item.change ?? {};
    const actions = strings(change.actions);
    if (actions.length === 0 || actions.every((action) => action === "read" || action === "no-op")) continue;
    changed += 1;

    const address = String(item.address ?? item.type ?? "unknown");
    const type = String(item.type ?? "");
    const after = change.after ?? {};
    const before = change.before ?? {};
    const afterText = JSON.stringify(after).toLowerCase();
    const beforeText = JSON.stringify(before).toLowerCase();

    const deletes = actions.includes("delete");
    const creates = actions.includes("create");
    const replaces = deletes && creates;
    if (deletes) destructive += 1;
    if (replaces) replacements += 1;

    if (deletes && statefulTerraformPatterns.test(type)) {
      addFinding(findings, "TF-SEC-STATEFUL-DESTRUCTIVE", environment === "production" ? "critical" : "high",
        "Stateful resource has a destructive Terraform action", [`${address} actions: ${actions.join(", ")}.`],
        ["Verify backup/restore evidence and rollback or forward-fix procedures before apply.", "Use lifecycle protections where appropriate."]);
    }

    if (replaces && /(network|vpc|subnet|load_balancer|security_group|dns|route53)/i.test(type)) {
      addFinding(findings, "TF-SEC-NETWORK-REPLACE", "high", "Network control is being replaced", [`${address} will be replaced.`],
        ["Model cutover ordering and validate DNS, routes, security groups and health checks before replacement."]);
    }

    const publicCidr = afterText.includes("0.0.0.0/0") || afterText.includes("::/0");
    const sensitivePorts = [22, 3389, 3306, 5432, 6379, 9200, 27017];
    const portEvidence = sensitivePorts.filter((port) =>
      afterText.includes(`"from_port":${port}`) ||
      afterText.includes(`"to_port":${port}`) ||
      afterText.includes(`"port":${port}`)
    );
    if (publicCidr && portEvidence.length > 0) {
      addFinding(findings, "TF-SEC-PUBLIC-SENSITIVE-PORT", "critical",
        "Public ingress exposes a sensitive administration or data-service port",
        [`${address} exposes ${portEvidence.join(", ")} to a public CIDR.`],
        ["Restrict ingress to trusted networks, private connectivity or authenticated proxy/bastion paths."]);
    } else if (publicCidr) {
      addFinding(findings, "TF-SEC-PUBLIC-CIDR", "high", "Terraform change contains unrestricted public CIDR exposure",
        [`${address} includes 0.0.0.0/0 or ::/0.`],
        ["Confirm the endpoint is intentionally public and constrain listeners, protocols and source networks."]);
    }

    if (/publicly_accessible"\s*:\s*true|public_network_access_enabled"\s*:\s*true|publicnetworkaccess"\s*:\s*"enabled"/.test(afterText)) {
      addFinding(findings, "TF-SEC-PUBLIC-DATA-SERVICE", statefulTerraformPatterns.test(type) ? "critical" : "high",
        "Resource enables public network access", [`${address} enables public network access.`],
        ["Prefer private endpoints/private service access and disable public network access for production data services."]);
    }

    if (/("encrypted"|"storage_encrypted"|"encryption_enabled")\s*:\s*false/.test(afterText)) {
      addFinding(findings, "TF-SEC-ENCRYPTION-DISABLED", "high", "Terraform resource explicitly disables encryption",
        [`${address} contains an encryption=false setting.`],
        ["Enable provider-supported encryption at rest and use managed or customer-managed keys according to policy."]);
    }

    if (environment === "production" && statefulTerraformPatterns.test(type) && /"deletion_protection"\s*:\s*false/.test(afterText)) {
      addFinding(findings, "TF-SEC-DELETION-PROTECTION", "high",
        "Production stateful resource has deletion protection disabled", [`${address} has deletion_protection=false.`],
        ["Enable deletion protection or document an explicit exception with recovery evidence."]);
    }

    if (/aws_s3_bucket_public_access_block/i.test(type) &&
      /"block_public_acls"\s*:\s*false|"block_public_policy"\s*:\s*false|"restrict_public_buckets"\s*:\s*false/.test(afterText)) {
      addFinding(findings, "TF-SEC-S3-PUBLIC-BLOCK-DISABLED", "critical", "S3 public-access block is weakened",
        [`${address} disables one or more S3 public-access-block controls.`],
        ["Keep all S3 public-access-block controls enabled unless a reviewed public distribution design requires otherwise."]);
    }

    if (/iam|role|policy/i.test(type) && /"\*"|:\*/.test(afterText)) {
      addFinding(findings, "TF-SEC-IAM-WILDCARD", "high", "Terraform IAM change contains wildcard permission scope",
        [`${address} contains wildcard IAM-like values.`],
        ["Review the generated IAM document and replace wildcards with explicit actions/resources."]);
    }

    if (environment === "production" && beforeText && afterText === "{}" && deletes) {
      addFinding(findings, "TF-SEC-PROD-DELETE", "medium", "Production change deletes a managed resource",
        [`${address} has a delete action.`],
        ["Confirm dependency ordering, recovery evidence and the intended destroy target before apply."]);
    }
  }

  if (changed === 0) throw new Error("Terraform plan contains no actionable resource changes.");
  const summary = summarize(findings);
  return {
    environment,
    policyPack: "terraform-security-v1",
    changedResources: changed,
    destructiveChanges: destructive,
    replacements,
    ...summary,
    findings,
    recommendedGate: summary.riskScore >= 75 ? "block" : summary.riskScore >= 50 ? "change-advisory-review" : "standard-review"
  };
}

const dangerousCapabilities = new Set(["SYS_ADMIN", "SYS_PTRACE", "NET_ADMIN", "SYS_MODULE", "DAC_READ_SEARCH", "DAC_OVERRIDE"]);

export function reviewKubernetesSecurity(input: KubernetesSecurityInput) {
  const docs = parseAllDocuments(input.manifestYaml).map((document) => document.toJSON()).filter(Boolean) as Array<Record<string, any>>;
  const workloads = docs.filter((doc) => ["Deployment", "StatefulSet", "DaemonSet", "Job", "CronJob", "Pod"].includes(doc.kind));
  if (workloads.length === 0) throw new Error("manifestYaml must include at least one Kubernetes workload.");

  const findings: SecurityFinding[] = [];
  const environment = input.environment ?? "production";
  const hasNetworkPolicy = docs.some((doc) => doc.kind === "NetworkPolicy");
  const publicServices = docs.filter((doc) =>
    doc.kind === "Ingress" ||
    (doc.kind === "Service" && ["LoadBalancer", "NodePort"].includes(doc.spec?.type))
  );

  for (const workload of workloads) {
    const name = String(workload.metadata?.name ?? "unnamed");
    const templateSpec = workload.kind === "Pod"
      ? workload.spec ?? {}
      : workload.kind === "CronJob"
        ? workload.spec?.jobTemplate?.spec?.template?.spec ?? {}
        : workload.spec?.template?.spec ?? {};
    const containers = [
      ...(Array.isArray(templateSpec.containers) ? templateSpec.containers : []),
      ...(Array.isArray(templateSpec.initContainers) ? templateSpec.initContainers : [])
    ];

    if (templateSpec.hostNetwork === true || templateSpec.hostPID === true || templateSpec.hostIPC === true) {
      addFinding(findings, "K8S-SEC-HOST-NAMESPACE", "high", "Workload shares a host namespace",
        [`${name} enables hostNetwork, hostPID or hostIPC.`],
        ["Disable host namespace sharing unless explicitly required by a privileged infrastructure workload."]);
    }

    const volumes = Array.isArray(templateSpec.volumes) ? templateSpec.volumes : [];
    if (volumes.some((volume: any) => volume?.hostPath)) {
      addFinding(findings, "K8S-SEC-HOSTPATH", "high", "Workload mounts a hostPath volume",
        [`${name} declares hostPath storage.`],
        ["Replace hostPath with scoped persistent volumes or platform-managed storage where possible."]);
    }

    const serviceAccountName = String(templateSpec.serviceAccountName ?? "default");
    if (serviceAccountName === "default" && templateSpec.automountServiceAccountToken !== false) {
      addFinding(findings, "K8S-SEC-DEFAULT-SA-TOKEN", "medium",
        "Workload can use the default service account token",
        [`${name} uses the default service account and does not disable token automount.`],
        ["Use a dedicated least-privilege service account and disable automountServiceAccountToken when Kubernetes API access is unnecessary."]);
    }

    for (const container of containers) {
      const containerName = String(container?.name ?? "unnamed-container");
      const security = container?.securityContext ?? {};
      const podSecurity = templateSpec.securityContext ?? {};

      if (security.privileged === true) {
        addFinding(findings, "K8S-SEC-PRIVILEGED", "critical", "Privileged container detected",
          [`${name}/${containerName} sets privileged=true.`],
          ["Remove privileged mode and grant only the narrow Linux capabilities or device access actually required."]);
      }

      if (security.allowPrivilegeEscalation === true) {
        addFinding(findings, "K8S-SEC-PRIV-ESC", "high", "Container allows privilege escalation",
          [`${name}/${containerName} sets allowPrivilegeEscalation=true.`],
          ["Set allowPrivilegeEscalation=false and enforce a restricted Pod Security posture."]);
      }

      if (security.runAsUser === 0 || security.runAsNonRoot === false || podSecurity.runAsUser === 0 || podSecurity.runAsNonRoot === false) {
        addFinding(findings, "K8S-SEC-ROOT", "high", "Container or pod security context permits root execution",
          [`${name}/${containerName} permits UID 0 or runAsNonRoot=false.`],
          ["Set runAsNonRoot=true and use a non-zero runAsUser compatible with the image."]);
      }

      const addedCapabilities = strings(security.capabilities?.add).map((capability) => capability.toUpperCase());
      const dangerous = addedCapabilities.filter((capability) => dangerousCapabilities.has(capability));
      if (dangerous.length > 0) {
        addFinding(findings, "K8S-SEC-DANGEROUS-CAP", "high", "Container adds dangerous Linux capabilities",
          [`${name}/${containerName} adds ${dangerous.join(", ")}.`],
          ["Drop ALL capabilities and add back only the minimum required capability set."]);
      }

      const ports = Array.isArray(container?.ports) ? container.ports : [];
      if (ports.some((port: any) => typeof port?.hostPort === "number" && port.hostPort > 0)) {
        addFinding(findings, "K8S-SEC-HOSTPORT", "medium", "Container binds a hostPort",
          [`${name}/${containerName} declares hostPort.`],
          ["Prefer ClusterIP/Ingress/LoadBalancer routing instead of hostPort unless node-level binding is required."]);
      }

      if (environment === "production" && security.readOnlyRootFilesystem !== true) {
        addFinding(findings, "K8S-SEC-READONLY-FS", "medium",
          "Production container does not enforce a read-only root filesystem",
          [`${name}/${containerName} lacks readOnlyRootFilesystem=true.`],
          ["Set readOnlyRootFilesystem=true and use explicit writable volumes for required paths."]);
      }
    }

    const seccomp = templateSpec.securityContext?.seccompProfile?.type;
    if (environment === "production" && !["RuntimeDefault", "Localhost"].includes(seccomp)) {
      addFinding(findings, "K8S-SEC-SECCOMP", "medium", "Production workload does not declare a seccomp profile",
        [`${name} does not declare RuntimeDefault or Localhost seccomp.`],
        ["Set pod securityContext.seccompProfile.type to RuntimeDefault unless a reviewed custom Localhost profile is required."]);
    }
  }

  if (publicServices.length > 0 && !hasNetworkPolicy) {
    addFinding(findings, "K8S-SEC-PUBLIC-NO-NETPOL", "high",
      "Public Kubernetes exposure has no NetworkPolicy in the supplied manifest bundle",
      [`${publicServices.length} public Service/Ingress objects were found and no NetworkPolicy was supplied.`],
      ["Add ingress/egress NetworkPolicy controls and verify the cluster network plugin enforces them."]);
  }

  const summary = summarize(findings);
  return {
    environment,
    policyPack: "kubernetes-security-v1",
    workloadCount: workloads.length,
    publicExposureObjects: publicServices.length,
    networkPolicyPresent: hasNetworkPolicy,
    ...summary,
    findings,
    recommendedGate: summary.riskScore >= 75 ? "block" : summary.riskScore >= 50 ? "security-review" : "standard-review"
  };
}

function parseSbom(sbomJson: string) {
  const sbom = parseJsonObject(sbomJson, "sbomJson");
  if (String(sbom.bomFormat ?? "").toLowerCase() === "cyclonedx") {
    const components = Array.isArray(sbom.components) ? sbom.components : [];
    return {
      format: "CycloneDX",
      specVersion: String(sbom.specVersion ?? "unknown"),
      components: components.map((component: any) => ({
        name: String(component?.name ?? ""),
        version: component?.version ? String(component.version) : undefined,
        hashes: Array.isArray(component?.hashes) ? component.hashes : [],
        purl: component?.purl ? String(component.purl) : undefined,
        licenses: Array.isArray(component?.licenses) ? component.licenses : []
      }))
    };
  }

  if (typeof sbom.spdxVersion === "string") {
    const packages = Array.isArray(sbom.packages) ? sbom.packages : [];
    return {
      format: "SPDX",
      specVersion: sbom.spdxVersion,
      components: packages.map((pkg: any) => ({
        name: String(pkg?.name ?? ""),
        version: pkg?.versionInfo ? String(pkg.versionInfo) : undefined,
        hashes: Array.isArray(pkg?.checksums) ? pkg.checksums : [],
        purl: Array.isArray(pkg?.externalRefs)
          ? pkg.externalRefs.find((ref: any) => String(ref?.referenceType ?? "").toLowerCase().includes("purl"))?.referenceLocator
          : undefined,
        licenses: pkg?.licenseConcluded || pkg?.licenseDeclared ? [pkg.licenseConcluded ?? pkg.licenseDeclared] : []
      }))
    };
  }

  throw new Error("sbomJson must be CycloneDX or SPDX JSON.");
}

function workflowFacts(workflowYaml?: string) {
  if (!workflowYaml) return { mutableActions: false, actionRefs: [] as string[] };
  let workflow: any;
  try {
    workflow = parseYaml(workflowYaml);
  } catch {
    throw new Error("workflowYaml must be valid YAML.");
  }
  const jobs = workflow?.jobs && typeof workflow.jobs === "object" ? Object.values(workflow.jobs) as any[] : [];
  const actionRefs: string[] = [];
  for (const job of jobs) {
    for (const step of Array.isArray(job?.steps) ? job.steps : []) {
      if (typeof step?.uses === "string" && !step.uses.startsWith("./") && !step.uses.startsWith("docker://")) {
        actionRefs.push(step.uses);
      }
    }
  }
  return {
    mutableActions: actionRefs.some((ref) => !/@[0-9a-f]{40}$/i.test(ref)),
    actionRefs
  };
}

function kubernetesImageFacts(manifestYaml?: string) {
  if (!manifestYaml) return { mutableImages: false, images: [] as string[] };
  const docs = parseAllDocuments(manifestYaml).map((document) => document.toJSON()).filter(Boolean) as Array<Record<string, any>>;
  const images: string[] = [];
  for (const doc of docs) {
    const specs = [
      doc.kind === "Pod" ? doc.spec : doc.spec?.template?.spec,
      doc.kind === "CronJob" ? doc.spec?.jobTemplate?.spec?.template?.spec : undefined
    ].filter(Boolean);
    for (const spec of specs) {
      for (const container of [...(spec.containers ?? []), ...(spec.initContainers ?? [])]) {
        if (typeof container?.image === "string") images.push(container.image);
      }
    }
  }
  return {
    mutableImages: images.some((image) => !image.includes("@sha256:")),
    images
  };
}

export function reviewSoftwareSupplyChain(input: SupplyChainInput) {
  const sbom = parseSbom(input.sbomJson);
  const workflow = workflowFacts(input.workflowYaml);
  const runtime = kubernetesImageFacts(input.kubernetesManifestYaml);
  const findings: SecurityFinding[] = [];
  const environment = input.environment ?? "production";
  const components = sbom.components;

  if (components.length === 0) {
    addFinding(findings, "SC-SBOM-EMPTY", "critical", "SBOM contains no components",
      [`${sbom.format} ${sbom.specVersion} contains zero components.`],
      ["Generate the SBOM from the resolved build graph or final container filesystem and fail the build if it is empty."]);
  }

  const missingVersion = components.filter((component) => !component.version).length;
  const missingHash = components.filter((component) => component.hashes.length === 0).length;
  const missingPurl = components.filter((component) => !component.purl).length;
  const missingLicense = components.filter((component) => component.licenses.length === 0).length;
  const ratio = (count: number) => components.length === 0 ? 1 : count / components.length;

  if (ratio(missingVersion) > 0.2) {
    addFinding(findings, "SC-SBOM-VERSION-COVERAGE", "high", "SBOM has weak component version coverage",
      [`${missingVersion}/${components.length} components lack a version.`],
      ["Populate resolved component versions in the generated SBOM."]);
  }
  if (ratio(missingHash) > 0.5) {
    addFinding(findings, "SC-SBOM-HASH-COVERAGE", "medium", "SBOM has weak checksum coverage",
      [`${missingHash}/${components.length} components lack hashes/checksums.`],
      ["Include component checksums where the SBOM generator supports them."]);
  }
  if (ratio(missingPurl) > 0.5) {
    addFinding(findings, "SC-SBOM-PURL-COVERAGE", "medium", "SBOM has weak package URL coverage",
      [`${missingPurl}/${components.length} components lack purl identifiers.`],
      ["Include package URLs so components can be matched reliably to advisory and inventory systems."]);
  }
  if (ratio(missingLicense) > 0.5) {
    addFinding(findings, "SC-SBOM-LICENSE-COVERAGE", "medium", "SBOM has weak license metadata coverage",
      [`${missingLicense}/${components.length} components lack license metadata.`],
      ["Populate declared or concluded license data and route unknowns for review."]);
  }

  if (workflow.mutableActions) {
    addFinding(findings, "SC-CI-MUTABLE-ACTIONS", "high", "CI workflow uses mutable external action references",
      workflow.actionRefs, ["Pin external GitHub Actions to immutable full commit SHAs."]);
  }

  if (runtime.mutableImages) {
    addFinding(findings, "SC-RUNTIME-MUTABLE-IMAGE", "high", "Kubernetes workload uses image references without digests",
      runtime.images, ["Deploy production images by immutable sha256 digest and retain tag-to-digest provenance."]);
  }

  if (input.artifactSigned === false) {
    addFinding(findings, "SC-UNSIGNED-ARTIFACT", "high", "Release artifact is explicitly marked unsigned",
      ["artifactSigned=false"], ["Sign release artifacts or container images and verify signatures before deployment."]);
  }

  if (input.hasProvenance === false) {
    addFinding(findings, "SC-NO-PROVENANCE", "high", "Release has no build provenance",
      ["hasProvenance=false"], ["Generate verifiable SLSA-compatible provenance from the trusted build system."]);
  }

  const correlationPaths: Array<{ pathId: string; severity: "high" | "critical"; sequence: string[]; impact: string }> = [];

  if (workflow.mutableActions && runtime.mutableImages) {
    addFinding(findings, "SC-CORR-MUTABLE-BUILD-RUNTIME", "critical",
      "Mutable build dependency and mutable runtime artifact appear in the same release path",
      [...workflow.actionRefs, ...runtime.images],
      ["Pin CI actions and runtime images simultaneously, then record commit-to-artifact-to-image provenance."]);
    correlationPaths.push({
      pathId: "SC-CORR-MUTABLE-BUILD-RUNTIME",
      severity: "critical",
      sequence: ["Mutable CI action", "Build output", "Mutable container image", "Kubernetes runtime"],
      impact: "Two mutable links weaken reproducibility and make artifact substitution harder to detect."
    });
  }

  if (input.artifactSigned === false && input.hasProvenance === false && components.length > 0) {
    addFinding(findings, "SC-CORR-UNVERIFIED-ARTIFACT", "critical",
      "SBOM exists but the artifact has neither signature nor provenance",
      [`${sbom.format} SBOM is present, artifactSigned=false, hasProvenance=false.`],
      ["Bind SBOM, provenance and artifact digest together in the release process and verify them at deployment time."]);
    correlationPaths.push({
      pathId: "SC-CORR-UNVERIFIED-ARTIFACT",
      severity: "critical",
      sequence: ["SBOM inventory", "Unsigned artifact", "No provenance", "Deployment"],
      impact: "Inventory exists, but there is no cryptographic proof that it describes the artifact being deployed."
    });
  }

  const summary = summarize(findings);
  return {
    environment,
    policyPack: "software-supply-chain-v1",
    sbomFormat: sbom.format,
    sbomSpecVersion: sbom.specVersion,
    componentCount: components.length,
    metadataCoverage: {
      versionsPresentPercent: components.length ? Math.round((1 - missingVersion / components.length) * 100) : 0,
      hashesPresentPercent: components.length ? Math.round((1 - missingHash / components.length) * 100) : 0,
      purlPresentPercent: components.length ? Math.round((1 - missingPurl / components.length) * 100) : 0,
      licensesPresentPercent: components.length ? Math.round((1 - missingLicense / components.length) * 100) : 0
    },
    mutableActionReferences: workflow.mutableActions,
    mutableRuntimeImages: runtime.mutableImages,
    artifactSigned: input.artifactSigned ?? null,
    hasProvenance: input.hasProvenance ?? null,
    ...summary,
    findings,
    correlationPaths,
    recommendedGate: summary.riskScore >= 75 ? "block" : summary.riskScore >= 50 ? "supply-chain-review" : "standard-review"
  };
}
