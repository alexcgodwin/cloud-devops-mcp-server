# Public Release Acceptance

Release: `cloud-devops-mcp-server@0.7.0`
Date: 2026-10-01

This acceptance record was verified against the publicly published npm package and the official MCP Registry, not only the repository source checkout.

## Release status

| Check | Result |
| --- | --- |
| GitHub release | v0.7.0 published |
| npm latest | 0.7.0 |
| npm exact version | 0.7.0 available |
| npm trusted publish | GitHub Actions OIDC |
| Clean npm install audit | 0 vulnerabilities |
| MCP Registry schema validation | Pass |
| MCP Registry publication | GitHub Actions OIDC |
| MCP Registry status | Active |
| MCP Registry latest | 0.7.0 |
| Repository quality gate | 57 of 57 tests pass |
| Statement coverage | 84.71% |
| Branch coverage | 70.70% |
| Function coverage | 85.75% |
| Line coverage | 88.08% |
| Production dependency audit | 0 vulnerabilities |

## Clean public-install acceptance

A fresh temporary directory installed:

```powershell
npm.cmd install --ignore-scripts cloud-devops-mcp-server@0.7.0 @modelcontextprotocol/client@2.2.0
```

The clean installation completed with zero reported vulnerabilities. A real MCP client then spawned the installed package over stdio and verified these tool surfaces:

| Configuration | Tool count | Result |
| --- | ---: | --- |
| Default analysis | 12 | Pass |
| Controlled Git/GitHub execution enabled | 22 | Pass |
| Terraform/Kubernetes infrastructure operations enabled | 18 | Pass |
| Live multi-cloud reads enabled | 18 | Pass |
| All optional planes enabled | 34 | Pass |

A real `git_status` MCP call against an explicitly allowlisted temporary Git repository also passed.

## Live multi-cloud acceptance

The v0.7 cloud plane adds six opt-in tools:

- `cloud_whoami`
- `cloud_inventory_summary`
- `cloud_kubernetes_clusters`
- `cloud_observability_summary`
- `cloud_finops_signals`
- `cloud_drift_compare`

Automated tests exercise AWS, Azure and GCP paths with deterministic injected command runners rather than live production credentials.

### AWS

Acceptance covers:

- STS caller identity and account verification.
- Account, region and optional profile allowlists.
- Bounded normalized inventory from the Resource Groups Tagging API.
- EKS cluster discovery.
- CloudWatch alarm-state summaries.
- Available EBS volume detection.
- Unassociated Elastic IP detection.

AWS general inventory is tag-based. Untagged AWS resources may not appear in the general inventory or AWS drift comparison.

### Azure

Acceptance covers:

- Explicit subscription allowlisting.
- Azure Resource Manager inventory normalization.
- AKS cluster discovery.
- Azure metric-alert summaries.
- Unattached managed disk detection.
- Unassociated public IP detection.

### GCP

Acceptance covers:

- Explicit project allowlisting.
- Cloud Asset Inventory normalization.
- GKE cluster discovery.
- Logging-sink summaries.
- Persistent disks with no attached users.
- Reserved static IP signals.

GCP general inventory requires Cloud Asset Inventory access for the configured identity.

## Fail-closed public-package check

The clean npm-installed package was started with live-cloud reads enabled but without an Azure subscription allowlist.

A real `cloud_inventory_summary` MCP call was rejected before any Azure CLI inventory command could be accepted.

Result: **Pass**.

## Drift behavior

`cloud_drift_compare` compares caller-supplied expected resource identifiers with the bounded live inventory. Tests verify missing-expected and unexpected-live reporting and the ability to suppress unexpected-live output.

The drift tool has no reconciliation, create, update or delete path.

## Security boundary

The v0.7 release keeps the default twelve analysis tools credential-free and read-only.

Optional live cloud access requires explicit enablement plus provider scope allowlists:

- AWS account and region allowlists, with optional profile allowlist.
- Azure subscription allowlist.
- GCP project allowlist.

Cloud credentials remain managed by the host's AWS CLI, Azure CLI or gcloud configuration. Credentials and tokens are not accepted through MCP tool arguments and are not returned in responses.

The server deliberately exposes no:

- Generic shell tool.
- Cloud create/update/delete operation.
- Cloud start/stop/resize operation.
- Cloud attach/detach operation.
- Cloud IAM/policy mutation.
- Force-push.
- Terraform apply/destroy.
- Kubernetes mutation.

Operational audit records redact known access-key and token patterns.

## Distribution status

- npm package: `cloud-devops-mcp-server@0.7.0`
- npm dist-tag: `latest = 0.7.0`
- npm trusted publishing: GitHub Actions OIDC
- MCP Registry name: `io.github.alexcgodwin/cloud-devops-mcp-server`
- MCP Registry status: active
- MCP Registry latest version: `0.7.0`
- Default transport: stdio
- Optional transport: authenticated Streamable HTTP

This record supersedes the v0.6 public-acceptance record for the current release.
