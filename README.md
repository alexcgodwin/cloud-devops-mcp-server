# Cloud DevOps MCP Server

<!-- mcp-name: io.github.alexcgodwin/cloud-devops-mcp-server -->

[![CI](https://github.com/alexcgodwin/cloud-devops-mcp-server/actions/workflows/ci.yml/badge.svg)](https://github.com/alexcgodwin/cloud-devops-mcp-server/actions/workflows/ci.yml)
[![npm version](https://img.shields.io/npm/v/cloud-devops-mcp-server.svg)](https://www.npmjs.com/package/cloud-devops-mcp-server)
[![MCP Registry](https://img.shields.io/badge/MCP%20Registry-active-brightgreen.svg)](https://registry.modelcontextprotocol.io/v0.1/servers?search=io.github.alexcgodwin%2Fcloud-devops-mcp-server)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![MCP](https://img.shields.io/badge/MCP-Cloud%20DevOps-blue)](server.json)

Cloud DevOps MCP Server is a Model Context Protocol v2 server by Alex C. Godwin. It provides evidence-backed Cloud DevOps analysis across infrastructure, identity, Kubernetes, CI/CD, SRE and software supply-chain controls.

The v0.7 line adds an opt-in live multi-cloud read plane for AWS, Azure and GCP: identity verification, bounded inventory, EKS/AKS/GKE discovery, observability summaries, FinOps waste signals and expected-vs-live drift reporting. Cloud mutation remains intentionally unavailable.

## Table of contents

- [Why this exists](#why-this-exists)
- [Tools](#tools)
- [Architecture](#architecture)
- [Quickstart](#quickstart)
- [Install from npm](#install-from-npm)
- [MCP clients](#mcp-clients)
- [Configuration](#configuration)
- [Authenticated Streamable HTTP](#authenticated-streamable-http)
- [Public release verification](#public-release-verification)
- [Example tool input](#example-tool-input)
- [Demo outputs](#demo-outputs)
- [Docker](#docker)
- [Development](#development)
- [Security model](#security-model)
- [Roadmap](#roadmap)
- [Author](#author)

## Why this exists

AI assistants are more useful in engineering work when they can call focused tools with clear inputs and consistent outputs. This server provides a Cloud DevOps tool layer for:

- Cross-domain release-risk correlation across infrastructure, identity, runtime and delivery.
- Infrastructure-as-code deployment risk analysis.
- Production incident runbook generation.
- CI/CD delivery readiness review.
- SLO error budget calculations.
- AWS IAM least-privilege review.
- AWS, Azure and GCP identity policy packs.
- Terraform destructive-change, public exposure and encryption security analysis.
- Kubernetes workload production readiness and security-policy analysis.
- GitHub Actions workflow security and deployment review.
- CycloneDX/SPDX SBOM quality and software supply-chain correlation.
- Optional authenticated Streamable HTTP serving for self-hosted remote access.
- Optional allowlisted live AWS/Azure/GCP inventory, observability, FinOps and drift signals.

## Tools

| Tool | Purpose |
| --- | --- |
| `assess_cloud_change_bundle` | Correlates Terraform, IAM, Kubernetes and GitHub Actions evidence into one deployment-risk assessment with cross-domain change paths. |
| `assess_terraform_change` | Scores Terraform/IaC risk and can derive evidence from raw Terraform plan JSON. |
| `build_incident_runbook` | Produces a practical incident response runbook for a service, symptom, environment and severity. |
| `review_cicd_pipeline` | Reviews CI/CD maturity while separating failed controls from unknown evidence. |
| `estimate_slo_error_budget` | Calculates downtime and request-failure budgets with consistency validation. |
| `review_iam_policy` | Parses IAM policy JSON and detects wildcard scope and privilege-escalation paths. |
| `review_kubernetes_deployment` | Parses Kubernetes YAML for probes, resources, disruption protection, image and exposure risks. |
| `review_github_actions_workflow` | Parses workflow YAML for triggers, immutable action pins, permissions, caching and concurrency. |
| `review_cloud_identity_policy` | Applies AWS IAM, Azure RBAC or GCP IAM policy packs to raw policy JSON. |
| `review_terraform_security` | Reviews Terraform plan JSON for destructive changes, public exposure, encryption, deletion protection and wildcard IAM. |
| `review_kubernetes_security` | Reviews privileged mode, host access, service accounts, capabilities, seccomp, root filesystems and NetworkPolicy. |
| `review_software_supply_chain` | Correlates CycloneDX/SPDX SBOM quality with CI action pinning, image immutability, signatures and provenance. |

### Optional live multi-cloud reads

When explicitly enabled, six additional tools provide allowlisted AWS/Azure/GCP identity verification, bounded inventory, managed Kubernetes discovery, observability configuration summaries, FinOps waste signals and drift reporting. No cloud mutation commands are exposed. AWS general inventory is sourced from the Resource Groups Tagging API, so untagged AWS resources may not appear in that inventory or AWS drift comparison.

### Optional infrastructure operations

When explicitly enabled, six additional tools provide Terraform format/validation/plan summaries and Kubernetes read-only runtime inspection. These operations use repository, context, namespace and resource allowlists. Full Terraform plan JSON, Kubernetes Secrets, arbitrary shell execution, Terraform apply and Kubernetes mutation are deliberately excluded.
## Architecture

```mermaid
flowchart TD
  LocalClient["Local MCP client"] --> Stdio["stdio"]
  RemoteClient["Remote MCP client"] --> HTTPS["HTTPS reverse proxy / gateway"]
  HTTPS --> AuthHTTP["Bearer-authenticated Streamable HTTP"]
  Stdio --> Server["Cloud DevOps MCP server"]
  AuthHTTP --> Server
  Server --> DomainTools["Domain + policy-pack analyzers"]
  DomainTools --> Correlator["Cross-domain and supply-chain correlation"]
  DomainTools --> Output["Structured guidance"]
  Correlator --> Output
```

## Quickstart

Run the published MCP server directly from npm:

```bash
npx -y cloud-devops-mcp-server@0.7.0
```

On Windows PowerShell systems where script execution policy blocks `npx.ps1`, use:

```powershell
npx.cmd -y cloud-devops-mcp-server@0.7.0
```

## Install from npm

Install the CLI globally if you prefer a persistent local command:

```bash
npm install -g cloud-devops-mcp-server@0.7.0
cloud-devops-mcp-server
```

The package is published on npm as `cloud-devops-mcp-server` and registered in the official MCP Registry as `io.github.alexcgodwin/cloud-devops-mcp-server`.

## MCP clients

Cloud DevOps MCP Server supports local stdio clients and MCP clients capable of connecting to Streamable HTTP endpoints. Common local clients include:

- Cursor
- Claude Desktop
- VS Code with MCP support
- Claude Code
- Other clients that follow the Model Context Protocol stdio transport

Use stdio for normal local operation. For self-hosted remote access, start the optional authenticated Streamable HTTP endpoint and place non-local deployments behind an HTTPS reverse proxy or gateway.

## Configuration

For MCP clients that support local stdio servers, the recommended public configuration is:

```json
{
  "mcpServers": {
    "cloud-devops": {
      "command": "npx",
      "args": ["-y", "cloud-devops-mcp-server@0.7.0"]
    }
  }
}
```

Windows clients can use `npx.cmd` if `npx` resolves through a blocked PowerShell wrapper:

```json
{
  "mcpServers": {
    "cloud-devops": {
      "command": "npx.cmd",
      "args": ["-y", "cloud-devops-mcp-server@0.7.0"]
    }
  }
}
```

See [docs/configuration.md](docs/configuration.md) for npm, global-install, source-development and authenticated Streamable HTTP configuration options.

## Authenticated Streamable HTTP

Local loopback example:

```powershell
$env:CLOUD_DEVOPS_MCP_BEARER_TOKEN="<random secret at least 32 characters>"
npm run start:http
```

The MCP endpoint is `http://127.0.0.1:3000/mcp` and requires `Authorization: Bearer <token>`. A non-local bind additionally requires `CLOUD_DEVOPS_MCP_ALLOWED_HOSTS` and an HTTPS `CLOUD_DEVOPS_MCP_PUBLIC_BASE_URL` so remote traffic is expected to terminate TLS at a reverse proxy or gateway.

## Public release verification

The v0.7.0 release candidate passes 57 automated tests, the full coverage gate and a production dependency audit with zero vulnerabilities. Public clean-install acceptance is recorded after npm and MCP Registry publication.

See [docs/public-acceptance.md](docs/public-acceptance.md) for the verification record.

## Example tool input

```json
{
  "changedResources": ["network", "iam", "kubernetes"],
  "includesIamChanges": true,
  "includesPublicIngress": true,
  "modifiesStatefulResources": false,
  "hasRollbackPlan": true,
  "hasPeerReview": true,
  "hasTerraformPlan": true
}
```

Example output shape:

```json
{
  "riskScore": 78,
  "riskLevel": "critical",
  "changedResources": ["network", "iam", "kubernetes"],
  "recommendedReleasePath": "Change-advisory review, maintenance window and staged execution are recommended."
}
```

## Demo outputs

See [docs/demo.md](docs/demo.md) for practical sample inputs and outputs across the toolset.

## Docker

Build and run the server in a container:

```bash
docker build -t cloud-devops-mcp-server .
docker run --rm -i cloud-devops-mcp-server
```

## Development

```bash
npm run dev
npm run build
npm test
npm run check
```

The core decision logic lives in `src/logic.ts` and the MCP tool registration lives in `src/index.ts`.

More project notes are available in [DEVELOPMENT.md](DEVELOPMENT.md), [RELEASE.md](RELEASE.md) and [docs/architecture.md](docs/architecture.md).

## Security model

- Stdio remains the default and requires no secrets.
- Optional Streamable HTTP requires a bearer token of at least 32 characters.
- Non-local HTTP binds require an explicit Host allowlist and an HTTPS public base URL for reverse-proxy/gateway termination.
- Host and Origin validation are enabled through the official MCP Fastify adapter.
- The default analysis tools do not require cloud credentials or call cloud APIs.
- Optional Terraform/Kubernetes operations may use locally configured provider or cluster credentials after explicit enablement and allowlisting.
- Optional live cloud reads use existing AWS CLI, Azure CLI or gcloud authentication and require explicit account/subscription/project allowlists.
- No cloud mutation tool is exposed.
- Analysis remains read-only by default. Controlled execution appears only when explicitly enabled and allowlisted.
- No generic shell tool or force-push capability is exposed.
- Direct commit/push on protected branches is blocked, and high-impact GitHub actions require explicit confirmation.
- Analysis outputs are advisory. Optional operational tools remain bounded by explicit allowlists and fixed command/API surfaces.

## Roadmap

- Add richer cloud organization/account topology and tag-governance analysis on top of the read-only live inventory plane.
- Add OAuth/OIDC resource-server authentication for multi-user hosted deployments.
- Add machine-readable policy profiles for production, staging and regulated workloads.
- Add vulnerability-database enrichment for SBOM components without weakening offline deterministic analysis.
- Expand policy packs for data classification, secrets management, network segmentation and cloud organization guardrails.

## Author

Built by [Alex C. Godwin](https://github.com/alexcgodwin), Cloud DevOps Engineer.
