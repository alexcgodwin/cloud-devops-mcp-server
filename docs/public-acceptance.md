# Public Release Acceptance

Release: `cloud-devops-mcp-server@0.4.0`
Date: 2026-10-01

This verification was performed from a clean directory using the package published on npm rather than the repository source checkout.

## Results

| Check | Result |
| --- | --- |
| Clean npm install | Pass |
| npm dependency audit | 0 vulnerabilities |
| Installed CLI shim | Pass |
| stdio MCP connection | Pass |
| Tool discovery | 12 of 12 tools |
| Cross-domain cloud change bundle | Pass |
| Terraform change assessment | Pass |
| Incident runbook | Pass |
| CI/CD review | Pass |
| SLO budget | Pass |
| AWS IAM review | Pass |
| Kubernetes deployment review | Pass |
| GitHub Actions review | Pass |
| Multi-cloud identity: AWS | Pass |
| Multi-cloud identity: Azure | Pass |
| Multi-cloud identity: GCP | Pass |
| Terraform security policy pack | Pass |
| Kubernetes security policy pack | Pass |
| CycloneDX supply-chain correlation | Pass |
| Malformed cloud identity input rejected | Pass |
| Authenticated Streamable HTTP health check | Pass |
| Invalid HTTP bearer token | 401 Unauthorized |
| Valid HTTP bearer token | Pass |
| HTTP tool discovery | 12 of 12 tools |
| Authenticated HTTP tool call | Pass |
| Sensitive filename scan | No findings |
| Credential/token/private-key pattern scan | No findings |
| npm trusted publish | GitHub Actions OIDC |
| npm provenance | SLSA provenance v1 |
| MCP Registry status | Active, latest = 0.4.0 |

## Public stdio command tested

Windows:

```powershell
npx.cmd -y cloud-devops-mcp-server@0.4.0
```

The public command started `cloud-devops-mcp-server v0.4.0` over stdio, exposed twelve MCP tools and completed calls across all twelve successfully.

## Multi-cloud policy-pack acceptance

The public package was exercised with all three supported identity-policy providers:

- AWS IAM policy JSON.
- Azure RBAC role-definition JSON.
- GCP IAM policy JSON.

All three provider packs returned structured MCP results successfully.

## Security-depth acceptance

The public package successfully executed:

- `review_terraform_security` against Terraform plan JSON.
- `review_kubernetes_security` against hardened Kubernetes YAML.
- `review_software_supply_chain` against CycloneDX 1.6 SBOM data, immutable GitHub Action references, signed-artifact evidence, provenance evidence and digest-pinned Kubernetes images.

The supply-chain test returned structured SBOM metadata coverage, mutation checks, security findings and correlation output.

## Authenticated Streamable HTTP acceptance

The published npm package was started directly in HTTP mode with:

- Loopback binding on `127.0.0.1`.
- A bearer token longer than 32 characters.
- The public package entry point with `--http`.

The health endpoint returned:

```json
{
  "status": "ok",
  "transport": "streamable-http",
  "authentication": "bearer"
}
```

A request with an invalid bearer token returned HTTP `401`. A real MCP client using the valid bearer token connected successfully, discovered all twelve tools and completed a `review_cloud_identity_policy` call.

Remote non-loopback operation remains fail-closed unless allowed hosts and an HTTPS public base URL are explicitly configured.

## Published package contents

The installed package contained only expected release artifacts and runtime dependencies.

No `.env`, credential, private-key, token or suspicious secret-pattern files were found in the published package.

## Distribution status

- npm package: `cloud-devops-mcp-server@0.4.0`
- npm dist-tag: `latest = 0.4.0`
- npm provenance: SLSA provenance v1
- MCP Registry name: `io.github.alexcgodwin/cloud-devops-mcp-server`
- MCP Registry status: active
- MCP Registry latest version: `0.4.0`
- Default transport: stdio
- Optional transport: authenticated Streamable HTTP
