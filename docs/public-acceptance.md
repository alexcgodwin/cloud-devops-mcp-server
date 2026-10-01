# Public Release Acceptance

Release: `cloud-devops-mcp-server@0.3.1`
Date: 2026-10-01

This verification was performed from a clean directory using the package published on npm rather than the repository source checkout.

## Results

| Check | Result |
| --- | --- |
| Clean npm install | Pass |
| npm dependency audit | 0 vulnerabilities |
| Installed CLI shim | Pass |
| stdio MCP connection | Pass |
| Tool discovery | 8 of 8 tools |
| Cross-domain cloud change bundle call | Pass |
| Terraform assessment call | Pass |
| Incident runbook call | Pass |
| CI/CD review call | Pass |
| SLO budget call | Pass |
| IAM policy review call | Pass |
| Kubernetes review call | Pass |
| GitHub Actions review call | Pass |
| Structured output returned | Pass |
| Malformed single-domain bundle rejected | Pass |
| Public `npx` launch | Pass |
| Sensitive filename scan | No findings |
| Credential/token/private-key pattern scan | No findings |
| npm trusted publish | GitHub Actions OIDC |
| npm provenance | SLSA provenance v1 |
| MCP Registry status | Active, latest = 0.3.1 |

## Public command tested

Windows:

```powershell
npx.cmd -y cloud-devops-mcp-server@0.3.1
```

The public command started `cloud-devops-mcp-server v0.3.1` over stdio, exposed eight MCP tools and completed a live `assess_cloud_change_bundle` invocation successfully.

## Cross-domain acceptance scenario

The acceptance test supplied production Terraform, IAM, Kubernetes and GitHub Actions evidence to `assess_cloud_change_bundle`.

The result returned:

- Bundle risk level: `critical`
- Release gate: `hold-for-remediation`
- Correlated findings: 4
- Structured content: present

A malformed bundle containing only one evidence domain was rejected as expected.

## Published package contents

The installed package contained only release artifacts:

- README, changelog, license, manifest and Registry metadata.
- Compiled `dist` JavaScript, declarations and source maps.
- Architecture, configuration, demo, tool and troubleshooting documentation.

No `.env`, credential, private-key, token, test fixture or development-only source files were found in the published package.

## Distribution status

- npm package: `cloud-devops-mcp-server@0.3.1`
- npm dist-tag: `latest = 0.3.1`
- npm provenance: SLSA provenance v1
- MCP Registry name: `io.github.alexcgodwin/cloud-devops-mcp-server`
- MCP Registry status: active
- MCP Registry latest version: `0.3.1`
- Transport: stdio
