# Security Policy

## Supported versions

| Version | Supported |
| --- | --- |
| 0.4.x | Yes |
| 0.3.x | Security fixes |
| 0.2.x | Best-effort security fixes |
| 0.1.x | No |

## Security posture

Cloud DevOps MCP Server is advisory and read-only. It does not deploy infrastructure, mutate cloud resources, execute supplied configuration, or require cloud-provider credentials for its analysis tools.

It parses structured inputs and raw Terraform plan JSON, AWS IAM policy JSON, Azure RBAC JSON, GCP IAM JSON, Kubernetes YAML, GitHub Actions workflow YAML, CycloneDX JSON and SPDX JSON in-process.

All registered tools are marked read-only, non-destructive and idempotent.

## Transport security

### Stdio

Stdio is the default transport and requires no server secret.

### Streamable HTTP

HTTP mode is explicit opt-in with `--http`.

Controls include:

- Bearer authentication with a minimum 32-character token.
- Timing-safe token comparison.
- Host header validation.
- Origin header validation.
- Non-local binding requires an explicit Host allowlist.
- Non-local binding requires an HTTPS public base URL representing TLS termination at a reverse proxy or gateway.
- The bearer token is never written by the server to normal output.

A shared static bearer token is intended for private self-hosted use. Multi-user or public hosted deployments should use an OAuth/OIDC-aware gateway or a future standards-based OAuth resource-server mode.

## Secrets

Do not commit:

- `CLOUD_DEVOPS_MCP_BEARER_TOKEN`
- cloud credentials
- GitHub/npm tokens
- private keys
- production configuration containing secrets

Rotate the HTTP bearer token if it is exposed.

## Supply-chain release security

npm releases use GitHub Actions trusted publishing with OIDC and SLSA provenance. CI uses immutable action commit SHAs and read-only repository permissions for the normal quality gate.

## Reporting a vulnerability

Open a private security advisory or contact Alex C. Godwin through the profile links in the repository README.

Include:

- Affected version or commit.
- Steps to reproduce.
- Expected and actual behavior.
- Impact and suggested mitigation, if known.
