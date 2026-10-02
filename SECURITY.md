# Security Policy

## Supported versions

| Version | Supported |
| --- | --- |
| 0.14.x | Yes |
| 0.13.x | Security fixes |
| 0.12.x | Best-effort security fixes |
| 0.11.x and earlier | No |

## Security posture

Cloud DevOps MCP Server is read-only by default. The default analysis surface does not deploy infrastructure, mutate cloud resources, execute supplied configuration, or require cloud-provider credentials. Optional controlled Git/GitHub execution is separately gated and allowlisted.

It parses structured inputs and raw Terraform plan JSON, AWS IAM policy JSON, Azure RBAC JSON, GCP IAM JSON, Kubernetes YAML, GitHub Actions workflow YAML, CycloneDX JSON and SPDX JSON in-process.

The v0.10 `diagnose_root_cause` gateway is read-only. It sends bounded evidence to a host-configured private OpsChugex service and contains no proprietary ranking rules or remediation capability.

The v0.11 `assess_governance_policy` gateway is separately gated and read-only. It sends bounded resource evidence and exception metadata to a host-configured private OpsChugex policy service. The public repository contains no proprietary governance profiles, policy rules, scoring weights, exception-processing logic or enforcement capability.

The v0.12 `assess_cloud_security_posture` gateway is also separately gated and read-only. It sends bounded asset, identity, secret and network evidence to a host-configured private OpsChugex security service. The public repository contains no proprietary security detection thresholds, scoring rules, attack-path algorithm or remediation capability.

The v0.13 `analyze_advanced_finops` gateway is separately gated and read-only. It sends bounded cost and utilization evidence to a host-configured private OpsChugex FinOps service. The public repository contains no proprietary savings factors, anomaly thresholds, prioritization, confidence or deduplication logic and cannot perform billing or infrastructure mutations.

The v0.14 `analyze_change_blast_radius` gateway is separately gated and read-only. It sends bounded planned-change, topology and readiness evidence to a host-configured private OpsChugex change-intelligence service. The public repository contains no proprietary dependency-propagation algorithm, risk weighting, blocker rules, readiness scoring or change-approval logic.

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
- `CLOUD_DEVOPS_MCP_OPSCHUGEX_TOKEN`
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

- Production-observability integrations are opt-in, exact-allowlisted, read-only, bounded and redacted; Prometheus/Grafana use HTTPS except for loopback development endpoints, and credentials remain host-side.
- The v0.10 root-cause, v0.11 governance, v0.12 security posture, v0.13 FinOps and v0.14 change-intelligence gateways are independently opt-in, use host-configured HTTPS endpoints plus a minimum 32-character host-side bearer token, and accept neither endpoint configuration nor credentials from MCP callers.
