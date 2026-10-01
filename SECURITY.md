# Security Policy

## Supported versions

| Version | Supported |
| --- | --- |
| 0.2.x | Yes |
| 0.1.x | Best-effort security fixes |

## Security posture

Cloud DevOps MCP Server runs locally over stdio. It does not require secrets, cloud credentials or external network access.

The current version is advisory only. It parses structured inputs and optional raw Terraform plan JSON, IAM policy JSON, Kubernetes YAML and GitHub Actions workflow YAML in-process. It does not evaluate supplied code, deploy infrastructure, change cloud resources, write to production systems or call external APIs.

All registered tools are marked read-only, non-destructive and idempotent. Artifact-derived findings include evidence, while information that cannot be proven from the supplied artifact remains explicitly unknown.

## Reporting a vulnerability

Open a private security advisory or contact Alex C. Godwin through the profile links in the repository README.

Please include:

- Affected version or commit.
- Steps to reproduce.
- Expected and actual behavior.
- Impact and suggested mitigation, if known.
