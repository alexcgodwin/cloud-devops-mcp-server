# Changelog

All notable changes to Cloud DevOps MCP Server will be documented in this file.

The format follows Keep a Changelog, and this project uses semantic versioning.

## [0.4.0] - 2026-10-01

### Added

- AWS, Azure and GCP identity policy packs through `review_cloud_identity_policy`.
- Deeper Terraform security analysis for destructive stateful changes, sensitive public ports, public data services, encryption, deletion protection, S3 public-access controls and IAM wildcards.
- Kubernetes security-policy analysis for privileged containers, host namespaces, hostPath, Linux capabilities, default service-account tokens, hostPort, seccomp, read-only root filesystems and NetworkPolicy.
- CycloneDX and SPDX SBOM parsing plus software supply-chain correlation across CI action pinning, container image immutability, artifact signing and build provenance.
- Optional bearer-authenticated Streamable HTTP serving through the MCP v2 HTTP handler.
- Host/Origin validation, minimum bearer-token length and HTTPS reverse-proxy requirements for non-local HTTP binding.
- End-to-end authenticated Streamable HTTP client tests.
- Four new public MCP tools, bringing the tool count to twelve.

### Changed

- Runtime, package, manifest and Registry metadata advanced to 0.4.0.
- Local stdio remains the default transport; remote HTTP is explicit opt-in.
- Security and architecture documentation now cover the authenticated HTTP trust boundary.

## [0.3.1] - 2026-10-01

### Fixed

- Shortened the MCP Registry description to satisfy the official 100-character limit.
- Added automated metadata consistency checks for package, manifest and Registry versions.
- Added CI coverage for Registry name/package identity and the eight-tool manifest.
- Public installation examples now point to 0.3.1.

## [0.3.0] - 2026-10-01

### Added

- New `assess_cloud_change_bundle` MCP tool for cross-domain release analysis.
- Correlation across Terraform, AWS IAM, Kubernetes and GitHub Actions evidence.
- Domain risk summaries, correlated finding IDs, change-path sequencing and combined release gates.
- Correlation rules for public exposure, privileged production delivery, mutable supply chains, public-plus-privilege blast radius, root-capable public workloads and high-risk IAM changes inside Terraform.
- Multi-domain confidence and uncertainty aggregation.
- Contract coverage for all eight MCP tools.

### Changed

- MCP server runtime version advanced to 0.3.0.
- Registry and npm metadata now declare version 0.3.0.
- Public installation examples point to the 0.3.0 package.
- Roadmap now focuses on deeper policy packs, provenance and authenticated remote transport rather than cross-tool correlation.

## [0.2.1] - 2026-10-01

### Fixed

- Normalized the npm executable path so package installation exposes the `cloud-devops-mcp-server` CLI correctly.
- Normalized npm repository metadata before publication.
- Added the official MCP Registry npm package declaration with stdio transport.

## [0.2.0] - 2026-10-01

### Added

- MCP TypeScript SDK v2 support for the 2026-07-28 protocol line.
- Validated structured tool outputs with output schemas.
- Read-only, non-destructive and idempotent tool annotations.
- Direct Terraform plan JSON evidence parsing.
- Direct AWS IAM policy JSON parsing with wildcard and privilege-escalation detection.
- Direct multi-document Kubernetes YAML parsing.
- Direct GitHub Actions workflow YAML parsing.
- Evidence, uncertainty and assessment-confidence fields.
- MCP client/server contract tests and enforced coverage thresholds.
- Production dependency audit in the CI quality gate.

### Changed

- Missing optional controls are now reported as unknown instead of being treated as failed.
- CI actions are pinned to immutable commit SHAs and workflow token permissions are read-only.
- Registry metadata now uses an io.github.alexcgodwin namespace.
- Corrected the Terraform README example score from 60/high to 78/critical.
- Release version advanced to 0.2.0 for the new backward-compatible capabilities.

## [0.1.0] - 2026-10-01

### Added

- Initial Cloud DevOps MCP server.
- Terraform and infrastructure change risk assessment tool.
- Incident runbook generation tool.
- CI/CD pipeline readiness review tool.
- SLO error budget estimation tool.
- AWS IAM policy review tool.
- Kubernetes deployment readiness review tool.
- GitHub Actions workflow review tool.
- CI workflow, tests, security policy and contribution guide.
