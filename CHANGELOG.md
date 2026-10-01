# Changelog

All notable changes to Cloud DevOps MCP Server will be documented in this file.

The format follows Keep a Changelog, and this project uses semantic versioning.

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
