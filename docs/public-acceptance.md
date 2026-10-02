# Public Release Acceptance

Release: `cloud-devops-mcp-server@0.10.0`
Date: 2026-10-02

This acceptance record was verified against repository CI, the publicly published npm package, a clean npm installation, a real MCP stdio client, the private OpsChugex v0.10 core integration, and the official MCP Registry publication workflow.

## Release status

| Check | Result |
| --- | --- |
| GitHub release | v0.10.0 published |
| npm exact version | 0.10.0 publicly available |
| npm latest dist-tag | 0.10.0 |
| npm trusted publish | GitHub Actions OIDC with provenance |
| Clean npm install audit | 0 vulnerabilities |
| MCP Registry schema validation | Pass |
| MCP Registry authentication | GitHub Actions OIDC |
| MCP Registry publication | Successfully published version 0.10.0 |
| Repository quality gate | 95 of 95 tests pass |
| Statement coverage | 85.65% |
| Branch coverage | 71.94% |
| Function coverage | 85.10% |
| Line coverage | 89.12% |
| Production dependency audit | 0 vulnerabilities |

## Clean public-install acceptance
A fresh temporary directory installed:

```powershell
npm.cmd install --ignore-scripts cloud-devops-mcp-server@0.10.0 @modelcontextprotocol/client@2.2.0
```

The clean installation completed with zero reported vulnerabilities.

A real MCP client spawned the npm-installed package over stdio and verified:

| Configuration | Tool count | Root-cause tool | Result |
| --- | ---: | --- | --- |
| Default analysis | 12 | Absent | Pass |
| v0.10 root-cause gateway enabled | 13 | Present | Pass |
| v0.9 tracing/SLO plane enabled | 18 | Absent | Pass |
| v0.8 observability + v0.9 tracing enabled | 30 | Absent | Pass |
| All optional capability planes enabled | 53 | Present | Pass |

The default public surface therefore remains unchanged at twelve tools. The v0.10 commercial gateway appears only when explicitly enabled.

## v0.10 automated root-cause intelligence acceptance

The v0.10 public package adds one optional tool:

- `diagnose_root_cause`

The tool accepts bounded incident evidence from:

- Metrics
- Logs
- Distributed traces
- Kubernetes
- Cloud-provider signals
- Terraform and infrastructure changes
- CI/CD and deployment evidence
The public MCP validates incident context and evidence, then forwards the request to a host-configured private OpsChugex service.

The public MIT package does not contain the proprietary cause-ranking weights, contradiction rules, commercial correlation logic, or future remediation logic.

Returned assessments include:

- Ranked probable causes
- Evidence-strength scores
- Confidence labels
- Supporting evidence IDs
- Contradicting evidence IDs
- Supporting evidence domains
- A concise reasoning summary
- Recommended next checks
- Explicit limitations

Evidence scores are evidence-strength indicators. They are not statistical probabilities and do not prove causation.

## End-to-end gateway acceptance

A local instance of the private OpsChugex v0.10 core was started on loopback for acceptance testing.

The clean npm-installed public MCP was configured only through host environment variables and called `diagnose_root_cause` through a real MCP stdio client.

The test supplied four incident evidence domains around a synthetic checkout deployment:

- CI/CD deployment evidence
- Kubernetes rollout failure evidence
- Distributed trace latency evidence
- Application log version-error evidence
The end-to-end result was:

```json
{
  "service": "checkout",
  "assessment": "strong",
  "topCause": "deployment_regression",
  "topConfidence": "strong",
  "topScore": 88,
  "domainCount": 4
}
```

This verifies the complete public-MCP-to-private-core request path without publishing the private ranking implementation.

No production credentials, customer data, or live customer infrastructure were used in this acceptance test.

## Security boundary

The v0.10 gateway is disabled by default and requires:

```text
CLOUD_DEVOPS_MCP_OPSCHUGEX_INTELLIGENCE_ENABLED=true
CLOUD_DEVOPS_MCP_OPSCHUGEX_ROOT_CAUSE_URL=<host-configured endpoint>
CLOUD_DEVOPS_MCP_OPSCHUGEX_TOKEN=<host-side secret>
```

Controls verified for the public gateway include:

- The endpoint cannot be supplied as an MCP tool argument.
- The bearer token cannot be supplied as an MCP tool argument.
- Remote endpoints must use HTTPS.
- Plain HTTP is accepted only for loopback development.
- The bearer token must be at least 32 characters.
- Evidence is schema-validated and capped at 1,000 records.
- The private-service response is schema-validated before it is returned.
- `diagnose_root_cause` is marked read-only and non-destructive.
- No v0.10 gateway path remediates or mutates cloud, Kubernetes, Terraform, CI/CD, tracing, or observability state.
- The public package contains no proprietary root-cause scoring engine.

## Private-core verification

The private OpsChugex v0.10 core is maintained separately from the public MIT repository.

Its verification completed with:

- 7 of 7 tests passing
- 90.58% statement coverage
- 85.71% branch coverage
- 96.15% function coverage
- 95.58% line coverage
- 0 production dependency vulnerabilities
- Private GitHub Actions CI passing

The private repository remains proprietary and is not published to npm or the MCP Registry.

## Distribution verification

The v0.10.0 release workflow completed successfully.

The workflow:

1. Verified release-version alignment.
2. Ran the repository quality gate.
3. Published `cloud-devops-mcp-server@0.10.0` to npm through OIDC.
4. Waited until the exact npm version was publicly readable.
5. Installed and verified the pinned MCP Registry publisher.
6. Authenticated to the MCP Registry through GitHub OIDC.
7. Published `io.github.alexcgodwin/cloud-devops-mcp-server` version 0.10.0.

Independent npm verification confirmed:

```json
{
  "version": "0.10.0",
  "dist-tags": {
    "latest": "0.10.0"
  }
}
```

## Final acceptance

`cloud-devops-mcp-server@0.10.0` passes repository CI, automated tests, coverage thresholds, production dependency audit, npm trusted publication, clean public installation, real MCP stdio tool discovery, an end-to-end call into the private OpsChugex intelligence core, and official MCP Registry publication.

The release establishes the intended product boundary:

```text
Public Cloud DevOps MCP
        |
        | bounded authenticated evidence contract
        v
Private OpsChugex Cloud Operations Core
        |
        v
Proprietary root-cause intelligence
```

This record supersedes the v0.9.0 public-acceptance record for the current release.
