# Public Release Acceptance

Release: `cloud-devops-mcp-server@0.14.0`
Date: 2026-10-02

This acceptance record was verified against repository CI, the publicly published npm package, a clean npm installation, a real MCP stdio client, the private OpsChugex v0.14 change-intelligence integration, and the official MCP Registry publication workflow.

## Release status

| Check | Result |
| --- | --- |
| GitHub release | v0.14.0 published |
| npm exact version | 0.14.0 publicly available |
| npm latest dist-tag | 0.14.0 |
| npm trusted publish | GitHub Actions OIDC with provenance |
| Clean npm install audit | 0 vulnerabilities |
| MCP Registry publication | Successfully published version 0.14.0 |
| Repository quality gate | 116 of 116 tests pass |
| Statement coverage | 85.80% |
| Branch coverage | 72.18% |
| Function coverage | 85.89% |
| Line coverage | 89.11% |
| Production dependency audit | 0 vulnerabilities |

## Clean public-install acceptance

A fresh temporary directory installed:

```powershell
npm.cmd install --ignore-scripts cloud-devops-mcp-server@0.14.0 @modelcontextprotocol/client@2.2.0
```

The clean installation completed with zero reported vulnerabilities.

A real MCP client spawned the npm-installed package over stdio and verified:

| Configuration | Tool count | Root cause | Governance | Security posture | FinOps | Change intelligence | Result |
| --- | ---: | --- | --- | --- | --- | --- | --- |
| Default analysis | 12 | Absent | Absent | Absent | Absent | Absent | Pass |
| v0.14 change-intelligence gateway | 13 | Absent | Absent | Absent | Absent | Present | Pass |
| All OpsChugex commercial gateways | 17 | Present | Present | Present | Present | Present | Pass |
| All optional capability planes | 57 | Present | Present | Present | Present | Present | Pass |

The default public surface remains unchanged at twelve tools.

The v0.10 root-cause, v0.11 governance, v0.12 security posture, v0.13 FinOps and v0.14 change-intelligence gateways are independently opt-in.

## v0.14 change-intelligence acceptance

The public v0.14 package adds one optional tool:

- `analyze_change_blast_radius`

The public contract accepts bounded factual evidence for:

- Terraform, Kubernetes, CI/CD, cloud and application change items
- change targets and action type
- stateful/destructive/IAM/network/public-exposure flags
- topology nodes with environment, criticality and customer-facing metadata
- topology edges using explicit `from depends on to` semantics
- rollback, peer-review, automated-test, maintenance-window and monitoring readiness

The private response is validated and returned as structured change intelligence, including:

- deterministic change-risk score and risk level
- direct target count
- impacted topology node count
- critical and customer-facing impact counts
- affected environments
- blockers and warnings
- evidence gaps
- impacted nodes with minimum dependency depth
- representative blast paths
- recommendations and summary

## Intellectual-property boundary

The public MIT repository contains:

- MCP input and output schemas
- request bounds
- HTTPS endpoint validation
- host-side bearer-token handling
- read-only MCP registration
- response-schema validation
- documentation and gateway tests

The public MIT repository does not contain:

- reverse-dependency graph construction
- transitive blast-radius traversal
- change-action risk weights
- criticality impact weights
- readiness penalties
- production blocker rules
- blast-radius risk calculation
- approval logic

Those capabilities remain in the private proprietary `OpsChugex/cloud-operations-core` repository.

A public-source implementation-boundary scan searched for unique private change-intelligence implementation identifiers. No matches were found.

## End-to-end blast-radius acceptance

A local instance of the private OpsChugex v0.14 core was started on loopback for acceptance testing.

The clean npm-installed public v0.14 MCP called `analyze_change_blast_radius` through a real MCP stdio client.

The synthetic change replaced a stateful production orders database. The supplied dependency graph represented:

```text
aws:rds:orders
      |
      v
service:checkout
      |
      v
service:storefront
      |
      v
network:public-ingress
```

The readiness evidence deliberately omitted a valid rollback plan, automated-test confirmation and monitoring readiness.

The end-to-end result was:

```json
{
  "organization": "OpsChugex",
  "changeId": "chg-prod-db-replacement",
  "riskLevel": "critical",
  "riskScore": 100,
  "impactedNodeCount": 4,
  "criticalImpactCount": 3,
  "customerFacingImpactCount": 3,
  "blockerCount": 3,
  "ingressDepth": 3,
  "ingressPath": [
    "aws:rds:orders",
    "service:checkout",
    "service:storefront",
    "network:public-ingress"
  ]
}
```

This verifies that the npm-installed public gateway can carry bounded change/topology evidence to the private engine and return a transitive blast path without publishing the private graph or risk implementation.

No production credentials, live customer topology or live infrastructure changes were used in this acceptance test.

## Public gateway security boundary

The v0.14 change-intelligence gateway is disabled by default and requires:

```text
CLOUD_DEVOPS_MCP_OPSCHUGEX_CHANGE_INTELLIGENCE_ENABLED=true
CLOUD_DEVOPS_MCP_OPSCHUGEX_CHANGE_INTELLIGENCE_URL=<host-configured endpoint>
CLOUD_DEVOPS_MCP_OPSCHUGEX_TOKEN=<host-side secret>
```

Controls verified for the public gateway include:

- The service endpoint cannot be supplied as an MCP tool argument.
- The bearer token cannot be supplied as an MCP tool argument.
- Remote endpoints must use HTTPS.
- Plain HTTP is accepted only for loopback development.
- The host token must be at least 32 characters.
- Planned change items are capped at 1,000 records.
- Topology nodes are capped at 5,000 records.
- Topology edges are capped at 15,000 records.
- The private-service response is schema-validated.
- The tool is marked read-only and non-destructive.
- The public gateway has no Terraform apply, Kubernetes mutation, PR merge, deployment, approval or rollback path.

## Private-core verification

The private OpsChugex v0.14 core is maintained separately from the public MIT repository.

Its verification completed with:

- 44 of 44 tests passing
- 87.20% statement coverage
- 76.11% branch coverage
- 98.36% function coverage
- 92.99% line coverage
- 0 production dependency vulnerabilities
- private GitHub Actions CI passing

The private repository remains proprietary and is not published to npm or the MCP Registry.

## Distribution verification

The v0.14.0 release workflow completed successfully.

The workflow:

1. Verified release-version alignment.
2. Ran the repository quality gate.
3. Published `cloud-devops-mcp-server@0.14.0` to npm through GitHub Actions OIDC.
4. Waited until the exact npm version was publicly readable.
5. Installed and verified the pinned MCP Registry publisher.
6. Authenticated to the MCP Registry through GitHub OIDC.
7. Published `io.github.alexcgodwin/cloud-devops-mcp-server` version 0.14.0.

Independent npm verification confirmed:

```json
{
  "version": "0.14.0",
  "dist-tags": {
    "latest": "0.14.0"
  }
}
```

## Final acceptance

`cloud-devops-mcp-server@0.14.0` passes repository CI, automated tests, coverage thresholds, production dependency audit, npm trusted publication, clean public installation, real MCP stdio tool discovery, a real end-to-end call into the private OpsChugex change-intelligence engine, private/public implementation-boundary checks, and official MCP Registry publication.

The intended product boundary remains:

```text
Public Cloud DevOps MCP
        |
        | bounded authenticated evidence contract
        v
Private OpsChugex Cloud Operations Core
        |
        v
Proprietary root-cause, governance, security, FinOps and change intelligence
```

This record supersedes the v0.13.0 public-acceptance record for the current release.
