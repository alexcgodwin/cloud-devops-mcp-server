# Public Release Acceptance

Release: `cloud-devops-mcp-server@0.12.0`
Date: 2026-10-02

This acceptance record was verified against repository CI, the publicly published npm package, a clean npm installation, a real MCP stdio client, the private OpsChugex v0.12 security posture integration, and the official MCP Registry publication workflow.

## Release status

| Check | Result |
| --- | --- |
| GitHub release | v0.12.0 published |
| npm exact version | 0.12.0 publicly available |
| npm latest dist-tag | 0.12.0 |
| npm trusted publish | GitHub Actions OIDC with provenance |
| Clean npm install audit | 0 vulnerabilities |
| MCP Registry publication | Successfully published version 0.12.0 |
| Repository quality gate | 106 of 106 tests pass |
| Statement coverage | 85.71% |
| Branch coverage | 72.10% |
| Function coverage | 85.49% |
| Line coverage | 89.10% |
| Production dependency audit | 0 vulnerabilities |

## Clean public-install acceptance
A fresh temporary directory installed:

```powershell
npm.cmd install --ignore-scripts cloud-devops-mcp-server@0.12.0 @modelcontextprotocol/client@2.2.0
```

The clean installation completed with zero reported vulnerabilities.

A real MCP client spawned the npm-installed package over stdio and verified:

| Configuration | Tool count | Root cause | Governance | Security posture | Result |
| --- | ---: | --- | --- | --- | --- |
| Default analysis | 12 | Absent | Absent | Absent | Pass |
| v0.12 security gateway | 13 | Absent | Absent | Present | Pass |
| All OpsChugex commercial gateways | 15 | Present | Present | Present | Pass |
| All optional capability planes | 55 | Present | Present | Present | Pass |

The default public surface remains unchanged at twelve tools.

The v0.10 root-cause, v0.11 governance and v0.12 security posture gateways are independently opt-in.

## v0.12 cloud security posture acceptance

The public v0.12 package adds one optional tool:

- `assess_cloud_security_posture`

The public contract accepts bounded factual evidence for:
- AWS, Azure, GCP, Kubernetes and generic assets
- identities and privilege state
- secret-exposure metadata
- network reachability
- encryption and logging state
- public exposure and management-plane exposure

The private response is validated and returned as structured security evidence, including:

- security score
- risk level
- ordered findings
- critical-finding count
- correlated attack paths
- evidence gaps
- recommended next actions

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
- private security detection thresholds
- severity-weight tables
- security-score calculation rules
- attack-path graph traversal logic
- privileged-identity correlation rules
- secret-escalation rules
- remediation logic

Those capabilities remain in the private proprietary `OpsChugex/cloud-operations-core` repository.

The public gateway therefore describes what evidence may be supplied and what shape of assessment may be returned without publishing the implementation that produces the assessment.

## End-to-end security acceptance

A local instance of the private OpsChugex v0.12 core was started on loopback for acceptance testing.

The clean npm-installed public v0.12 MCP called `assess_cloud_security_posture` through a real MCP stdio client.

The synthetic test supplied:

- one internet-facing AWS application load balancer
- one sensitive AWS RDS target
- one privileged runtime IAM role
- an explicit reachable network path from the public entry point to the sensitive data asset
The end-to-end result was:

```json
{
  "organization": "OpsChugex",
  "riskLevel": "critical",
  "securityScore": 28,
  "attackPathCount": 2,
  "findingCount": 3,
  "criticalFindingCount": 0
}
```

The critical overall risk is produced by correlated attack-path evidence even though the individual findings in this synthetic case were below critical severity.

This verifies the complete public-MCP-to-private-security-engine request path without publishing the private security implementation.

No production credentials, customer data, live secrets or live customer infrastructure were used in this acceptance test.

## Public gateway security boundary

The v0.12 security gateway is disabled by default and requires:

```text
CLOUD_DEVOPS_MCP_OPSCHUGEX_SECURITY_ENABLED=true
CLOUD_DEVOPS_MCP_OPSCHUGEX_SECURITY_URL=<host-configured endpoint>
CLOUD_DEVOPS_MCP_OPSCHUGEX_TOKEN=<host-side secret>
```
Controls verified for the public gateway include:

- The service endpoint cannot be supplied as an MCP tool argument.
- The bearer token cannot be supplied as an MCP tool argument.
- Remote endpoints must use HTTPS.
- Plain HTTP is accepted only for loopback development.
- The host token must be at least 32 characters.
- Asset evidence is capped at 3,000 records.
- Identity evidence is capped at 3,000 records.
- Secret-exposure evidence is capped at 2,000 records.
- Network edges are capped at 10,000 records.
- The private-service response is schema-validated.
- The tool is marked read-only and non-destructive.
- The public gateway has no credential-rotation, IAM-mutation, network-mutation, encryption-mutation or remediation path.

## Private-core verification

The private OpsChugex v0.12 core is maintained separately from the public MIT repository.

Its verification completed with:

- 21 of 21 tests passing
- 84.53% statement coverage
- 70.43% branch coverage
- 98.43% function coverage
- 90.25% line coverage
- 0 production dependency vulnerabilities
- private GitHub Actions CI passing
The private repository remains proprietary and is not published to npm or the MCP Registry.

## Distribution verification

The v0.12.0 release workflow completed successfully.

The workflow:

1. Verified release-version alignment.
2. Ran the repository quality gate.
3. Published `cloud-devops-mcp-server@0.12.0` to npm through GitHub Actions OIDC.
4. Waited until the exact npm version was publicly readable.
5. Installed and verified the pinned MCP Registry publisher.
6. Authenticated to the MCP Registry through GitHub OIDC.
7. Published `io.github.alexcgodwin/cloud-devops-mcp-server` version 0.12.0.

Independent npm verification confirmed:

```json
{
  "version": "0.12.0",
  "dist-tags": {
    "latest": "0.12.0"
  }
}
```

## Final acceptance
`cloud-devops-mcp-server@0.12.0` passes repository CI, automated tests, coverage thresholds, production dependency audit, npm trusted publication, clean public installation, real MCP stdio tool discovery, a real end-to-end call into the private OpsChugex security posture engine, and official MCP Registry publication.

The intended product boundary remains:

```text
Public Cloud DevOps MCP
        |
        | bounded authenticated evidence contract
        v
Private OpsChugex Cloud Operations Core
        |
        v
Proprietary root-cause, governance and security intelligence
```

This record supersedes the v0.11.0 public-acceptance record for the current release.
