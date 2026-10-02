# Public Release Acceptance

Release: `cloud-devops-mcp-server@0.11.0`
Date: 2026-10-02

This acceptance record was verified against repository CI, the publicly published npm package, a clean npm installation, a real MCP stdio client, the private OpsChugex v0.11 governance integration, and the official MCP Registry publication workflow.

## Release status

| Check | Result |
| --- | --- |
| GitHub release | v0.11.0 published |
| npm exact version | 0.11.0 publicly available |
| npm latest dist-tag | 0.11.0 |
| npm trusted publish | GitHub Actions OIDC with provenance |
| Clean npm install audit | 0 vulnerabilities |
| MCP Registry publication | Successfully published version 0.11.0 |
| Repository quality gate | 101 of 101 tests pass |
| Statement coverage | 85.68% |
| Branch coverage | 72.02% |
| Function coverage | 85.30% |
| Line coverage | 89.08% |
| Production dependency audit | 0 vulnerabilities |

## Clean public-install acceptance

A fresh temporary directory installed:
```powershell
npm.cmd install --ignore-scripts cloud-devops-mcp-server@0.11.0 @modelcontextprotocol/client@2.2.0
```

The clean installation completed with zero reported vulnerabilities.

A real MCP client spawned the npm-installed package over stdio and verified:

| Configuration | Tool count | Root cause | Governance | Result |
| --- | ---: | --- | --- | --- |
| Default analysis | 12 | Absent | Absent | Pass |
| v0.10 root-cause gateway | 13 | Present | Absent | Pass |
| v0.11 governance gateway | 13 | Absent | Present | Pass |
| Both OpsChugex gateways | 14 | Present | Present | Pass |
| Observability + tracing | 30 | Absent | Absent | Pass |
| All optional capability planes | 54 | Present | Present | Pass |

The default public surface remains unchanged at twelve tools.

The v0.10 and v0.11 OpsChugex gateways are independently opt-in.

## v0.11 policy and governance acceptance

The public v0.11 package adds one optional tool:

- `assess_governance_policy`

The public contract accepts bounded resource evidence for AWS, Azure, GCP, Kubernetes and generic resources.
Callers may select a development, staging, production or regulated profile and may provide owner-attributed, time-bounded exception metadata.

The public package returns the private service response as structured governance evidence, including:

- `pass`, `review`, or `block`
- governance score
- control findings
- severity
- exception-applied state
- evidence gaps
- expired exception identifiers
- concise assessment summary

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

- governance profile rule tables
- control thresholds
- scoring weights
- control-to-severity mapping logic
- exception-evaluation algorithms
- policy enforcement or remediation logic
Those capabilities remain in the private proprietary `OpsChugex/cloud-operations-core` repository.

A public-source leak check searched for private implementation identifiers including the private profile table, severity weights, required-tag rules, exception evaluator, and specific private control-rule identifiers. No matches were found.

## End-to-end governance acceptance

A local instance of the private OpsChugex v0.11 core was started on loopback for acceptance testing.

The clean npm-installed public v0.11 MCP called `assess_governance_policy` through a real MCP stdio client.

The synthetic test supplied one production application-load-balancer resource with complete evidence except that public exposure was enabled.

The end-to-end result was:

```json
{
  "organization": "OpsChugex",
  "profile": "production",
  "decision": "block",
  "score": 84,
  "findingCount": 1,
  "blockedFindingCount": 1,
  "topControl": "network.public_exposure",
  "topSeverity": "high",
  "evidenceGaps": 0
}
```

This verifies the complete public-MCP-to-private-policy-engine request path without publishing the private governance implementation.
No production credentials, customer data or live customer infrastructure were used in this acceptance test.

## Public gateway security boundary

The v0.11 governance gateway is disabled by default and requires:

```text
CLOUD_DEVOPS_MCP_OPSCHUGEX_GOVERNANCE_ENABLED=true
CLOUD_DEVOPS_MCP_OPSCHUGEX_GOVERNANCE_URL=<host-configured endpoint>
CLOUD_DEVOPS_MCP_OPSCHUGEX_TOKEN=<host-side secret>
```

Controls verified include:

- The governance endpoint cannot be supplied as an MCP argument.
- The bearer token cannot be supplied as an MCP argument.
- Remote endpoints must use HTTPS.
- Plain HTTP is accepted only for loopback development.
- The bearer token must be at least 32 characters.
- Resource evidence is capped at 2,000 records.
- Governance exceptions are capped at 500 records.
- The private-service response is schema-validated.
- The tool is marked read-only and non-destructive.
- No policy enforcement or infrastructure mutation is exposed.

## Private-core verification

The private OpsChugex v0.11 core remains private and proprietary.
Its v0.11 verification completed with:

- 14 of 14 tests passing
- 86.62% statement coverage
- 77.16% branch coverage
- 97.43% function coverage
- 91.83% line coverage
- 0 production dependency vulnerabilities
- private pull-request CI passing
- private post-merge CI passing

The private repository is not published to npm or the MCP Registry.

## Distribution verification

The v0.11.0 release workflow completed successfully.

The workflow:

1. Verified release-version alignment.
2. Ran the repository quality gate.
3. Published `cloud-devops-mcp-server@0.11.0` to npm through OIDC.
4. Waited until the exact npm version was publicly readable.
5. Installed and verified the pinned MCP Registry publisher.
6. Authenticated to the MCP Registry through GitHub OIDC.
7. Published `io.github.alexcgodwin/cloud-devops-mcp-server` version 0.11.0.

Independent npm verification confirmed `0.11.0` as the `latest` dist-tag.
## Final acceptance

`cloud-devops-mcp-server@0.11.0` passes repository CI, automated tests, coverage thresholds, production dependency audit, npm trusted publication, clean public installation, real MCP stdio discovery, an end-to-end call into the private OpsChugex governance engine, IP-boundary checks, and official MCP Registry publication.

The architecture now has two commercial gateways while keeping the product intelligence private:

```text
Public Cloud DevOps MCP
        |
        +--> private root-cause API
        |
        +--> private governance API
                    |
                    v
        OpsChugex Cloud Operations Core
        proprietary intelligence
```

This record supersedes the v0.10.0 public-acceptance record for the current release.
