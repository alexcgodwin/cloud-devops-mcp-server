# Public Release Acceptance

Release: `cloud-devops-mcp-server@0.13.0`
Date: 2026-10-02

This acceptance record was verified against repository CI, the publicly published npm package, a clean npm installation, a real MCP stdio client, the private OpsChugex v0.13 FinOps integration, and the official MCP Registry publication workflow.

## Release status

| Check | Result |
| --- | --- |
| GitHub release | v0.13.0 published |
| npm exact version | 0.13.0 publicly available |
| npm latest dist-tag | 0.13.0 |
| npm trusted publish | GitHub Actions OIDC with provenance |
| Clean npm install audit | 0 vulnerabilities |
| MCP Registry publication | Successfully published version 0.13.0 |
| Repository quality gate | 111 of 111 tests pass |
| Statement coverage | 85.76% |
| Branch coverage | 72.10% |
| Function coverage | 85.71% |
| Line coverage | 89.12% |
| Production dependency audit | 0 vulnerabilities |

## Clean public-install acceptance

A fresh temporary directory installed:

```powershell
npm.cmd install --ignore-scripts cloud-devops-mcp-server@0.13.0 @modelcontextprotocol/client@2.2.0
```

The clean installation completed with zero reported vulnerabilities.

A real MCP client spawned the npm-installed package over stdio and verified:

| Configuration | Tool count | Root cause | Governance | Security posture | FinOps | Result |
| --- | ---: | --- | --- | --- | --- | --- |
| Default analysis | 12 | Absent | Absent | Absent | Absent | Pass |
| v0.13 FinOps gateway | 13 | Absent | Absent | Absent | Present | Pass |
| All OpsChugex commercial gateways | 16 | Present | Present | Present | Present | Pass |
| All optional capability planes | 56 | Present | Present | Present | Present | Pass |

The default public surface remains unchanged at twelve tools.

The v0.10 root-cause, v0.11 governance, v0.12 security posture and v0.13 FinOps gateways are independently opt-in.

## v0.13 advanced FinOps acceptance

The public v0.13 package adds one optional tool:

- `analyze_advanced_finops`

The public contract accepts bounded factual evidence for:

- cloud monthly cost
- previous-period cost
- CPU and memory utilization
- storage utilization
- idle-hours evidence
- commitment eligibility and coverage
- spot/preemptible eligibility
- Kubernetes requests and p95 usage
- linked Kubernetes/cloud cost scopes
- cost-allocation tags

The private response is validated and returned as structured FinOps evidence, including:

- analyzed monthly and annual cost
- low/high monthly and annual savings ranges
- savings percentages
- ordered opportunities
- cost anomalies
- confidence and priority
- Kubernetes/cloud correlations
- portfolio savings deduplication indicators
- evidence gaps
- concise summary

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

- idle-resource thresholds
- rightsizing thresholds
- savings factors
- cost-anomaly thresholds
- commitment prioritization
- spot/preemptible prioritization
- Kubernetes over-request scoring
- confidence calculation
- portfolio savings deduplication algorithm

Those capabilities remain in the private proprietary `OpsChugex/cloud-operations-core` repository.

A public-source implementation-boundary scan searched for unique private FinOps implementation identifiers. No matches were found.

## End-to-end FinOps acceptance

A local instance of the private OpsChugex v0.13 core was started on loopback for acceptance testing.

The clean npm-installed public v0.13 MCP called `analyze_advanced_finops` through a real MCP stdio client.

The synthetic assessment supplied:

- an idle AWS EC2 workload
- a steady Azure VM with low commitment coverage
- a GCP service with a material month-over-month cost anomaly
- a Kubernetes workload with 4x CPU and memory request-to-p95 ratios
- an explicit Kubernetes-to-cloud cost link for deduplication

The end-to-end result was:

```json
{
  "organization": "OpsChugex",
  "currency": "USD",
  "analyzedMonthlyCost": 1100,
  "monthlySavingsLow": 168,
  "monthlySavingsHigh": 288,
  "opportunityCount": 5,
  "anomalyCount": 1,
  "correlationCount": 1,
  "deduplicated": true
}
```

The cost anomaly was reported separately and was not treated as assumed savings.

The linked Kubernetes workload was excluded from the portfolio savings total because its attributed cost mapped to cloud spend already represented in the assessment.

This verifies the complete public-MCP-to-private-FinOps-engine request path without publishing the private optimization implementation.

No production credentials, customer billing records or live customer infrastructure were used in this acceptance test.

## Public gateway security boundary

The v0.13 FinOps gateway is disabled by default and requires:

```text
CLOUD_DEVOPS_MCP_OPSCHUGEX_FINOPS_ENABLED=true
CLOUD_DEVOPS_MCP_OPSCHUGEX_FINOPS_URL=<host-configured endpoint>
CLOUD_DEVOPS_MCP_OPSCHUGEX_TOKEN=<host-side secret>
```

Controls verified for the public gateway include:

- The service endpoint cannot be supplied as an MCP tool argument.
- The bearer token cannot be supplied as an MCP tool argument.
- Remote endpoints must use HTTPS.
- Plain HTTP is accepted only for loopback development.
- The host token must be at least 32 characters.
- Cloud-resource evidence is capped at 5,000 records.
- Kubernetes workload evidence is capped at 5,000 records.
- The private-service response is schema-validated.
- The tool is marked read-only and non-destructive.
- The public gateway has no resize, termination, commitment-purchase, Kubernetes-mutation, storage-tier or billing-action path.

## Private-core verification

The private OpsChugex v0.13 core is maintained separately from the public MIT repository.

Its verification completed with:

- 33 of 33 tests passing
- 86.65% statement coverage
- 74.65% branch coverage
- 97.80% function coverage
- 91.34% line coverage
- 0 production dependency vulnerabilities
- private GitHub Actions CI passing

The private repository remains proprietary and is not published to npm or the MCP Registry.

## Distribution verification

The v0.13.0 release workflow completed successfully.

The workflow:

1. Verified release-version alignment.
2. Ran the repository quality gate.
3. Published `cloud-devops-mcp-server@0.13.0` to npm through GitHub Actions OIDC.
4. Waited until the exact npm version was publicly readable.
5. Installed and verified the pinned MCP Registry publisher.
6. Authenticated to the MCP Registry through GitHub OIDC.
7. Published `io.github.alexcgodwin/cloud-devops-mcp-server` version 0.13.0.

Independent npm verification confirmed:

```json
{
  "version": "0.13.0",
  "dist-tags": {
    "latest": "0.13.0"
  }
}
```

## Final acceptance

`cloud-devops-mcp-server@0.13.0` passes repository CI, automated tests, coverage thresholds, production dependency audit, npm trusted publication, clean public installation, real MCP stdio tool discovery, a real end-to-end call into the private OpsChugex FinOps engine, private/public implementation-boundary checks, and official MCP Registry publication.

The intended product boundary remains:

```text
Public Cloud DevOps MCP
        |
        | bounded authenticated evidence contract
        v
Private OpsChugex Cloud Operations Core
        |
        v
Proprietary root-cause, governance, security and FinOps intelligence
```

This record supersedes the v0.12.0 public-acceptance record for the current release.
