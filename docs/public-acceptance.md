# Public Release Acceptance

Release: `cloud-devops-mcp-server@0.6.0`  
Date: 2026-10-01

This acceptance record was verified against the publicly published npm package and the official MCP Registry, not only the repository source checkout.

## Release status

| Check | Result |
| --- | --- |
| GitHub release | v0.6.0 published |
| npm latest | 0.6.0 |
| npm exact version | 0.6.0 available |
| npm trusted publish | GitHub Actions OIDC |
| npm dependency audit in clean install | 0 vulnerabilities |
| MCP Registry schema validation | Pass |
| MCP Registry publication | GitHub Actions OIDC |
| MCP Registry status | Active |
| MCP Registry latest | 0.6.0 |
| Repository quality gate | 49 of 49 tests pass |
| Statement coverage | 83.03% |
| Branch coverage | 71.23% |
| Function coverage | 85.42% |
| Line coverage | 86.64% |
| Production dependency audit | 0 vulnerabilities |

## Clean public-install acceptance

A fresh temporary directory installed:

```powershell
npm.cmd install --ignore-scripts cloud-devops-mcp-server@0.6.0 @modelcontextprotocol/client@2.2.0
```

The clean installation completed with zero reported vulnerabilities. A real MCP client then spawned the installed package over stdio and verified the following tool surfaces:

| Configuration | Tool count | Result |
| --- | ---: | --- |
| Default | 12 | Pass |
| Controlled Git/GitHub execution enabled | 22 | Pass |
| Terraform/Kubernetes infrastructure operations enabled | 18 | Pass |
| Both optional operational planes enabled | 28 | Pass |

The default remains the twelve evidence-backed analysis tools. Operational tools are not exposed unless their explicit environment gates are enabled.

## Controlled Git/GitHub execution acceptance

The npm-installed package was started with controlled execution enabled and the temporary test repository explicitly allowlisted.

A real `git_status` MCP call completed successfully and returned the expected `main` branch. The v0.5/v0.6 automated test suite also verifies:

- Repository allowlisting.
- Protected-branch blocking.
- Fast-forward-only pull.
- No force-push path.
- Selected-file commit staging.
- Push dry-run support.
- GitHub pull-request creation and check inspection.
- Passing-CI requirement before merge.
- Exact confirmation strings for merge and workflow dispatch.
- GitHub repository and workflow allowlists.
- Audit logging and secret redaction.

## Terraform operations acceptance

The optional infrastructure plane adds:

- `terraform_fmt_check`
- `terraform_validate`
- `terraform_plan_summary`

Acceptance tests verify that formatting runs in check-only mode, validation returns bounded JSON diagnostics, and plan execution returns only summarized action counts.

The plan path uses `-input=false`, `-lock=false`, `-refresh=false` and a temporary plan artifact. No `terraform apply`, destroy, import or state-mutation tool is exposed. Var-files must resolve within the allowlisted working directory.

## Kubernetes runtime-read acceptance

The optional infrastructure plane also adds:

- `kubectl_current_context`
- `kubectl_get_resources`
- `kubectl_rollout_status`

Acceptance tests verify context, namespace and resource allowlists; bounded metadata/status output; rollout checks with `--watch=false`; and rejection of unapproved contexts, namespaces and Secret resource retrieval.

The server does not expose Kubernetes apply, create, patch, edit, delete, exec, cp or port-forward tools.

## Distribution and registry acceptance

The release workflow:

1. Runs the full quality gate.
2. Publishes npm through GitHub Actions OIDC with provenance.
3. Waits until the exact npm version is publicly visible.
4. Downloads the pinned MCP Registry publisher v1.8.1.
5. Verifies its SHA-256 digest before execution.
6. Validates `server.json`.
7. Authenticates to the MCP Registry with GitHub OIDC.
8. Publishes the same release metadata to the official MCP Registry.

The official registry currently reports:

- Name: `io.github.alexcgodwin/cloud-devops-mcp-server`
- Status: active
- Latest version: `0.6.0`
- npm package: `cloud-devops-mcp-server@0.6.0`
- Default transport: stdio

## Security boundary

The v0.6 release deliberately keeps operational capability narrow:

- No generic shell execution tool.
- No force-push.
- No direct protected-branch commit/push.
- No Terraform apply or destroy.
- No Kubernetes mutation.
- Kubernetes Secrets are excluded from the default resource allowlist.
- Repositories, branches/remotes, GitHub repositories/workflows, Kubernetes contexts/namespaces/resources and Terraform working paths are constrained before command execution.
- Default analysis remains read-only and requires no cloud-provider credentials.

This record supersedes the v0.4 public-acceptance record for the current release.
