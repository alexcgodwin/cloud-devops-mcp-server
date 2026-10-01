# Release

## Checklist

1. Update `CHANGELOG.md`.
2. Keep the version aligned in `package.json`, `package-lock.json`, `server.json` and `manifest.json`.
3. Run the full quality gate:

```bash
npm ci
npm run check
```

4. Confirm the MCP contract test lists all registered tools and validates structured output.
5. Confirm authenticated Streamable HTTP integration tests pass when the release changes transport code.
6. Confirm CI uses immutable action SHAs and least-privilege token permissions.
7. Commit the release changes through a protected pull request and wait for CI.
8. Create the GitHub release from the reviewed `main` commit. The release event triggers trusted npm publishing through GitHub Actions OIDC.
9. Verify the npm version, `latest` dist-tag and SLSA provenance after registry processing.
10. Validate and publish `server.json` to the MCP Registry.
11. Run a clean public-install acceptance test against the published npm package.

## Versioning

This project uses semantic versioning:

- Patch: bug fixes and documentation improvements.
- Minor: new backward-compatible tools, parsers or output fields.
- Major: breaking schema or behavior changes.
