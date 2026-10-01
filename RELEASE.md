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
5. Confirm CI uses immutable action SHAs and least-privilege token permissions.
6. Commit the release changes and create a GitHub release from the reviewed commit.
7. Publish the npm package before adding an npm `packages` entry to `server.json`.
8. After package publication, validate and publish `server.json` to the MCP Registry.

## Versioning

This project uses semantic versioning:

- Patch: bug fixes and documentation improvements.
- Minor: new backward-compatible tools, parsers or output fields.
- Major: breaking schema or behavior changes.
