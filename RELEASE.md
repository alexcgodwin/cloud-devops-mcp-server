# Release

## Checklist

1. Update `CHANGELOG.md`.
2. Update the version in `package.json`, `server.json` and `manifest.json`.
3. Run checks.

```bash
npm run check
```

4. Commit the release changes.
5. Create a GitHub release with a short summary and changelog notes.

## Versioning

This project uses semantic versioning:

- Patch: bug fixes and documentation improvements.
- Minor: new backward-compatible tools or output fields.
- Major: breaking schema or behavior changes.
