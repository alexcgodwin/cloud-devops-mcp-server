# Contributing

Contributions are welcome when they improve correctness, safety or Cloud DevOps usefulness.

## Local setup

```bash
npm install
npm run build
npm test
```

## Guidelines

- Keep tool inputs structured and explicit.
- Keep outputs practical, reviewable and concise.
- Do not add cloud write actions without a clear safety design.
- Add tests for scoring or decision logic changes.
- Avoid storing credentials, tokens or account identifiers in examples.
