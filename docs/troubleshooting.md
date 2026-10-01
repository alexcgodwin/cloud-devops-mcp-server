# Troubleshooting

## The MCP client cannot start the server

Run the server directly:

```bash
node dist/index.js
```

If `dist/index.js` does not exist, build the project:

```bash
npm run build
```

## The client says the path does not exist

Use an absolute path to `dist/index.js`. On Windows, escape backslashes in JSON:

```json
"C:\\Users\\Owner\\Downloads\\cloud-devops-mcp-server-bootstrap\\dist\\index.js"
```

## The GitHub token does not work

Keep GitHub as a separate MCP server and use a fine-grained token with the smallest required access. For read-only testing, start with repository metadata, contents, pull requests and actions as read-only.

Never paste the token into chat and never commit it to git.
