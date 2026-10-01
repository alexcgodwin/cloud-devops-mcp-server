# Troubleshooting

## The MCP client cannot start the server

Test the published package directly:

```bash
npx -y cloud-devops-mcp-server@0.4.0
```

On Windows PowerShell systems where script execution policy blocks `npx.ps1`, use:

```powershell
npx.cmd -y cloud-devops-mcp-server@0.4.0
```

A successfully started stdio MCP server waits for protocol messages; it is normal for it to remain running without printing interactive prompts.

## PowerShell says running scripts is disabled

Do not change the machine execution policy just to run this package. Use the Windows command shim instead:

```powershell
npm.cmd --version
npx.cmd -y cloud-devops-mcp-server@0.4.0
```

## The client cannot resolve npx

Install the package globally:

```bash
npm install -g cloud-devops-mcp-server@0.4.0
```

Then set the MCP client command to:

```text
cloud-devops-mcp-server
```

## HTTP mode refuses to start

HTTP mode requires a bearer token with at least 32 characters:

```text
CLOUD_DEVOPS_MCP_BEARER_TOKEN=<strong random token>
```

For a non-local bind, also set:

```text
CLOUD_DEVOPS_MCP_ALLOWED_HOSTS=mcp.example.com
CLOUD_DEVOPS_MCP_PUBLIC_BASE_URL=https://mcp.example.com
```

If `CLOUD_DEVOPS_MCP_PUBLIC_BASE_URL` is plain HTTP, the process intentionally refuses to start. Use TLS termination at a reverse proxy or gateway.

## HTTP client receives 401

Confirm the client sends:

```text
Authorization: Bearer <same token configured on the server>
```

The comparison is exact. Whitespace inside the token changes its value.

## HTTP client receives 403

A `403` before MCP handling usually indicates Host or Origin validation. Confirm the request hostname is present in `CLOUD_DEVOPS_MCP_ALLOWED_HOSTS`, and browser-originated clients are included in `CLOUD_DEVOPS_MCP_ALLOWED_ORIGINS`.

## Source-development path does not exist

For source development only, run `npm run build` and point the client to the generated `dist/index.js` using an absolute path.

## Credentials

The advisory analysis tools do not require AWS, Azure, GCP, GitHub or Kubernetes credentials. The only secret used by the current server is the optional HTTP bearer token.
