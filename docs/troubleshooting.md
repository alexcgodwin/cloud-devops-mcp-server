# Troubleshooting

## The MCP client cannot start the server

Test the published package directly:

```bash
npx -y cloud-devops-mcp-server@0.2.1
```

On Windows PowerShell systems where script execution policy blocks `npx.ps1`, use:

```powershell
npx.cmd -y cloud-devops-mcp-server@0.2.1
```

A successfully started stdio MCP server waits for protocol messages; it is normal for it to remain running without printing interactive prompts.

## PowerShell says running scripts is disabled

Do not change the machine execution policy just to run this package. Use the Windows command shim instead:

```powershell
npm.cmd --version
npx.cmd -y cloud-devops-mcp-server@0.2.1
```

## The client cannot resolve npx

Install the package globally:

```bash
npm install -g cloud-devops-mcp-server@0.2.1
```

Then set the MCP client command to:

```text
cloud-devops-mcp-server
```

## Source-development path does not exist

For source development only, run `npm run build` and point the client to the generated `dist/index.js` using an absolute path.

## Credentials

The current advisory server does not require AWS, Azure, GitHub or Kubernetes credentials. Do not add tokens or cloud credentials to its configuration.
