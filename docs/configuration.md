# Configuration

Cloud DevOps MCP Server currently runs as a local stdio MCP server.

## Build first

```bash
npm install
npm run build
```

## Generic MCP client

```json
{
  "mcpServers": {
    "cloud-devops": {
      "command": "node",
      "args": ["/absolute/path/to/cloud-devops-mcp-server/dist/index.js"]
    }
  }
}
```

## Windows local path example

```json
{
  "mcpServers": {
    "cloud-devops": {
      "command": "node",
      "args": [
        "C:\\Users\\Owner\\Downloads\\cloud-devops-mcp-server-bootstrap\\dist\\index.js"
      ]
    }
  }
}
```

## GitHub MCP side-by-side

If you want GitHub tools available in the same client, add a separate GitHub MCP server next to this server. Do not paste tokens into chat or commit them to git.

```json
{
  "mcpServers": {
    "cloud-devops": {
      "command": "node",
      "args": [
        "C:\\Users\\Owner\\Downloads\\cloud-devops-mcp-server-bootstrap\\dist\\index.js"
      ]
    },
    "github": {
      "command": "github-mcp-server",
      "env": {
        "GITHUB_TOKEN": "PASTE_YOUR_TOKEN_HERE_LOCALLY_ONLY"
      }
    }
  }
}
```

## Important client note

ChatGPT in Chrome does not read this local JSON file from your laptop. Use Cursor, Claude Desktop, VS Code or another MCP client for local stdio servers.
