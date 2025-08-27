# Todoist MCP

<!-- TODO: redo auth tests and write extensive tests generally -->
<!-- TODO: global review & feedback  -->
<!-- TODO: token refresh functionality -->
<!-- TODO: integrate MCP auth spec with todoist oauth api? docs: https://modelcontextprotocol.io/specification/draft/basic/authorization -->

_Note: predictably obsoleted by Todoist AI SDK, see [here](https://github.com/Doist/todoist-ai)._

---

Connect this [Model Context Protocol](https://modelcontextprotocol.io/introduction) server to your LLM to interact with Todoist.

## Functionality

This integration implements all the APIs available from the [Todoist TypeScript Client](https://doist.github.io/todoist-api-typescript/api/classes/TodoistApi/), providing access to:

### Task Management

- Create tasks (with content, descriptions, due dates, priorities, labels, and more)
- Create tasks with natural language (e.g., "Submit report by Friday 5pm #Work")
- Retrieve tasks (individual, filtered, or all tasks)
- Retrieve completed tasks (by completion date or due date)
- Get productivity statistics
- Update tasks
- Move tasks (individually or in batches)
- Close/reopen tasks
- Delete tasks

### Project Management

- Create, retrieve, update, and delete projects

### Section Management

- Create, retrieve, update, and delete sections within projects

### Comment Management

- Add, retrieve, update, and delete comments for tasks or projects

### Label Management

- Create, retrieve, update, and delete labels
- Manage shared labels

### Collaboration

- Get collaborators for projects

## Setup

**Build the server app:**

```
bun install
bun run build
```

**Run in development**

```
TODOIST_API_KEY=<key> bun dev
```

**Docker deployment:**

```
docker compose up -d
```

**Debugging:**

Use the inspector to debug the server:

```

bunx @modelcontextprotocol/inspector
```

**Configure Claude:**

You must install the [Claude](https://claude.ai/) desktop app which supports MCP.

You can get your Todoist API key from [Todoist > Settings > Integrations > Developer](https://app.todoist.com/app/settings/integrations/developer).

Then, in your `claude_desktop_config.json`, add a new MCP server:

```
{
    "mcpServers": {
        "default-server": {
            "type": "streamable-http",
            "url": "http://localhost:3000/mcp",
            "note": "For Streamable HTTP connections, add this URL directly in your MCP Client"
        }
    }
}
```

You can now launch Claude desktop app and ask to update Todoist.

## 🔐 Security Features

**This MCP server has been secured with enterprise-grade security measures:**

- **Authentication Required**: JWT Bearer tokens or API key authentication
- **Rate Limiting**: Prevents abuse with configurable limits
- **Input Validation**: Comprehensive request validation and sanitization
- **Security Headers**: CORS, CSP, HSTS, and other security headers
- **Logging & Monitoring**: Security event logging and request monitoring
- **Environment Configuration**: Secure configuration via environment variables

**See [SECURITY.md](./SECURITY.md) for detailed security documentation.**

## Quick Security Setup

1. **Generate secure tokens:**

   ```bash
   npm run setup-security
   ```

2. **Create `.env` file:**

   ```bash
   cp .env.example .env
   # Add your generated tokens and Todoist API key
   ```

3. **Required Environment Variables:**

   ```env
   JWT_SECRET=your_generated_jwt_secret_here
   TODOIST_API_KEY=your_todoist_api_key_here
   ```

## Authentication

The server supports two authentication methods:

### Method 1: API Key (Recommended for scripts)

```bash
curl -X POST http://localhost:3000/mcp \
  -H "X-API-Key: YOUR_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc": "2.0", "method": "tools/list", "id": 1}'
```

### Method 2: JWT Bearer Token (Recommended for applications)

```bash
curl -X POST http://localhost:3000/mcp \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc": "2.0", "method": "tools/list", "id": 1}'
```
