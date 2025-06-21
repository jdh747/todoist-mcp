# Todoist MCP

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
