import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js'
import { registerTodoistTools } from '../handlers/register-todoist-tools.js'

export function createMCPServer() {
    const mcpServer = new McpServer({ name: 'todoist-mcp', version: '1.0.1' })
    registerTodoistTools(mcpServer)
    return mcpServer
}
