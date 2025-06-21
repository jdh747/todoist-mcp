import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js'
import express from 'express'
import { registerRoutes } from './handlers/registerRoutes.js'
import { registerTodoistTools } from './handlers/registerTodoistTools.js'

function createMCPServer() {
    const mcpServer = new McpServer({ name: 'todoist-mcp', version: '1.0.1' })
    registerTodoistTools(mcpServer)
    return mcpServer
}

function createHttpServer(createMcpServer: () => McpServer) {
    const httpServer = express()
    httpServer.use(express.json())
    registerRoutes(httpServer, createMcpServer)
    return httpServer
}

async function main() {
    const PORT = process.env.PORT ? Number.parseInt(process.env.PORT, 10) : 3000

    const httpServer = createHttpServer(createMCPServer)

    httpServer.listen(PORT, () => {
        console.log(`MCP Stateless Streamable HTTP Server listening on port ${PORT}`)
    })
}

main().catch((error) => {
    console.error('Fatal error in main():', error)
    process.exit(1)
})
