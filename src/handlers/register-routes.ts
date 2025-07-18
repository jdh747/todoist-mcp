import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js'
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js'
import type { Express, Request, Response } from 'express'
import { authenticate } from '../middleware/auth.js'
import { authorizeUser } from '../middleware/authorize-user.js'
import { sanitizeInput } from '../middleware/sanitize-input.js'
import { validateMCPRequest } from '../middleware/validate-mcp-request.js'
import { logger } from '../utils/logger.js'
import { sendMethodNotAllowedError } from '../utils/security-responses.js'

export function registerRoutes(httpServer: Express, createMcpServer: () => McpServer) {
    // Add authentication, authorization, and validation middleware to the MCP endpoint
    httpServer.post(
        '/mcp',
        authenticate,
        authorizeUser,
        validateMCPRequest,
        sanitizeInput,
        handlePost,
    )
    httpServer.get('/mcp', handleGet)
    httpServer.delete('/mcp', handleDelete)

    async function handlePost(req: Request, res: Response): Promise<void> {
        logger.info('Received authenticated MCP request', {
            method: req.mcpAuth?.method,
            identifier: req.mcpAuth?.identifier,
            ip: req.ip,
        })

        // In stateless mode, create a new instance of transport and server for each request
        // to ensure complete isolation. A single instance would cause request ID collisions
        // when multiple clients connect concurrently.
        const mcpServer = createMcpServer()
        const transport: StreamableHTTPServerTransport = new StreamableHTTPServerTransport({
            sessionIdGenerator: undefined,
        })

        res.on('close', () => {
            logger.info('Request closed')
            transport.close()
            mcpServer.close()
        })

        await mcpServer.connect(transport)
        await transport.handleRequest(req, res, req.body)
    }

    async function handleGet(_req: Request, res: Response): Promise<void> {
        logger.warn('Received GET request on MCP endpoint - method not allowed')
        sendMethodNotAllowedError(res)
    }

    async function handleDelete(_req: Request, res: Response): Promise<void> {
        logger.warn('Received DELETE request on MCP endpoint - method not allowed')
        sendMethodNotAllowedError(res)
    }
}
