import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js'
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js'
import type { Express, Request, Response } from 'express'
import { authenticateOAuth } from '../middleware/oauth-auth.js'
import { authorizeOAuthUser } from '../middleware/oauth-authorize-user.js'
import { sanitizeInput } from '../middleware/sanitize-input.js'
import { validateMCPRequest } from '../middleware/validate-mcp-request.js'
import { logger } from '../utils/logger.js'
import { sendMethodNotAllowedError } from '../utils/security-responses.js'
import { setCurrentRequest } from '../utils/mcp-tool-context.js'
import { handleProtectedResourceMetadata, handleAuthorizationServerMetadata } from './oauth-metadata.js'
import { 
    handleTodoistConnect, 
    handleTodoistCallback, 
    handleTodoistDisconnect, 
    handleTodoistStatus 
} from './todoist-oauth.js'

export function registerRoutes(httpServer: Express, createMcpServer: () => McpServer) {
    // OAuth 2.0 Protected Resource Metadata endpoints (RFC 9728)
    httpServer.get('/.well-known/oauth-protected-resource', handleProtectedResourceMetadata)
    httpServer.get('/.well-known/oauth-authorization-server', handleAuthorizationServerMetadata)

    // Todoist OAuth integration endpoints
    httpServer.get('/auth/todoist/connect', authenticateOAuth, handleTodoistConnect)
    httpServer.get('/auth/todoist/callback', handleTodoistCallback)
    httpServer.post('/auth/todoist/disconnect', authenticateOAuth, handleTodoistDisconnect)
    httpServer.get('/auth/todoist/status', authenticateOAuth, handleTodoistStatus)

    // Add OAuth authentication, authorization, and validation middleware to the MCP endpoint
    httpServer.post(
        '/mcp',
        authenticateOAuth,
        authorizeOAuthUser,
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
            todoistUserId: req.todoistAuth?.todoistUserId,
            ip: req.ip,
        })

        // Set request context for MCP tools to access
        setCurrentRequest(req)

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
