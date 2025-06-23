import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js'
import express from 'express'
import { registerRoutes } from '../handlers/register-routes.js'
import { globalErrorLog } from '../middleware/global-error-log.js'
import { jsonBodyParser } from '../middleware/json-body-parser.js'
import { logRequest } from '../middleware/log-request.js'
import { validatePostParseSize } from '../middleware/post-parse-validation.js'
import { applySecurity } from '../middleware/security/security.js'
import { urlEncodedParser } from '../middleware/url-encoded-parser.js'

export function createHttpServer(createMcpServer: () => McpServer) {
    const httpServer = express()

    // Apply security middleware first
    applySecurity(httpServer)

    // Request logging
    httpServer.use(logRequest)

    // Body parsing without size limits (handled by validatePayloadSize middleware)
    httpServer.use(jsonBodyParser)

    httpServer.use(urlEncodedParser)

    // Post-parsing payload size validation
    httpServer.use(validatePostParseSize)

    // Register routes with security
    registerRoutes(httpServer, createMcpServer)

    // Global error handler
    httpServer.use(globalErrorLog)

    return httpServer
}
