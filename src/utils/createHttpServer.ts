import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js'
import express from 'express'
import { SECURITY_CONFIG } from '../config/security.js'
import { registerRoutes } from '../handlers/registerRoutes.js'
import { globalErrorLog } from '../middleware/globalErrorLog.js'
import { applySecurity } from '../middleware/security.js'
import { logRequest } from './logger.js'

export function createHttpServer(createMcpServer: () => McpServer) {
    const httpServer = express()

    // Apply security middleware first
    applySecurity(httpServer)

    // Request logging
    httpServer.use(logRequest)

    // Body parsing with size limits
    httpServer.use(
        express.json({
            limit: SECURITY_CONFIG.MAX_REQUEST_SIZE,
            strict: true,
        }),
    )

    httpServer.use(
        express.urlencoded({
            extended: false,
            limit: SECURITY_CONFIG.MAX_REQUEST_SIZE,
        }),
    )

    // Register routes with security
    registerRoutes(httpServer, createMcpServer)

    // Global error handler
    httpServer.use(globalErrorLog)

    return httpServer
}
