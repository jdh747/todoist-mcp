import { SECURITY_CONFIG, validateSecurityConfig } from './config/security.js'
import { validateOAuthConfig } from './config/oauth.js'
import { registerSignalHandlers } from './handlers/register-signal-handlers.js'
import { createMCPServer } from './utils/create-mcp-server.js'
import { createHttpServer } from './utils/createHttpServer.js'
import { logger } from './utils/logger.js'

async function main() {
    try {
        validateSecurityConfig()
        validateOAuthConfig()
        logger.info('OAuth 2.1 configuration validated successfully')
    } catch (error) {
        logger.error('Configuration validation failed:', error)
        process.exit(1)
    }

    logger.info('Starting Todoist MCP Server with OAuth 2.1', {
        port: SECURITY_CONFIG.PORT,
        nodeEnv: SECURITY_CONFIG.NODE_ENV,
        securityEnabled: true,
        authMode: 'OAuth 2.1',
    })

    const httpServer = createHttpServer(createMCPServer)

    const server = httpServer.listen(SECURITY_CONFIG.PORT, () => {
        logger.info(`🔐 OAuth 2.1 MCP Server listening on port ${SECURITY_CONFIG.PORT}`, {
            authMethods: ['OAuth 2.1 Bearer Token'],
            corsOrigins: SECURITY_CONFIG.ALLOWED_ORIGINS,
            rateLimiting: `${SECURITY_CONFIG.RATE_LIMIT_MAX_REQUESTS} requests per ${SECURITY_CONFIG.RATE_LIMIT_WINDOW_MS / 1000 / 60} minutes`,
            todoistIntegration: 'Per-user OAuth tokens',
        })

        if (SECURITY_CONFIG.NODE_ENV === 'development') {
            logger.warn('⚠️  Running in development mode. Ensure proper security in production!')
        }
    })

    registerSignalHandlers(server)
}

main().catch((error) => {
    console.error('Fatal error in main():', error)
    process.exit(1)
})
