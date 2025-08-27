import dotenv from 'dotenv'

// Load environment variables
dotenv.config()

export const SECURITY_CONFIG = {
    // Rate Limiting
    RATE_LIMIT_WINDOW_MS: Number.parseInt(process.env.RATE_LIMIT_WINDOW_MS || '900000'), // 15 minutes
    RATE_LIMIT_MAX_REQUESTS: Number.parseInt(process.env.RATE_LIMIT_MAX_REQUESTS || '100'),

    // Rate limit failed auth attempts
    FAILED_AUTH_RATE_LIMIT_WINDOW_MS: Number.parseInt(
        process.env.FAILED_AUTH_RATE_LIMIT_WINDOW_MS || '300000',
    ),
    FAILED_AUTH_RATE_LIMIT_MAX_REQUESTS: Number.parseInt(
        process.env.FAILED_AUTH_RATE_LIMIT_MAX_REQUESTS || '5',
    ), // 5 minutes

    // CORS Settings: MCP Inspector(6274)
    ALLOWED_ORIGINS: process.env.ALLOWED_ORIGINS?.split(',') || ['http://localhost:6274'],

    // Security Headers
    ENABLE_HELMET: process.env.ENABLE_HELMET !== 'false',

    // Port to bind the http server to
    PORT: Number.parseInt(process.env.PORT || '3000'),

    // Environment
    NODE_ENV: process.env.NODE_ENV || 'development',

    // Logging
    LOG_LEVEL: process.env.LOG_LEVEL || 'info',

    // Request timeout (30 seconds)
    REQUEST_TIMEOUT_MS: Number.parseInt(process.env.REQUEST_TIMEOUT_MS || '30000'),

    // Max request body size
    MAX_REQUEST_SIZE: process.env.MAX_REQUEST_SIZE || '10mb',

    // Max request payload size (50KB)
    MAX_REQUEST_PAYLOAD_SIZE: Number.parseInt(process.env.MAX_REQUEST_PAYLOAD_SIZE || '50000'),
} as const

// Validate required environment variables on startup
export function validateSecurityConfig() {
    // OAuth configuration is validated by the oauth module
    // Basic security validation only
    console.log('OAuth 2.1 mode: Security configuration using OAuth instead of JWT')
}
