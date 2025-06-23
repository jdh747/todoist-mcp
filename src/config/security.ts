import dotenv from 'dotenv'

// Load environment variables
dotenv.config()

export const SECURITY_CONFIG = {
    // JWT Settings
    JWT_SECRET: process.env.JWT_SECRET || '',
    JWT_EXPIRES_IN: process.env.JWT_EXPIRES_IN || '24h',

    // Rate Limiting
    RATE_LIMIT_WINDOW_MS: Number.parseInt(process.env.RATE_LIMIT_WINDOW_MS || '900000'), // 15 minutes
    RATE_LIMIT_MAX_REQUESTS: Number.parseInt(process.env.RATE_LIMIT_MAX_REQUESTS || '100'),

    // Rate limit failed login attempts
    FAILED_LOGIN_RATE_LIMIT_WINDOW_MS: Number.parseInt(
        process.env.FAILED_LOGIN_RATE_LIMIT_WINDOW_MS || '300000',
    ),
    FAILED_LOGIN_RATE_LIMIT_MAX_REQUESTS: Number.parseInt(
        process.env.FAILED_LOGIN_RATE_LIMIT_MAX_REQUESTS || '5',
    ), // 5 minutes

    // CORS Settings: MCP Inspector(6274)
    ALLOWED_ORIGINS: process.env.ALLOWED_ORIGINS?.split(',') || ['http://localhost:6274'],

    // Security Headers
    ENABLE_HELMET: process.env.ENABLE_HELMET !== 'false',

    // Port to bind the http server to
    PORT: Number.parseInt(process.env.PORT || '3000'),

    // Environment
    NODE_ENV: process.env.NODE_ENV || 'development',

    // Todoist API
    TODOIST_API_KEY: process.env.TODOIST_API_KEY || '',

    // User Authorization
    ALLOWED_USER_ID: process.env.ALLOWED_USER_ID || '',

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
    // Require JWT_SECRET, TODOIST_API_KEY, and ALLOWED_USER_ID
    const requiredVars = ['JWT_SECRET', 'TODOIST_API_KEY', 'ALLOWED_USER_ID']
    const missing = requiredVars.filter(
        (varName) => !process.env[varName] || process.env[varName]?.trim() === '',
    )

    if (missing.length > 0) {
        throw new Error(`Missing required environment variables: ${missing.join(', ')}`)
    }

    // Validate JWT secret strength
    if (SECURITY_CONFIG.JWT_SECRET.length < 32) {
        throw new Error('JWT_SECRET must be at least 32 characters long')
    }

    // Validate user ID is not empty
    if (SECURITY_CONFIG.ALLOWED_USER_ID.trim() === '') {
        throw new Error('ALLOWED_USER_ID cannot be empty')
    }
}
