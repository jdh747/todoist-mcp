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

    // CORS Settings
    ALLOWED_ORIGINS: process.env.ALLOWED_ORIGINS?.split(',') || ['http://localhost:3001'],

    // Security Headers
    ENABLE_HELMET: process.env.ENABLE_HELMET !== 'false',

    // Port to bind the http server to
    PORT: Number.parseInt(process.env.PORT || '3000'),

    // Environment
    NODE_ENV: process.env.NODE_ENV || 'development',

    // Todoist API
    TODOIST_API_KEY: process.env.TODOIST_API_KEY || '',

    // Logging
    LOG_LEVEL: process.env.LOG_LEVEL || 'info',

    // Request timeout (30 seconds)
    REQUEST_TIMEOUT_MS: Number.parseInt(process.env.REQUEST_TIMEOUT_MS || '30000'),

    // Max request body size
    MAX_REQUEST_SIZE: process.env.MAX_REQUEST_SIZE || '10mb',
} as const

// Validate required environment variables on startup
export function validateSecurityConfig() {
    // Require JWT_SECRET and TODOIST_API_KEY
    const requiredVars = ['JWT_SECRET', 'TODOIST_API_KEY']
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
}
