import dotenv from 'dotenv'

// Load environment variables
dotenv.config()

export const OAUTH_CONFIG = {
    // OAuth 2.1 Resource Server Configuration
    AUTHORIZATION_SERVER_URL: process.env.OAUTH_AUTHORIZATION_SERVER_URL || '',
    AUDIENCE: process.env.OAUTH_AUDIENCE || '',
    INTROSPECTION_ENDPOINT: process.env.OAUTH_INTROSPECTION_ENDPOINT || '',
    CLIENT_ID: process.env.OAUTH_CLIENT_ID || '',
    CLIENT_SECRET: process.env.OAUTH_CLIENT_SECRET || '',

    // Todoist OAuth Client Configuration
    TODOIST_CLIENT_ID: process.env.TODOIST_CLIENT_ID || '',
    TODOIST_CLIENT_SECRET: process.env.TODOIST_CLIENT_SECRET || '',
    TODOIST_REDIRECT_URI: process.env.TODOIST_REDIRECT_URI || '',
    TODOIST_AUTHORIZATION_URL: 'https://todoist.com/oauth/authorize',
    TODOIST_TOKEN_URL: 'https://todoist.com/oauth/access_token',
    TODOIST_REVOKE_URL: 'https://api.todoist.com/sync/v9/access_tokens/revoke',

    // Token Storage Configuration
    TOKEN_ENCRYPTION_KEY: process.env.TOKEN_ENCRYPTION_KEY || '',
    TOKEN_STORAGE_TYPE: (process.env.TOKEN_STORAGE_TYPE as 'redis' | 'file' | 'memory') || 'memory',

    // Required Scopes for MCP Operations
    REQUIRED_SCOPES: ['mcp:todoist:read', 'mcp:todoist:write'],

    // Server Configuration
    SERVER_URL: process.env.SERVER_URL || 'http://localhost:3000',
} as const

// Validate required OAuth environment variables
export function validateOAuthConfig() {
    const requiredVars = [
        'OAUTH_AUTHORIZATION_SERVER_URL',
        'OAUTH_AUDIENCE', 
        'OAUTH_INTROSPECTION_ENDPOINT',
        'OAUTH_CLIENT_ID',
        'OAUTH_CLIENT_SECRET',
        'TODOIST_CLIENT_ID',
        'TODOIST_CLIENT_SECRET',
        'TODOIST_REDIRECT_URI',
        'TOKEN_ENCRYPTION_KEY',
        'SERVER_URL'
    ]
    
    const missing = requiredVars.filter(
        (varName) => !process.env[varName] || process.env[varName]?.trim() === '',
    )

    if (missing.length > 0) {
        throw new Error(`Missing required OAuth environment variables: ${missing.join(', ')}`)
    }

    // Validate token encryption key strength
    if (OAUTH_CONFIG.TOKEN_ENCRYPTION_KEY.length < 32) {
        throw new Error('TOKEN_ENCRYPTION_KEY must be at least 32 characters long')
    }

    // Validate URLs are properly formatted
    try {
        new URL(OAUTH_CONFIG.AUTHORIZATION_SERVER_URL)
        new URL(OAUTH_CONFIG.AUDIENCE)
        new URL(OAUTH_CONFIG.INTROSPECTION_ENDPOINT)
        new URL(OAUTH_CONFIG.TODOIST_REDIRECT_URI)
        new URL(OAUTH_CONFIG.SERVER_URL)
    } catch (error) {
        throw new Error('Invalid URL format in OAuth configuration')
    }
}