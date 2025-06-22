#!/usr/bin/env node

import crypto from 'node:crypto'
import jwt from 'jsonwebtoken'

/**
 * Security setup utility for generating secure tokens and keys
 */

// Generate a cryptographically secure random string
function generateSecureKey(length = 32): string {
    return crypto.randomBytes(length).toString('hex')
}

// Generate JWT secret
function generateJWTSecret(): string {
    return generateSecureKey(64) // 512 bits
}

// Generate a sample JWT token for testing
function generateSampleToken(): string {
    const tempSecret = generateJWTSecret()

    const payload = {
        sub: 'user-1',
        iat: Math.floor(Date.now() / 1000),
        exp: Math.floor(Date.now() / 1000) + 24 * 60 * 60, // 24 hours
    }

    return jwt.sign(payload, tempSecret)
}

// Create .env.example file content
function generateEnvExample(): string {
    return `# Security Configuration
JWT_SECRET=${generateJWTSecret()}

# Todoist API
TODOIST_API_KEY=your_todoist_api_key_here

# Server Configuration
PORT=3000
NODE_ENV=development

# Rate Limiting
RATE_LIMIT_WINDOW_MS=900000
RATE_LIMIT_MAX_REQUESTS=100

# CORS Settings
ALLOWED_ORIGINS=http://localhost:3001,https://yourdomain.com

# Logging
LOG_LEVEL=info

# Request timeout (30 seconds)
REQUEST_TIMEOUT_MS=30000

# Max request body size
MAX_REQUEST_SIZE=10mb

# Security Features
ENABLE_HELMET=true
`
}

// Main setup function
function setup() {
    console.log('🔐 Todoist MCP Security Setup')
    console.log('================================')
    console.log()

    console.log('Generated JWT Secret (512-bit):')
    console.log(generateJWTSecret())
    console.log()

    console.log('Sample JWT Token:')
    console.log(generateSampleToken())
    console.log()

    console.log('Environment Variables (.env file):')
    console.log('-----------------------------------')
    console.log(generateEnvExample())

    console.log()
    console.log('🛡️  Security Recommendations:')
    console.log('1. Store the JWT_SECRET and MCP_API_KEY securely')
    console.log('2. Use HTTPS in production')
    console.log('3. Set appropriate CORS origins')
    console.log('4. Monitor logs for security events')
    console.log('5. Regularly rotate your API keys')
    console.log('6. Use a reverse proxy (nginx) in production')
    console.log('7. Enable firewall rules to restrict access')
    console.log()

    console.log('📖 Authentication Methods:')
    console.log('1. JWT Bearer Token: Authorization: Bearer <token>')
    console.log()
}

// Run setup if called directly
if (import.meta.url === `file://${process.argv[1]}`) {
    setup()
}

export { generateEnvExample, generateJWTSecret, generateSampleToken, generateSecureKey, setup }
