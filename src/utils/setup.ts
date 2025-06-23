#!/usr/bin/env node

import { SECURITY_CONFIG } from '../config/security.js'
import { generateToken } from './auth.js'

/**
 * Security setup utility for generating secure tokens and keys
 */

// Main setup function
export function setup() {
    const token = generateToken({
        sub: 'sample_user',
        name: 'Sample User',
        email: 'sample_user@example.com',
    })

    console.log('🔐 Todoist MCP Security Setup')
    console.log('================================')
    console.log()

    console.log('Generated JWT Secret (512-bit):')
    console.log(SECURITY_CONFIG.JWT_SECRET)
    console.log()

    console.log('Sample JWT Token:')
    console.log(token)
    console.log()

    console.log('Environment Variables (.env file):')
    console.log('-----------------------------------')
    console.log(generateEnvExample())

    console.log()
    console.log('🛡️  Security Recommendations:')
    console.log('1. Store the JWT_SECRET securely')
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

// Create .env.example file content
function generateEnvExample(): string {
    return `# Security Configuration
JWT_SECRET=${SECURITY_CONFIG.JWT_SECRET}

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

# Limit the size of request payloads (50KB)
MAX_REQUEST_PAYLOAD_SIZE=50000
`
}
