/**
 * OAuth 2.1 Authentication Middleware for MCP Compliance
 *
 * This middleware implements MCP-compliant OAuth 2.1 token validation as a resource server.
 * It validates access tokens issued by an external authorization server and extracts
 * user identity for downstream processing.
 *
 * Security Features:
 * - Strict Bearer token validation (Authorization header only)
 * - Token introspection with external authorization server
 * - Audience validation to prevent token misuse
 * - Scope validation for required MCP operations
 * - Rate limiting on token validation attempts
 * - Comprehensive security event logging
 *
 * MCP Compliance:
 * - Validates tokens per MCP authorization specification
 * - Implements OAuth 2.1 security best practices
 * - No token passthrough between services
 * - Proper error responses for different failure scenarios
 */

import type { NextFunction, Request, Response } from 'express'
import { OAUTH_CONFIG } from '../config/oauth.js'
import { ERROR_CODES } from '../constants/security.js'
import { extractBearerToken } from '../utils/auth.js'
import { logSecurityEvent } from '../utils/logger.js'
import { RateLimiterFactory } from '../utils/rate-limiter.js'
import { sendOAuthError } from '../utils/security-responses.js'

// Initialize rate limiter for token validation attempts
const tokenValidationRateLimiter = RateLimiterFactory.createAuthLimiter()

// Token introspection response interface
interface TokenIntrospectionResponse {
    active: boolean
    sub?: string
    aud?: string | string[]
    scope?: string
    exp?: number
    iat?: number
    client_id?: string
    username?: string
    token_type?: string
}

/**
 * OAuth 2.1 authentication middleware for MCP compliance
 * 
 * Validates access tokens via token introspection and populates req.mcpAuth
 * with user information for downstream middleware.
 */
export async function authenticateOAuth(req: Request, res: Response, next: NextFunction): Promise<void> {
    const clientIp = req.ip || req.socket?.remoteAddress || 'unknown'
    const authHeader = req.headers.authorization
    const userAgent = req.headers['user-agent']

    // Extract Bearer token from Authorization header
    const token = extractBearerToken(authHeader)
    if (!token) {
        logSecurityEvent('OAuth auth failed', {
            reason: 'missing_or_invalid_bearer_token',
            ip: clientIp,
            userAgent: userAgent,
        })

        sendOAuthError(res, ERROR_CODES.UNAUTHORIZED, 'Authentication required')
        return
    }

    // Rate limiting check for token validation attempts
    const rateLimitResult = tokenValidationRateLimiter.checkRateLimit(clientIp)
    if (!rateLimitResult.allowed) {
        logSecurityEvent('OAuth auth failed', {
            reason: 'rate_limited',
            ip: clientIp,
            userAgent: userAgent,
            attempts: rateLimitResult.totalRequests,
            resetTime: new Date(rateLimitResult.resetTime).toISOString(),
        })

        sendOAuthError(res, ERROR_CODES.TOO_MANY_REQUESTS, 'Too many authentication attempts. Please try again later.')
        return
    }

    try {
        // Perform token introspection with authorization server
        const introspectionResult = await introspectToken(token)

        // Validate token is active
        if (!introspectionResult.active) {
            throw new Error('Token is not active')
        }

        // Validate required claims
        if (!introspectionResult.sub || typeof introspectionResult.sub !== 'string') {
            throw new Error('Missing or invalid subject claim')
        }

        // Validate audience claim (critical for MCP compliance)
        const validAudience = validateAudience(introspectionResult.aud)
        if (!validAudience) {
            throw new Error('Invalid audience claim')
        }

        // Validate required scopes for MCP operations
        const validScopes = validateScopes(introspectionResult.scope)
        if (!validScopes) {
            throw new Error('Insufficient scopes for MCP operations')
        }

        // Check token expiration
        if (introspectionResult.exp && introspectionResult.exp <= Math.floor(Date.now() / 1000)) {
            throw new Error('Token has expired')
        }

        // Populate request with OAuth authentication info
        req.mcpAuth = {
            authorized: true,
            method: 'oauth2.1',
            identifier: introspectionResult.sub,
            scopes: introspectionResult.scope?.split(' ') || [],
            clientId: introspectionResult.client_id,
            username: introspectionResult.username,
            expiresAt: introspectionResult.exp,
            issuedAt: introspectionResult.iat,
        }

        logSecurityEvent('OAuth auth successful', {
            reason: 'token_valid',
            ip: clientIp,
            userAgent: userAgent,
            userId: introspectionResult.sub,
            clientId: introspectionResult.client_id,
            scopes: introspectionResult.scope,
        })

        next()
    } catch (error) {
        // Classify different types of OAuth errors
        let reason = 'invalid_token'
        let logLevel = 'warn'
        let errorCode: number = ERROR_CODES.UNAUTHORIZED
        let errorMessage = 'Authentication failed'

        if (error instanceof Error) {
            if (error.message.includes('not active')) {
                reason = 'token_inactive'
                errorCode = ERROR_CODES.OAUTH_TOKEN_INACTIVE
                errorMessage = 'Token is not active'
            } else if (error.message.includes('audience')) {
                reason = 'invalid_audience'
                errorCode = ERROR_CODES.OAUTH_INVALID_AUDIENCE
                errorMessage = 'Invalid token audience'
                logLevel = 'error' // Potential security issue
            } else if (error.message.includes('scopes')) {
                reason = 'insufficient_scopes'
                errorCode = ERROR_CODES.OAUTH_INSUFFICIENT_SCOPE
                errorMessage = 'Insufficient permissions'
            } else if (error.message.includes('expired')) {
                reason = 'token_expired'
                errorCode = ERROR_CODES.OAUTH_TOKEN_EXPIRED
                errorMessage = 'Token has expired'
            } else if (error.message.includes('subject')) {
                reason = 'invalid_subject'
                errorCode = ERROR_CODES.OAUTH_INVALID_CLAIMS
                errorMessage = 'Invalid token claims'
            } else if (error.message.includes('network') || error.message.includes('timeout')) {
                reason = 'introspection_failed'
                errorCode = ERROR_CODES.SERVICE_UNAVAILABLE
                errorMessage = 'Authentication service unavailable'
                logLevel = 'error'
            }
        }

        logSecurityEvent(
            'OAuth auth failed',
            {
                reason,
                ip: clientIp,
                userAgent: userAgent,
                error: error instanceof Error ? error.message : 'Unknown error',
                errorCode,
            },
            logLevel as 'warn' | 'error',
        )

        // Record failed auth attempt for rate limiting
        tokenValidationRateLimiter.recordAttempt(clientIp)

        sendOAuthError(res, errorCode, errorMessage)
        return
    }
}

/**
 * Perform token introspection with the authorization server
 */
async function introspectToken(token: string): Promise<TokenIntrospectionResponse> {
    const introspectionUrl = OAUTH_CONFIG.INTROSPECTION_ENDPOINT
    const clientId = OAUTH_CONFIG.CLIENT_ID
    const clientSecret = OAUTH_CONFIG.CLIENT_SECRET

    // Prepare introspection request
    const body = new URLSearchParams({
        token: token,
        token_type_hint: 'access_token'
    })

    // Use client_secret_basic authentication
    const authHeader = `Basic ${Buffer.from(`${clientId}:${clientSecret}`).toString('base64')}`

    try {
        const response = await fetch(introspectionUrl, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
                'Authorization': authHeader,
                'Accept': 'application/json',
            },
            body: body.toString(),
            // Set reasonable timeout for introspection
            signal: AbortSignal.timeout(10000), // 10 seconds
        })

        if (!response.ok) {
            throw new Error(`Token introspection failed: ${response.status} ${response.statusText}`)
        }

        const result = await response.json() as TokenIntrospectionResponse
        return result
    } catch (error) {
        if (error instanceof Error && error.name === 'AbortError') {
            throw new Error('Token introspection timeout')
        }
        throw new Error(`Token introspection network error: ${error instanceof Error ? error.message : 'Unknown error'}`)
    }
}

/**
 * Validate audience claim matches this MCP server
 */
function validateAudience(audience: string | string[] | undefined): boolean {
    if (!audience) {
        return false
    }

    const expectedAudience = OAUTH_CONFIG.AUDIENCE
    
    if (typeof audience === 'string') {
        return audience === expectedAudience
    }
    
    if (Array.isArray(audience)) {
        return audience.includes(expectedAudience)
    }
    
    return false
}

/**
 * Validate token has required scopes for MCP operations
 */
function validateScopes(scopes: string | undefined): boolean {
    if (!scopes) {
        return false
    }

    const tokenScopes = scopes.split(' ')
    const requiredScopes = OAUTH_CONFIG.REQUIRED_SCOPES

    // Check if all required scopes are present
    return requiredScopes.every(requiredScope => tokenScopes.includes(requiredScope))
}