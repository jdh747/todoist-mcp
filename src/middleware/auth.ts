/**
 * JWT Authentication Middleware with Security Best Practices
 *
 * This middleware implements secure JWT authentication with the following features:
 * - Strict JWT verification with algorithm specification
 * - Token blacklisting for revocation
 * - Rate limiting for authentication attempts
 * - Comprehensive security logging
 * - Protection against timing attacks
 * - Detailed JWT claims validation
 *
 * Security Features:
 * - Algorithm whitelisting (HS256 only)
 * - Issuer and audience validation
 * - Token ID (jti) tracking for blacklisting
 * - Clock skew tolerance (30 seconds)
 * - Rate limiting (5 attempts per 5 minutes per IP)
 * - Comprehensive error classification and logging
 */

import type { NextFunction, Request, Response } from 'express'
import jwt from 'jsonwebtoken'
import { SECURITY_CONFIG } from '../config/security.js'
import { extractBearerToken, isValidJWTFormat, sendAuthError } from '../utils/auth.js'
import { logSecurityEvent } from '../utils/logger.js'
import { RateLimiterFactory } from '../utils/rate-limiter.js'
import { TokenBlacklistFactory } from '../utils/token-blacklist.js'

// Initialize security components
const tokenBlacklist = TokenBlacklistFactory.createDefault()
const authRateLimiter = RateLimiterFactory.createAuthLimiter()

// JWT verification options for enhanced security
const JWT_VERIFY_OPTIONS: jwt.VerifyOptions = {
    algorithms: ['HS256'], // Restrict to specific algorithms to prevent algorithm confusion attacks
    issuer: 'todoist-mcp', // Validate issuer
    audience: 'todoist-mcp-client', // Validate audience
    clockTolerance: 30, // Allow 30 seconds clock skew
    ignoreExpiration: false, // Ensure expiration is checked
    ignoreNotBefore: false, // Ensure nbf claim is checked
    maxAge: '24h', // Maximum token age
}

// JWT Authentication middleware (main export)
export function authenticate(req: Request, res: Response, next: NextFunction): void {
    const clientIp = req.ip || req.socket?.remoteAddress || 'unknown'
    const authHeader = req.headers.authorization
    const userAgent = req.headers['user-agent']

    // Extract and validate Bearer token
    const token = extractBearerToken(authHeader)
    if (!token) {
        logSecurityEvent('JWT auth failed', {
            reason: 'missing_or_invalid_bearer_token',
            ip: clientIp,
            userAgent: userAgent,
        })

        sendAuthError(res, 'Authentication required')
        return
    }

    // Validate JWT format
    if (!isValidJWTFormat(token)) {
        logSecurityEvent('JWT auth failed', {
            reason: 'invalid_jwt_format',
            ip: clientIp,
            userAgent: userAgent,
        })

        sendAuthError(res, 'Invalid authentication token')
        return
    }

    // Rate limiting check
    const rateLimitResult = authRateLimiter.checkRateLimit(clientIp)
    if (!rateLimitResult.allowed) {
        logSecurityEvent('JWT auth failed', {
            reason: 'rate_limited',
            ip: clientIp,
            userAgent: userAgent,
            attempts: rateLimitResult.totalRequests,
            resetTime: new Date(rateLimitResult.resetTime).toISOString(),
        })

        sendAuthError(res, 'Too many authentication attempts. Please try again later.')
        return
    }

    try {
        // Verify JWT with strict options
        const decoded = jwt.verify(
            token,
            SECURITY_CONFIG.JWT_SECRET,
            JWT_VERIFY_OPTIONS,
        ) as jwt.JwtPayload

        // Validate required claims
        if (!decoded.sub || typeof decoded.sub !== 'string') {
            throw new Error('Missing or invalid subject claim')
        }

        if (!decoded.jti || typeof decoded.jti !== 'string') {
            throw new Error('Missing or invalid token ID claim')
        }

        if (!decoded.iat || typeof decoded.iat !== 'number') {
            throw new Error('Missing or invalid issued at claim')
        }

        if (!decoded.exp || typeof decoded.exp !== 'number') {
            throw new Error('Missing or invalid expiration claim')
        }

        // Additional security checks
        const now = Math.floor(Date.now() / 1000)

        // Check if token is blacklisted
        if (tokenBlacklist.isTokenBlacklisted(decoded.jti)) {
            throw new Error('Token has been revoked')
        }

        // Check if token was issued in the future (with small tolerance)
        if (decoded.iat > now + 60) {
            throw new Error('Token issued in the future')
        }

        // Check if token is expired (redundant but explicit)
        if (decoded.exp <= now) {
            throw new Error('Token has expired')
        }

        req.mcpAuth = {
            authorized: true,
            method: 'jwt',
            identifier: decoded.sub,
            tokenId: decoded.jti,
            issuedAt: decoded.iat,
            expiresAt: decoded.exp,
        }

        next()
    } catch (error) {
        // Classify different types of JWT errors for better logging
        let reason = 'invalid_token'
        let logLevel = 'warn'

        if (error instanceof jwt.TokenExpiredError) {
            reason = 'token_expired'
        } else if (error instanceof jwt.JsonWebTokenError) {
            reason = 'token_malformed'
        } else if (error instanceof jwt.NotBeforeError) {
            reason = 'token_not_active'
        } else if (error instanceof Error && error.message.includes('audience')) {
            reason = 'invalid_audience'
            logLevel = 'error' // Potential security issue
        } else if (error instanceof Error && error.message.includes('issuer')) {
            reason = 'invalid_issuer'
            logLevel = 'error' // Potential security issue
        } else if (error instanceof Error && error.message.includes('algorithm')) {
            reason = 'invalid_algorithm'
            logLevel = 'error' // Potential security issue
        }

        logSecurityEvent(
            'JWT auth failed',
            {
                reason,
                ip: clientIp,
                userAgent: userAgent,
                error: error instanceof Error ? error.message : 'Unknown error',
            },
            logLevel as 'warn' | 'error',
        )

        // Record failed auth attempt (this increments the rate limit counter)
        authRateLimiter.recordAttempt(clientIp)

        res.status(401).json({
            jsonrpc: '2.0',
            error: {
                code: -32001,
                message: 'Authentication failed',
            },
            id: null,
        })

        return
    }
}
