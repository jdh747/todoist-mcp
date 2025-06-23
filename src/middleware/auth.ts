/**
 * JWT Authentication Middleware with Enhanced Security
 *
 * This middleware implements enterprise-grade JWT authentication with comprehensive security features:
 * - Strict JWT verification with algorithm specification and enhanced validation
 * - Cryptographically secure token generation with crypto.randomBytes()
 * - Token blacklisting with automatic cleanup for revocation management
 * - Rate limiting for authentication attempts with failed login tracking
 * - Comprehensive security logging with detailed error classification
 * - Protection against timing attacks using constant-time comparisons
 * - Detailed JWT claims validation with specific error codes
 *
 * Security Enhancements:
 * - Algorithm whitelisting (HS256 only) prevents algorithm confusion attacks
 * - Timing-safe issuer and audience validation prevents side-channel attacks
 * - Token ID (jti) tracking with secure random generation for blacklisting
 * - Clock skew tolerance (30 seconds) with future token detection
 * - Rate limiting (5 attempts per 5 minutes per IP) with automatic cleanup
 * - Granular error codes for different JWT failure scenarios
 * - Enhanced security event logging with context and error classification
 */

import type { NextFunction, Request, Response } from 'express'
import jwt from 'jsonwebtoken'
import { SECURITY_CONFIG } from '../config/security.js'
import { ERROR_CODES, JWT_CONSTANTS } from '../constants/security.js'
import {
    extractBearerToken,
    isValidJWTFormat,
    sendAuthError,
    timingSafeStringEqual,
} from '../utils/auth.js'
import { logSecurityEvent } from '../utils/logger.js'
import { RateLimiterFactory } from '../utils/rate-limiter.js'
import { sendJwtError } from '../utils/security-responses.js'
import { TokenBlacklistFactory } from '../utils/token-blacklist.js'

// Initialize security components
const tokenBlacklist = TokenBlacklistFactory.createDefault()
const authRateLimiter = RateLimiterFactory.createAuthLimiter()

// JWT verification options for enhanced security
const JWT_VERIFY_OPTIONS: jwt.VerifyOptions = {
    algorithms: [JWT_CONSTANTS.ALGORITHM], // Restrict to specific algorithms to prevent algorithm confusion attacks
    issuer: JWT_CONSTANTS.ISSUER, // Validate issuer
    audience: JWT_CONSTANTS.AUDIENCE, // Validate audience
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

        // Validate required claims with enhanced security
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

        // Additional timing-safe validation for critical claims
        if (!decoded.iss || !timingSafeStringEqual(decoded.iss, JWT_CONSTANTS.ISSUER)) {
            throw new Error('Invalid issuer claim')
        }

        if (
            !decoded.aud ||
            (typeof decoded.aud === 'string' &&
                !timingSafeStringEqual(decoded.aud, JWT_CONSTANTS.AUDIENCE)) ||
            (Array.isArray(decoded.aud) &&
                !decoded.aud.some((aud) => timingSafeStringEqual(aud, JWT_CONSTANTS.AUDIENCE)))
        ) {
            throw new Error('Invalid audience claim')
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
        // Classify different types of JWT errors for better logging and specific error codes
        let reason = 'invalid_token'
        let logLevel = 'warn'
        let errorCode: number = ERROR_CODES.UNAUTHORIZED
        let errorMessage = 'Authentication failed'

        if (error instanceof jwt.TokenExpiredError) {
            reason = 'token_expired'
            errorCode = ERROR_CODES.JWT_TOKEN_EXPIRED
            errorMessage = 'Token has expired'
        } else if (error instanceof jwt.JsonWebTokenError) {
            reason = 'token_malformed'
            errorCode = ERROR_CODES.JWT_TOKEN_MALFORMED
            errorMessage = 'Token is malformed'
        } else if (error instanceof jwt.NotBeforeError) {
            reason = 'token_not_active'
            errorCode = ERROR_CODES.JWT_TOKEN_NOT_ACTIVE
            errorMessage = 'Token is not yet active'
        } else if (error instanceof Error && error.message.includes('audience')) {
            reason = 'invalid_audience'
            errorCode = ERROR_CODES.JWT_INVALID_AUDIENCE
            errorMessage = 'Invalid token audience'
            logLevel = 'error' // Potential security issue
        } else if (error instanceof Error && error.message.includes('issuer')) {
            reason = 'invalid_issuer'
            errorCode = ERROR_CODES.JWT_INVALID_ISSUER
            errorMessage = 'Invalid token issuer'
            logLevel = 'error' // Potential security issue
        } else if (error instanceof Error && error.message.includes('algorithm')) {
            reason = 'invalid_algorithm'
            errorCode = ERROR_CODES.JWT_INVALID_ALGORITHM
            errorMessage = 'Invalid token algorithm'
            logLevel = 'error' // Potential security issue
        } else if (error instanceof Error && error.message.includes('revoked')) {
            reason = 'token_revoked'
            errorCode = ERROR_CODES.JWT_TOKEN_REVOKED
            errorMessage = 'Token has been revoked'
        } else if (error instanceof Error && error.message.includes('claim')) {
            reason = 'invalid_claims'
            errorCode = ERROR_CODES.JWT_INVALID_CLAIMS
            errorMessage = 'Invalid token claims'
        }

        logSecurityEvent(
            'JWT auth failed',
            {
                reason,
                ip: clientIp,
                userAgent: userAgent,
                error: error instanceof Error ? error.message : 'Unknown error',
                errorCode,
            },
            logLevel as 'warn' | 'error',
        )

        // Record failed auth attempt (this increments the rate limit counter)
        authRateLimiter.recordAttempt(clientIp)

        sendJwtError(res, errorCode, errorMessage)
        return
    }
}
