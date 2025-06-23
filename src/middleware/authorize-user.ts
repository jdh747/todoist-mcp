/**
 * User Authorization Middleware
 *
 * This middleware provides user-specific access control for the MCP endpoint.
 * It checks if the authenticated user's identifier matches the configured allowed user ID.
 *
 * Security Features:
 * - Works in conjunction with JWT authentication middleware
 * - Validates user authorization against ALLOWED_USER_ID configuration
 * - Logs unauthorized access attempts with user context
 * - Returns standardized 403 Forbidden responses for unauthorized users
 * - Maintains timing-safe comparison for user ID validation
 */

import type { NextFunction, Request, Response } from 'express'
import { SECURITY_CONFIG } from '../config/security.js'
import { ERROR_CODES } from '../constants/security.js'
import { timingSafeStringEqual } from '../utils/auth.js'
import { logSecurityEvent } from '../utils/logger.js'
import { sendJwtError } from '../utils/security-responses.js'

/**
 * Authorization middleware that restricts access to specific user
 *
 * Requirements:
 * - Must be called after authenticate middleware
 * - req.mcpAuth must be populated with user identifier
 *
 * @param req Express request object with mcpAuth populated
 * @param res Express response object
 * @param next Express next function
 */
export function authorizeUser(req: Request, res: Response, next: NextFunction): void {
    const clientIp = req.ip || req.socket?.remoteAddress || 'unknown'
    const userAgent = req.headers['user-agent'] || 'unknown'

    // Ensure authentication middleware has run first
    if (!req.mcpAuth?.authorized || !req.mcpAuth.identifier) {
        logSecurityEvent(
            'User authorization failed',
            {
                reason: 'authentication_required',
                ip: clientIp,
                userAgent: userAgent,
            },
            'error',
        )

        sendJwtError(res, ERROR_CODES.UNAUTHORIZED, 'Authentication required')
        return
    }

    const userIdentifier = req.mcpAuth.identifier
    const allowedUserId = SECURITY_CONFIG.ALLOWED_USER_ID

    // Use timing-safe comparison to prevent timing attacks
    const isAuthorized = timingSafeStringEqual(userIdentifier, allowedUserId)

    if (!isAuthorized) {
        logSecurityEvent(
            'User authorization failed',
            {
                reason: 'user_not_authorized',
                ip: clientIp,
                userAgent: userAgent,
                attemptedUser: userIdentifier,
                allowedUser: allowedUserId, // Safe to log for debugging
            },
            'warn',
        )

        sendJwtError(res, ERROR_CODES.USER_NOT_AUTHORIZED, 'Access denied: User not authorized')
        return
    }

    // Log successful authorization for security monitoring
    logSecurityEvent('User authorization successful', {
        reason: 'user_authorized',
        ip: clientIp,
        userAgent: userAgent,
        userId: userIdentifier,
        method: req.mcpAuth.method,
        tokenId: req.mcpAuth.tokenId,
    })

    // Authorization successful, proceed to next middleware
    next()
}
