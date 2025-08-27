/**
 * OAuth User Authorization Middleware
 *
 * This middleware handles user-specific authorization for OAuth-authenticated users.
 * It checks if the authenticated user has a valid Todoist connection and loads
 * their Todoist API credentials for MCP operations.
 *
 * Features:
 * - Works with OAuth 2.1 authentication middleware
 * - Validates user has connected their Todoist account
 * - Loads user-specific Todoist API tokens
 * - Handles token expiration and connection status
 * - Comprehensive security logging
 */

import type { NextFunction, Request, Response } from 'express'
import { ERROR_CODES } from '../constants/security.js'
import { logSecurityEvent } from '../utils/logger.js'
import { sendOAuthError } from '../utils/security-responses.js'
import { UserTokenStorage } from '../utils/user-token-storage.js'

// Initialize user token storage
const userTokenStorage = new UserTokenStorage()

/**
 * Authorization middleware for OAuth-authenticated users
 * 
 * Requirements:
 * - Must be called after authenticateOAuth middleware
 * - req.mcpAuth must be populated with OAuth user information
 * 
 * This middleware:
 * 1. Validates the user has completed OAuth authentication
 * 2. Checks if user has connected their Todoist account
 * 3. Loads user's Todoist API token for downstream operations
 * 4. Handles cases where user needs to connect Todoist
 */
export async function authorizeOAuthUser(req: Request, res: Response, next: NextFunction): Promise<void> {
    const clientIp = req.ip || req.socket?.remoteAddress || 'unknown'
    const userAgent = req.headers['user-agent'] || 'unknown'

    // Ensure OAuth authentication middleware has run first
    if (!req.mcpAuth?.authorized || !req.mcpAuth.identifier) {
        logSecurityEvent(
            'OAuth user authorization failed',
            {
                reason: 'oauth_authentication_required',
                ip: clientIp,
                userAgent: userAgent,
            },
            'error',
        )

        sendOAuthError(res, ERROR_CODES.UNAUTHORIZED, 'OAuth authentication required')
        return
    }

    const userSubject = req.mcpAuth.identifier

    try {
        // Load user's Todoist connection status and token
        const userTokenData = await userTokenStorage.getUserToken(userSubject)

        if (!userTokenData) {
            // User has not connected their Todoist account yet
            logSecurityEvent(
                'OAuth user authorization failed',
                {
                    reason: 'todoist_not_connected',
                    ip: clientIp,
                    userAgent: userAgent,
                    userId: userSubject,
                },
                'warn',
            )

            sendOAuthError(
                res, 
                ERROR_CODES.USER_NOT_AUTHORIZED, 
                'Todoist account not connected. Please connect your Todoist account first.'
            )
            return
        }

        // Check if Todoist token is still valid (basic validation)
        const isTokenValid = await validateTodoistToken(userTokenData.todoistToken)
        if (!isTokenValid) {
            // Token has expired or been revoked
            logSecurityEvent(
                'OAuth user authorization failed',
                {
                    reason: 'todoist_token_expired',
                    ip: clientIp,
                    userAgent: userAgent,
                    userId: userSubject,
                    todoistUserId: userTokenData.todoistUserId,
                },
                'warn',
            )

            // Remove invalid token from storage
            await userTokenStorage.removeUserToken(userSubject)

            sendOAuthError(
                res,
                ERROR_CODES.OAUTH_TOKEN_EXPIRED,
                'Todoist token has expired. Please reconnect your Todoist account.'
            )
            return
        }

        // Update last used timestamp
        await userTokenStorage.updateLastUsed(userSubject)

        // Add Todoist token info to request for downstream middleware
        req.todoistAuth = {
            todoistToken: userTokenData.todoistToken,
            todoistUserId: userTokenData.todoistUserId,
            connectedAt: userTokenData.connectedAt,
            lastUsed: new Date(),
        }

        logSecurityEvent('OAuth user authorization successful', {
            reason: 'user_authorized',
            ip: clientIp,
            userAgent: userAgent,
            userId: userSubject,
            todoistUserId: userTokenData.todoistUserId,
            method: req.mcpAuth.method,
            scopes: req.mcpAuth.scopes?.join(' '),
        })

        next()
    } catch (error) {
        logSecurityEvent(
            'OAuth user authorization failed',
            {
                reason: 'authorization_error',
                ip: clientIp,
                userAgent: userAgent,
                userId: userSubject,
                error: error instanceof Error ? error.message : 'Unknown error',
            },
            'error',
        )

        sendOAuthError(res, ERROR_CODES.INTERNAL_ERROR, 'Authorization service error')
        return
    }
}

/**
 * Validate Todoist token by making a simple API call
 * This helps detect expired or revoked tokens before attempting operations
 */
async function validateTodoistToken(token: string): Promise<boolean> {
    try {
        // Make a lightweight API call to verify token validity
        const response = await fetch('https://api.todoist.com/rest/v2/projects', {
            method: 'GET',
            headers: {
                'Authorization': `Bearer ${token}`,
            },
            signal: AbortSignal.timeout(5000), // 5 second timeout
        })

        // Token is valid if we get a successful response
        return response.ok
    } catch (error) {
        // Token is invalid if we get network errors or timeouts
        return false
    }
}