/**
 * Todoist OAuth Integration Handlers
 *
 * Implements the OAuth flow for connecting users' Todoist accounts to the MCP server.
 * Users must first be authenticated with the MCP server via OAuth, then can connect
 * their Todoist account through these endpoints.
 *
 * Flow:
 * 1. User authenticated with MCP server (OAuth 2.1)
 * 2. User initiates Todoist connection (/auth/todoist/connect)
 * 3. Redirected to Todoist OAuth authorization
 * 4. Todoist redirects back to callback (/auth/todoist/callback)
 * 5. Server exchanges code for Todoist access token
 * 6. Token stored encrypted, mapped to user's MCP subject
 */

import type { Request, Response } from 'express'
import { randomBytes } from 'node:crypto'
import { OAUTH_CONFIG } from '../config/oauth.js'
import { ERROR_CODES } from '../constants/security.js'
import { logSecurityEvent } from '../utils/logger.js'
import { sendOAuthError } from '../utils/security-responses.js'
import { UserTokenStorage } from '../utils/user-token-storage.js'

// Initialize user token storage
const userTokenStorage = new UserTokenStorage()

// In-memory storage for OAuth state (in production, use Redis)
const oauthStates = new Map<string, { userId: string; timestamp: number }>()

// Clean up expired OAuth states every 10 minutes
setInterval(() => {
    const now = Date.now()
    const expiredStates = Array.from(oauthStates.entries())
        .filter(([, data]) => now - data.timestamp > 600000) // 10 minutes
        .map(([state]) => state)
    
    expiredStates.forEach(state => oauthStates.delete(state))
}, 600000)

/**
 * Initiate Todoist OAuth connection
 * 
 * Requires user to be authenticated with MCP server first.
 * Redirects to Todoist OAuth authorization page.
 */
export function handleTodoistConnect(req: Request, res: Response): void {
    const clientIp = req.ip || req.socket?.remoteAddress || 'unknown'
    const userAgent = req.headers['user-agent'] || 'unknown'

    // Ensure user is authenticated with MCP server
    if (!req.mcpAuth?.authorized || !req.mcpAuth.identifier) {
        logSecurityEvent('Todoist connect failed', {
            reason: 'not_authenticated',
            ip: clientIp,
            userAgent: userAgent,
        })

        sendOAuthError(res, ERROR_CODES.UNAUTHORIZED, 'MCP authentication required')
        return
    }

    const userId = req.mcpAuth.identifier

    // Generate OAuth state parameter for CSRF protection
    const state = randomBytes(32).toString('hex')
    oauthStates.set(state, {
        userId,
        timestamp: Date.now(),
    })

    // Build Todoist OAuth authorization URL
    const authUrl = new URL(OAUTH_CONFIG.TODOIST_AUTHORIZATION_URL)
    authUrl.searchParams.append('client_id', OAUTH_CONFIG.TODOIST_CLIENT_ID)
    authUrl.searchParams.append('scope', 'data:read,data:read_write,task:add,project:delete')
    authUrl.searchParams.append('state', state)
    authUrl.searchParams.append('redirect_uri', OAUTH_CONFIG.TODOIST_REDIRECT_URI)
    authUrl.searchParams.append('response_type', 'code')

    logSecurityEvent('Todoist connect initiated', {
        userId,
        ip: clientIp,
        userAgent: userAgent,
        state,
    })

    // Redirect to Todoist OAuth
    res.redirect(authUrl.toString())
}

/**
 * Handle Todoist OAuth callback
 * 
 * Processes the authorization code from Todoist and exchanges it for an access token.
 * Stores the token encrypted and mapped to the user's MCP subject.
 */
export async function handleTodoistCallback(req: Request, res: Response): Promise<void> {
    const clientIp = req.ip || req.socket?.remoteAddress || 'unknown'
    const userAgent = req.headers['user-agent'] || 'unknown'

    const { code, state } = req.query

    // Validate required parameters
    if (!code || !state) {
        logSecurityEvent('Todoist callback failed', {
            reason: 'missing_parameters',
            ip: clientIp,
            userAgent: userAgent,
            hasCode: !!code,
            hasState: !!state,
        })

        sendOAuthError(res, ERROR_CODES.INVALID_PARAMS, 'Missing authorization code or state')
        return
    }

    // Validate state parameter (CSRF protection)
    const stateData = oauthStates.get(state as string)
    if (!stateData) {
        logSecurityEvent('Todoist callback failed', {
            reason: 'invalid_state',
            ip: clientIp,
            userAgent: userAgent,
            state,
        })

        sendOAuthError(res, ERROR_CODES.VALIDATION_ERROR, 'Invalid or expired OAuth state')
        return
    }

    // Remove used state
    oauthStates.delete(state as string)

    const userId = stateData.userId

    try {
        // Exchange authorization code for access token
        const tokenResponse = await exchangeCodeForToken(code as string)

        // Get user info from Todoist to validate token and get user ID
        const userInfo = await getTodoistUserInfo(tokenResponse.access_token)

        // Store encrypted token mapped to user
        await userTokenStorage.storeUserToken(
            userId,
            tokenResponse.access_token,
            userInfo.id
        )

        logSecurityEvent('Todoist connection successful', {
            userId,
            todoistUserId: userInfo.id,
            todoistEmail: userInfo.email,
            ip: clientIp,
            userAgent: userAgent,
        })

        // Return success response
        res.json({
            success: true,
            message: 'Todoist account connected successfully',
            user: {
                id: userInfo.id,
                email: userInfo.email,
                name: userInfo.full_name,
            },
        })
    } catch (error) {
        logSecurityEvent('Todoist callback failed', {
            reason: 'token_exchange_failed',
            userId,
            ip: clientIp,
            userAgent: userAgent,
            error: error instanceof Error ? error.message : 'Unknown error',
        }, 'error')

        sendOAuthError(res, ERROR_CODES.INTERNAL_ERROR, 'Failed to connect Todoist account')
        return
    }
}

/**
 * Disconnect Todoist account
 * 
 * Revokes the stored Todoist token and removes the connection.
 */
export async function handleTodoistDisconnect(req: Request, res: Response): Promise<void> {
    const clientIp = req.ip || req.socket?.remoteAddress || 'unknown'
    const userAgent = req.headers['user-agent'] || 'unknown'

    // Ensure user is authenticated
    if (!req.mcpAuth?.authorized || !req.mcpAuth.identifier) {
        sendOAuthError(res, ERROR_CODES.UNAUTHORIZED, 'Authentication required')
        return
    }

    const userId = req.mcpAuth.identifier

    try {
        // Get current token to revoke it
        const userTokenData = await userTokenStorage.getUserToken(userId)
        if (userTokenData) {
            // Revoke token with Todoist
            await revokeTodoistToken(userTokenData.todoistToken)

            // Remove from storage
            await userTokenStorage.removeUserToken(userId)

            logSecurityEvent('Todoist disconnection successful', {
                userId,
                todoistUserId: userTokenData.todoistUserId,
                ip: clientIp,
                userAgent: userAgent,
            })

            res.json({
                success: true,
                message: 'Todoist account disconnected successfully',
            })
        } else {
            res.json({
                success: true,
                message: 'No Todoist account was connected',
            })
        }
    } catch (error) {
        logSecurityEvent('Todoist disconnect failed', {
            reason: 'disconnect_error',
            userId,
            ip: clientIp,
            userAgent: userAgent,
            error: error instanceof Error ? error.message : 'Unknown error',
        }, 'error')

        sendOAuthError(res, ERROR_CODES.INTERNAL_ERROR, 'Failed to disconnect Todoist account')
        return
    }
}

/**
 * Get connection status
 * 
 * Returns whether the user has a connected Todoist account.
 */
export async function handleTodoistStatus(req: Request, res: Response): Promise<void> {
    // Ensure user is authenticated
    if (!req.mcpAuth?.authorized || !req.mcpAuth.identifier) {
        sendOAuthError(res, ERROR_CODES.UNAUTHORIZED, 'Authentication required')
        return
    }

    const userId = req.mcpAuth.identifier

    try {
        const userTokenData = await userTokenStorage.getUserToken(userId)
        
        if (userTokenData) {
            res.json({
                connected: true,
                user: {
                    id: userTokenData.todoistUserId,
                    connectedAt: userTokenData.connectedAt,
                    lastUsed: userTokenData.lastUsed,
                },
            })
        } else {
            res.json({
                connected: false,
            })
        }
    } catch (error) {
        sendOAuthError(res, ERROR_CODES.INTERNAL_ERROR, 'Failed to check connection status')
        return
    }
}

/**
 * Exchange authorization code for access token
 */
async function exchangeCodeForToken(code: string): Promise<{ access_token: string; token_type: string }> {
    const tokenUrl = OAUTH_CONFIG.TODOIST_TOKEN_URL
    
    const body = new URLSearchParams({
        client_id: OAUTH_CONFIG.TODOIST_CLIENT_ID,
        client_secret: OAUTH_CONFIG.TODOIST_CLIENT_SECRET,
        code: code,
        redirect_uri: OAUTH_CONFIG.TODOIST_REDIRECT_URI,
    })

    const response = await fetch(tokenUrl, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
            'Accept': 'application/json',
        },
        body: body.toString(),
        signal: AbortSignal.timeout(10000), // 10 seconds
    })

    if (!response.ok) {
        throw new Error(`Token exchange failed: ${response.status} ${response.statusText}`)
    }

    const result = await response.json()
    
    if (!result.access_token) {
        throw new Error('No access token received from Todoist')
    }

    return result
}

/**
 * Get user information from Todoist API
 */
async function getTodoistUserInfo(token: string): Promise<{ id: string; email: string; full_name: string }> {
    const response = await fetch('https://api.todoist.com/sync/v9/sync', {
        method: 'POST',
        headers: {
            'Authorization': `Bearer ${token}`,
            'Content-Type': 'application/x-www-form-urlencoded',
        },
        body: 'sync_token=*&resource_types=["user"]',
        signal: AbortSignal.timeout(10000), // 10 seconds
    })

    if (!response.ok) {
        throw new Error(`Failed to get user info: ${response.status} ${response.statusText}`)
    }

    const result = await response.json()
    
    if (!result.user) {
        throw new Error('No user information received from Todoist')
    }

    return {
        id: result.user.id.toString(),
        email: result.user.email,
        full_name: result.user.full_name,
    }
}

/**
 * Revoke Todoist access token
 */
async function revokeTodoistToken(token: string): Promise<void> {
    try {
        const response = await fetch(OAUTH_CONFIG.TODOIST_REVOKE_URL, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                client_id: OAUTH_CONFIG.TODOIST_CLIENT_ID,
                client_secret: OAUTH_CONFIG.TODOIST_CLIENT_SECRET,
                access_token: token,
            }),
            signal: AbortSignal.timeout(10000), // 10 seconds
        })

        // Todoist revocation might return various status codes, so we don't strictly check response.ok
        // The token will be considered revoked regardless
    } catch (error) {
        // Log but don't throw - revocation is best effort
        console.warn('Failed to revoke Todoist token:', error)
    }
}