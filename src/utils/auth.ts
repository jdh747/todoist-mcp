import type { Response } from 'express'
import jwt from 'jsonwebtoken'
import { SECURITY_CONFIG } from '../config/security.js'

export function generateToken(
    payload: {
        sub: string // Subject (user identifier)
        [key: string]: unknown // Additional claims
    },
    expiresIn: string = SECURITY_CONFIG.JWT_EXPIRES_IN,
): string {
    const now = Math.floor(Date.now() / 1000)

    // Generate unique token ID for tracking
    const tokenId = `${payload.sub}_${now}_${Math.random().toString(36).substring(2, 15)}`

    const tokenPayload = {
        ...payload,
        iss: 'todoist-mcp', // Issuer
        aud: 'todoist-mcp-client', // Audience
        iat: now, // Issued at
        jti: tokenId, // JWT ID for token tracking
        // nbf (not before) can be added if needed
    }

    return jwt.sign(tokenPayload, SECURITY_CONFIG.JWT_SECRET, {
        expiresIn,
        algorithm: 'HS256', // Explicitly specify algorithm
    } as jwt.SignOptions)
}

export function extractBearerToken(authHeader: string | undefined): string | null {
    if (!authHeader) return null

    const parts = authHeader.split(' ')
    if (parts.length !== 2 || parts[0] !== 'Bearer') {
        return null
    }

    return parts[1]
}

export function isValidJWTFormat(token: string): boolean {
    // JWT should have exactly 3 parts separated by dots
    const parts = token.split('.')
    if (parts.length !== 3) return false

    // Each part should be base64url encoded (non-empty)
    return parts.every((part) => part.length > 0 && /^[A-Za-z0-9_-]+$/.test(part))
}

export function sendAuthError(res: Response, message: string): void {
    res.status(401).json({
        jsonrpc: '2.0',
        error: {
            code: -32001,
            message,
        },
        id: null,
    })
}

// Extend Request interface to include auth data
declare global {
    namespace Express {
        interface Request {
            mcpAuth?: {
                authorized: boolean
                method: 'jwt'
                identifier?: string
                tokenId?: string // jti claim for token tracking
                issuedAt?: number // iat claim
                expiresAt?: number // exp claim
            }
        }
    }
}
