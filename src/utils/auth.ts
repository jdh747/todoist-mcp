import crypto from 'node:crypto'
import type { Response } from 'express'
import jwt from 'jsonwebtoken'
import { SECURITY_CONFIG } from '../config/security.js'
import { JWT_CONSTANTS } from '../constants/security.js'
import { sendAuthenticationError } from './security-responses.js'

export function generateToken(
    payload: {
        sub: string // Subject (user identifier)
        [key: string]: unknown // Additional claims
    },
    expiresIn: string = SECURITY_CONFIG.JWT_EXPIRES_IN,
    jwtSecret?: string,
): string {
    const now = Math.floor(Date.now() / 1000)

    // Generate cryptographically secure unique token ID for tracking
    const randomBytes = crypto.randomBytes(16).toString('hex')
    const tokenId = `${payload.sub}_${now}_${randomBytes}`

    const tokenPayload = {
        ...payload,
        iss: JWT_CONSTANTS.ISSUER, // Issuer
        aud: JWT_CONSTANTS.AUDIENCE, // Audience
        iat: now, // Issued at
        jti: tokenId, // JWT ID for token tracking
        // nbf (not before) can be added if needed
    }

    const secretToUse = jwtSecret || SECURITY_CONFIG.JWT_SECRET
    return jwt.sign(tokenPayload, secretToUse, {
        expiresIn,
        algorithm: JWT_CONSTANTS.ALGORITHM, // Explicitly specify algorithm
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
    sendAuthenticationError(res, message)
}

export function timingSafeStringEqual(a: string, b: string): boolean {
    try {
        // Constant-time comparison of fixed-length buffers
        return crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b))
    } catch {
        return false
    }
}

// Extend Request interface to include auth data
declare global {
    namespace Express {
        interface Request {
            mcpAuth?: {
                authorized: boolean
                method: 'jwt' | 'oauth2.1'
                identifier?: string
                tokenId?: string // jti claim for token tracking (JWT only)
                issuedAt?: number // iat claim
                expiresAt?: number // exp claim
                scopes?: string[] // OAuth scopes
                clientId?: string // OAuth client ID
                username?: string // OAuth username
            }
            todoistAuth?: {
                todoistToken: string
                todoistUserId: string
                connectedAt: Date
                lastUsed: Date
            }
        }
    }
}
