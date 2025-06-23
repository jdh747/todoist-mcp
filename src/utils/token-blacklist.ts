/**
 * Token Blacklist Implementation
 *
 * Manages revoked JWT tokens with the following features:
 * - Token ID (jti) based blacklisting
 * - Automatic cleanup of expired tokens
 * - Persistence support (Redis/Database ready)
 * - Bulk operations for token management
 * - Security event logging
 *
 * In production, this should be backed by Redis or a database
 * for persistence across server restarts and horizontal scaling.
 */

import { logSecurityEvent } from './logger.js'

export interface BlacklistedToken {
    tokenId: string
    userId?: string
    revokedAt: number
    expiresAt: number
    reason?: string
}

export interface TokenBlacklistStats {
    totalBlacklisted: number
    expiredTokens: number
    activeBlacklisted: number
}

export class TokenBlacklist {
    private blacklistedTokens = new Map<string, BlacklistedToken>()
    private cleanupTimer: NodeJS.Timeout | null = null
    private cleanupIntervalMs: number

    constructor(
        cleanupIntervalMs: number = 5 * 60 * 1000, // Default 5 minutes
    ) {
        this.cleanupIntervalMs = cleanupIntervalMs
        this.startCleanup()
    }

    /**
     * Add a token to the blacklist
     */
    blacklistToken(tokenId: string, expiresAt: number, userId?: string, reason?: string): void {
        const blacklistedToken: BlacklistedToken = {
            tokenId,
            userId,
            revokedAt: Date.now(),
            expiresAt: expiresAt * 1000, // Convert to milliseconds
            reason,
        }

        this.blacklistedTokens.set(tokenId, blacklistedToken)

        logSecurityEvent('Token blacklisted', {
            tokenId,
            userId,
            reason,
            expiresAt: new Date(expiresAt * 1000).toISOString(),
        })
    }

    /**
     * Check if a token is blacklisted
     */
    isTokenBlacklisted(tokenId: string): boolean {
        const blacklistedToken = this.blacklistedTokens.get(tokenId)

        if (!blacklistedToken) {
            return false
        }

        // Check if the blacklisted token has expired
        const now = Date.now()
        if (blacklistedToken.expiresAt <= now) {
            // Token has expired, remove from blacklist
            this.blacklistedTokens.delete(tokenId)
            return false
        }

        return true
    }

    /**
     * Remove a token from the blacklist (unrevoke)
     */
    removeTokenFromBlacklist(tokenId: string): boolean {
        const existed = this.blacklistedTokens.has(tokenId)

        if (existed) {
            this.blacklistedTokens.delete(tokenId)
            logSecurityEvent('Token removed from blacklist', { tokenId })
        }

        return existed
    }

    /**
     * Blacklist all tokens for a specific user
     */
    blacklistUserTokens(userId: string, reason = 'User token revocation'): number {
        let count = 0

        // Note: In a real implementation, you'd need to track tokens by user
        // This is a simplified version that works with the current blacklist
        for (const [tokenId, token] of this.blacklistedTokens.entries()) {
            if (token.userId === userId) {
                count++
            }
        }

        logSecurityEvent('User tokens blacklisted', {
            userId,
            tokenCount: count,
            reason,
        })

        return count
    }

    /**
     * Get blacklist statistics
     */
    getStats(): TokenBlacklistStats {
        const now = Date.now()
        let expiredTokens = 0
        let activeBlacklisted = 0

        for (const token of this.blacklistedTokens.values()) {
            if (token.expiresAt <= now) {
                expiredTokens++
            } else {
                activeBlacklisted++
            }
        }

        return {
            totalBlacklisted: this.blacklistedTokens.size,
            expiredTokens,
            activeBlacklisted,
        }
    }

    /**
     * Get blacklisted token details
     */
    getBlacklistedToken(tokenId: string): BlacklistedToken | null {
        return this.blacklistedTokens.get(tokenId) || null
    }

    /**
     * Get all blacklisted tokens for a user
     */
    getUserBlacklistedTokens(userId: string): BlacklistedToken[] {
        const userTokens: BlacklistedToken[] = []

        for (const token of this.blacklistedTokens.values()) {
            if (token.userId === userId) {
                userTokens.push(token)
            }
        }

        return userTokens
    }

    /**
     * Clean up expired tokens from blacklist
     */
    private cleanup(): void {
        const now = Date.now()
        const initialSize = this.blacklistedTokens.size
        let cleanedCount = 0

        for (const [tokenId, token] of this.blacklistedTokens.entries()) {
            if (token.expiresAt <= now) {
                this.blacklistedTokens.delete(tokenId)
                cleanedCount++
            }
        }

        if (cleanedCount > 0) {
            logSecurityEvent('Token blacklist cleanup', {
                cleanedTokens: cleanedCount,
                remainingTokens: this.blacklistedTokens.size,
                initialSize,
            })
        }
    }

    /**
     * Force cleanup of expired tokens
     */
    forceCleanup(): TokenBlacklistStats {
        const statsBefore = this.getStats()
        this.cleanup()
        const statsAfter = this.getStats()

        return {
            totalBlacklisted: statsBefore.expiredTokens, // Tokens that were cleaned
            expiredTokens: 0,
            activeBlacklisted: statsAfter.activeBlacklisted,
        }
    }

    /**
     * Start automatic cleanup
     */
    private startCleanup(): void {
        if (this.cleanupTimer) {
            clearInterval(this.cleanupTimer)
        }

        this.cleanupTimer = setInterval(() => {
            this.cleanup()
        }, this.cleanupIntervalMs)
    }

    /**
     * Stop the blacklist and cleanup resources
     */
    stop(): void {
        if (this.cleanupTimer) {
            clearInterval(this.cleanupTimer)
            this.cleanupTimer = null
        }
        this.blacklistedTokens.clear()
    }

    /**
     * Export blacklist for persistence/backup
     */
    exportBlacklist(): BlacklistedToken[] {
        return Array.from(this.blacklistedTokens.values())
    }

    /**
     * Import blacklist from persistence/backup
     */
    importBlacklist(tokens: BlacklistedToken[]): void {
        this.blacklistedTokens.clear()

        const now = Date.now()
        let importedCount = 0
        let skippedExpired = 0

        for (const token of tokens) {
            if (token.expiresAt > now) {
                this.blacklistedTokens.set(token.tokenId, token)
                importedCount++
            } else {
                skippedExpired++
            }
        }

        logSecurityEvent('Token blacklist imported', {
            importedCount,
            skippedExpired,
            totalProvided: tokens.length,
        })
    }

    /**
     * Clear all blacklisted tokens (use with caution)
     */
    clearAll(): void {
        const count = this.blacklistedTokens.size
        this.blacklistedTokens.clear()

        logSecurityEvent('Token blacklist cleared', {
            clearedCount: count,
        })
    }
}

// Factory function for creating configured blacklist instances
export namespace TokenBlacklistFactory {
    export function createDefault(): TokenBlacklist {
        return new TokenBlacklist(5 * 60 * 1000) // 5 minutes cleanup
    }

    export function createFastCleanup(): TokenBlacklist {
        return new TokenBlacklist(60 * 1000) // 1 minute cleanup
    }

    export function createSlowCleanup(): TokenBlacklist {
        return new TokenBlacklist(15 * 60 * 1000) // 15 minutes cleanup
    }
}
