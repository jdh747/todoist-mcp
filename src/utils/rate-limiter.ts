/**
 * Rate Limiter Implementation
 *
 * Provides flexible rate limiting with different strategies:
 * - Sliding window
 * - Fixed window
 * - Token bucket (future enhancement)
 *
 * Features:
 * - Configurable time windows and limits
 * - Automatic cleanup of expired entries
 * - Multiple rate limit categories (auth, api, etc.)
 * - Memory efficient with periodic cleanup
 */

import { logSecurityEvent } from './logger.js'

export interface RateLimitConfig {
    maxRequests: number
    windowMs: number
    cleanupIntervalMs?: number
}

export interface RateLimitResult {
    allowed: boolean
    remaining: number
    resetTime: number
    totalRequests: number
}

interface RateLimitEntry {
    count: number
    firstRequest: number
    lastRequest: number
}

export class RateLimiter {
    private attempts = new Map<string, RateLimitEntry>()
    private cleanupTimer: NodeJS.Timeout | null = null
    private config: Required<RateLimitConfig>

    constructor(config: RateLimitConfig) {
        this.config = {
            cleanupIntervalMs: 60000, // Default 1 minute cleanup
            ...config,
        }

        this.startCleanup()
    }

    /**
     * Check if a key (IP, user ID, etc.) is rate limited
     */
    checkRateLimit(key: string): RateLimitResult {
        const now = Date.now()
        const entry = this.attempts.get(key)

        if (!entry) {
            // First request
            this.attempts.set(key, {
                count: 1,
                firstRequest: now,
                lastRequest: now,
            })

            return {
                allowed: true,
                remaining: this.config.maxRequests - 1,
                resetTime: now + this.config.windowMs,
                totalRequests: 1,
            }
        }

        // Check if window has expired
        if (now - entry.firstRequest > this.config.windowMs) {
            // Reset the window
            this.attempts.set(key, {
                count: 1,
                firstRequest: now,
                lastRequest: now,
            })

            return {
                allowed: true,
                remaining: this.config.maxRequests - 1,
                resetTime: now + this.config.windowMs,
                totalRequests: 1,
            }
        }

        // Increment counter
        entry.count++
        entry.lastRequest = now

        const allowed = entry.count <= this.config.maxRequests
        const remaining = Math.max(0, this.config.maxRequests - entry.count)
        const resetTime = entry.firstRequest + this.config.windowMs

        if (!allowed) {
            logSecurityEvent('Rate limit exceeded', {
                key,
                attempts: entry.count,
                maxRequests: this.config.maxRequests,
                windowMs: this.config.windowMs,
            })
        }

        return {
            allowed,
            remaining,
            resetTime,
            totalRequests: entry.count,
        }
    }

    /**
     * Record a failed attempt (increments counter)
     */
    recordAttempt(key: string): RateLimitResult {
        return this.checkRateLimit(key)
    }

    /**
     * Check if key is currently rate limited (without incrementing)
     */
    isRateLimited(key: string): boolean {
        const now = Date.now()
        const entry = this.attempts.get(key)

        if (!entry) return false

        // Check if window has expired
        if (now - entry.firstRequest > this.config.windowMs) {
            return false
        }

        return entry.count >= this.config.maxRequests
    }

    /**
     * Reset rate limit for a specific key
     */
    resetRateLimit(key: string): void {
        this.attempts.delete(key)
        logSecurityEvent('Rate limit reset', { key })
    }

    /**
     * Get current stats for a key
     */
    getStats(key: string): RateLimitResult | null {
        const now = Date.now()
        const entry = this.attempts.get(key)

        if (!entry) return null

        // Check if window has expired
        if (now - entry.firstRequest > this.config.windowMs) {
            return null
        }

        return {
            allowed: entry.count <= this.config.maxRequests,
            remaining: Math.max(0, this.config.maxRequests - entry.count),
            resetTime: entry.firstRequest + this.config.windowMs,
            totalRequests: entry.count,
        }
    }

    /**
     * Start automatic cleanup of expired entries
     */
    private startCleanup(): void {
        if (this.cleanupTimer) {
            clearInterval(this.cleanupTimer)
        }

        this.cleanupTimer = setInterval(() => {
            this.cleanup()
        }, this.config.cleanupIntervalMs)
    }

    /**
     * Clean up expired entries
     */
    private cleanup(): void {
        const now = Date.now()
        let cleanedCount = 0

        for (const [key, entry] of this.attempts.entries()) {
            if (now - entry.firstRequest > this.config.windowMs) {
                this.attempts.delete(key)
                cleanedCount++
            }
        }

        if (cleanedCount > 0) {
            logSecurityEvent('Rate limiter cleanup', {
                cleanedEntries: cleanedCount,
                remainingEntries: this.attempts.size,
            })
        }
    }

    /**
     * Stop the rate limiter and cleanup resources
     */
    stop(): void {
        if (this.cleanupTimer) {
            clearInterval(this.cleanupTimer)
            this.cleanupTimer = null
        }
        this.attempts.clear()
    }

    /**
     * Get configuration
     */
    getConfig(): Required<RateLimitConfig> {
        return { ...this.config }
    }

    /**
     * Update configuration (restarts cleanup timer)
     */
    updateConfig(config: Partial<RateLimitConfig>): void {
        this.config = { ...this.config, ...config }
        this.startCleanup()
    }
}

// Factory function for common rate limiter configurations
export namespace RateLimiterFactory {
    export function createAuthLimiter(): RateLimiter {
        return new RateLimiter({
            maxRequests: 5,
            windowMs: 5 * 60 * 1000, // 5 minutes
            cleanupIntervalMs: 60 * 1000, // 1 minute
        })
    }

    export function createApiLimiter(): RateLimiter {
        return new RateLimiter({
            maxRequests: 100,
            windowMs: 60 * 1000, // 1 minute
            cleanupIntervalMs: 30 * 1000, // 30 seconds
        })
    }

    export function createStrictLimiter(): RateLimiter {
        return new RateLimiter({
            maxRequests: 1,
            windowMs: 60 * 1000, // 1 minute
            cleanupIntervalMs: 60 * 1000, // 1 minute
        })
    }
}
