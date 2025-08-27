/**
 * Todoist API Manager for Per-User Token Management
 *
 * Manages dynamic TodoistApi instances for each authenticated user.
 * Creates API clients on-demand using user-specific tokens from the
 * encrypted token storage system.
 *
 * Features:
 * - Dynamic API client creation per user
 * - Token validation and error handling
 * - API client caching for performance
 * - Automatic cleanup of expired/invalid clients
 */

import { TodoistApi } from '@doist/todoist-api-typescript'
import type { Request } from 'express'
import { logSecurityEvent } from './logger.js'
import { UserTokenStorage } from './user-token-storage.js'

export class TodoistApiManager {
    private userTokenStorage: UserTokenStorage
    private apiClientCache: Map<string, { api: TodoistApi; lastUsed: number }> = new Map()
    private readonly CACHE_TTL = 3600000 // 1 hour

    constructor() {
        this.userTokenStorage = new UserTokenStorage()
        
        // Clean up expired API clients every 10 minutes
        setInterval(() => {
            this.cleanupExpiredClients()
        }, 600000)
    }

    /**
     * Get TodoistApi instance for the authenticated user
     * 
     * Extracts user token from request and creates/returns cached API client.
     * Requires request to have been processed by OAuth authentication middleware.
     */
    async getApiForUser(req: Request): Promise<TodoistApi> {
        // Ensure user is authenticated and has Todoist connection
        if (!req.mcpAuth?.authorized || !req.mcpAuth.identifier) {
            throw new Error('User not authenticated')
        }

        if (!req.todoistAuth?.todoistToken) {
            throw new Error('Todoist account not connected')
        }

        const userId = req.mcpAuth.identifier
        const todoistToken = req.todoistAuth.todoistToken

        // Check cache first
        const cachedClient = this.apiClientCache.get(userId)
        if (cachedClient && Date.now() - cachedClient.lastUsed < this.CACHE_TTL) {
            cachedClient.lastUsed = Date.now()
            return cachedClient.api
        }

        // Create new API client
        const api = new TodoistApi(todoistToken)

        // Validate the API client works by making a test call
        try {
            await this.validateApiClient(api)
        } catch (error) {
            logSecurityEvent('Todoist API validation failed', {
                userId,
                error: error instanceof Error ? error.message : 'Unknown error',
            }, 'error')
            
            // Remove invalid token from storage
            await this.userTokenStorage.removeUserToken(userId)
            
            throw new Error('Todoist token is invalid or expired')
        }

        // Cache the validated API client
        this.apiClientCache.set(userId, {
            api,
            lastUsed: Date.now(),
        })

        logSecurityEvent('Todoist API client created', {
            userId,
            todoistUserId: req.todoistAuth.todoistUserId,
        })

        return api
    }

    /**
     * Get TodoistApi instance for a specific user (for admin/background operations)
     */
    async getApiForUserId(userId: string): Promise<TodoistApi> {
        const userTokenData = await this.userTokenStorage.getUserToken(userId)
        if (!userTokenData) {
            throw new Error('User has no Todoist connection')
        }

        // Check cache first
        const cachedClient = this.apiClientCache.get(userId)
        if (cachedClient && Date.now() - cachedClient.lastUsed < this.CACHE_TTL) {
            cachedClient.lastUsed = Date.now()
            return cachedClient.api
        }

        // Create new API client
        const api = new TodoistApi(userTokenData.todoistToken)

        // Validate the API client
        try {
            await this.validateApiClient(api)
        } catch (error) {
            logSecurityEvent('Todoist API validation failed', {
                userId,
                error: error instanceof Error ? error.message : 'Unknown error',
            }, 'error')
            
            // Remove invalid token from storage
            await this.userTokenStorage.removeUserToken(userId)
            
            throw new Error('Todoist token is invalid or expired')
        }

        // Cache the validated API client
        this.apiClientCache.set(userId, {
            api,
            lastUsed: Date.now(),
        })

        return api
    }

    /**
     * Validate API client by making a lightweight test call
     */
    private async validateApiClient(api: TodoistApi): Promise<void> {
        try {
            // Make a lightweight API call to validate the token
            await api.getProjects()
        } catch (error) {
            throw new Error(`API validation failed: ${error instanceof Error ? error.message : 'Unknown error'}`)
        }
    }

    /**
     * Remove API client from cache (e.g., when user disconnects)
     */
    removeApiClient(userId: string): void {
        this.apiClientCache.delete(userId)
        
        logSecurityEvent('Todoist API client removed', {
            userId,
        })
    }

    /**
     * Clean up expired API clients from cache
     */
    private cleanupExpiredClients(): void {
        const now = Date.now()
        const expiredUsers: string[] = []

        for (const [userId, client] of this.apiClientCache.entries()) {
            if (now - client.lastUsed > this.CACHE_TTL) {
                expiredUsers.push(userId)
            }
        }

        for (const userId of expiredUsers) {
            this.apiClientCache.delete(userId)
        }

        if (expiredUsers.length > 0) {
            logSecurityEvent('Cleaned up expired API clients', {
                count: expiredUsers.length,
                expiredUsers,
            })
        }
    }

    /**
     * Get cache statistics (for monitoring)
     */
    getCacheStats(): { totalClients: number; activeClients: number } {
        const now = Date.now()
        const activeClients = Array.from(this.apiClientCache.values())
            .filter(client => now - client.lastUsed < this.CACHE_TTL)
            .length

        return {
            totalClients: this.apiClientCache.size,
            activeClients,
        }
    }
}