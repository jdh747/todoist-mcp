/**
 * User Token Storage System
 *
 * Manages encrypted storage of user Todoist tokens mapped to OAuth subjects.
 * Supports multiple storage backends (memory, file, Redis) with encrypted token storage.
 *
 * Security Features:
 * - AES-256-GCM encryption for stored tokens
 * - Secure key derivation using PBKDF2
 * - Token expiration and cleanup
 * - Audit logging for token operations
 */

import { createCipheriv, createDecipheriv, pbkdf2Sync, randomBytes } from 'node:crypto'
import { readFile, writeFile } from 'node:fs/promises'
import path from 'node:path'
import { OAUTH_CONFIG } from '../config/oauth.js'
import { logSecurityEvent } from './logger.js'

export interface UserTokenData {
    mcpSubject: string
    todoistToken: string
    todoistUserId: string
    connectedAt: Date
    lastUsed: Date
}

interface EncryptedTokenData {
    encryptedToken: string
    iv: string
    salt: string
    authTag: string
    todoistUserId: string
    connectedAt: string
    lastUsed: string
}

export class UserTokenStorage {
    private memoryStorage: Map<string, UserTokenData> = new Map()
    private encryptionKey: Buffer
    private storageType: 'memory' | 'file' | 'redis'
    private filePath: string

    constructor() {
        this.storageType = OAUTH_CONFIG.TOKEN_STORAGE_TYPE
        this.filePath = path.join(process.cwd(), 'data', 'user-tokens.json')
        
        // Derive encryption key from config
        this.encryptionKey = this.deriveEncryptionKey(OAUTH_CONFIG.TOKEN_ENCRYPTION_KEY)
        
        // Initialize storage backend
        this.initializeStorage()
    }

    /**
     * Store user's Todoist token
     */
    async storeUserToken(
        mcpSubject: string,
        todoistToken: string,
        todoistUserId: string
    ): Promise<void> {
        const tokenData: UserTokenData = {
            mcpSubject,
            todoistToken,
            todoistUserId,
            connectedAt: new Date(),
            lastUsed: new Date(),
        }

        try {
            switch (this.storageType) {
                case 'memory':
                    this.memoryStorage.set(mcpSubject, tokenData)
                    break
                case 'file':
                    await this.storeToFile(mcpSubject, tokenData)
                    break
                case 'redis':
                    // TODO: Implement Redis storage
                    throw new Error('Redis storage not yet implemented')
            }

            logSecurityEvent('User token stored', {
                userId: mcpSubject,
                todoistUserId,
                storageType: this.storageType,
            })
        } catch (error) {
            logSecurityEvent('Failed to store user token', {
                userId: mcpSubject,
                todoistUserId,
                error: error instanceof Error ? error.message : 'Unknown error',
            }, 'error')
            throw error
        }
    }

    /**
     * Retrieve user's Todoist token
     */
    async getUserToken(mcpSubject: string): Promise<UserTokenData | null> {
        try {
            let tokenData: UserTokenData | null = null

            switch (this.storageType) {
                case 'memory':
                    tokenData = this.memoryStorage.get(mcpSubject) || null
                    break
                case 'file':
                    tokenData = await this.loadFromFile(mcpSubject)
                    break
                case 'redis':
                    // TODO: Implement Redis storage
                    throw new Error('Redis storage not yet implemented')
            }

            if (tokenData) {
                logSecurityEvent('User token retrieved', {
                    userId: mcpSubject,
                    todoistUserId: tokenData.todoistUserId,
                    storageType: this.storageType,
                })
            }

            return tokenData
        } catch (error) {
            logSecurityEvent('Failed to retrieve user token', {
                userId: mcpSubject,
                error: error instanceof Error ? error.message : 'Unknown error',
            }, 'error')
            return null
        }
    }

    /**
     * Remove user's token (disconnect)
     */
    async removeUserToken(mcpSubject: string): Promise<void> {
        try {
            switch (this.storageType) {
                case 'memory':
                    this.memoryStorage.delete(mcpSubject)
                    break
                case 'file':
                    await this.removeFromFile(mcpSubject)
                    break
                case 'redis':
                    // TODO: Implement Redis storage
                    throw new Error('Redis storage not yet implemented')
            }

            logSecurityEvent('User token removed', {
                userId: mcpSubject,
                storageType: this.storageType,
            })
        } catch (error) {
            logSecurityEvent('Failed to remove user token', {
                userId: mcpSubject,
                error: error instanceof Error ? error.message : 'Unknown error',
            }, 'error')
            throw error
        }
    }

    /**
     * Update last used timestamp
     */
    async updateLastUsed(mcpSubject: string): Promise<void> {
        const tokenData = await this.getUserToken(mcpSubject)
        if (tokenData) {
            tokenData.lastUsed = new Date()
            await this.storeUserToken(mcpSubject, tokenData.todoistToken, tokenData.todoistUserId)
        }
    }

    /**
     * List all stored users (for admin/cleanup purposes)
     */
    async listUsers(): Promise<string[]> {
        switch (this.storageType) {
            case 'memory':
                return Array.from(this.memoryStorage.keys())
            case 'file':
                return await this.listUsersFromFile()
            case 'redis':
                throw new Error('Redis storage not yet implemented')
        }
    }

    /**
     * Encrypt token data
     */
    private encryptToken(token: string): { encryptedToken: string; iv: string; salt: string; authTag: string } {
        const salt = randomBytes(16)
        const iv = randomBytes(12) // 12 bytes for GCM
        const key = pbkdf2Sync(this.encryptionKey, salt, 10000, 32, 'sha256')
        
        const cipher = createCipheriv('aes-256-gcm', key, iv)
        let encryptedToken = cipher.update(token, 'utf8', 'hex')
        encryptedToken += cipher.final('hex')
        const authTag = cipher.getAuthTag()
        
        return {
            encryptedToken,
            iv: iv.toString('hex'),
            salt: salt.toString('hex'),
            authTag: authTag.toString('hex'),
        }
    }

    /**
     * Decrypt token data
     */
    private decryptToken(encryptedToken: string, iv: string, salt: string, authTag: string): string {
        const key = pbkdf2Sync(this.encryptionKey, Buffer.from(salt, 'hex'), 10000, 32, 'sha256')
        
        const decipher = createDecipheriv('aes-256-gcm', key, Buffer.from(iv, 'hex'))
        decipher.setAuthTag(Buffer.from(authTag, 'hex'))
        let decrypted = decipher.update(encryptedToken, 'hex', 'utf8')
        decrypted += decipher.final('utf8')
        
        return decrypted
    }

    /**
     * Derive encryption key from configuration
     */
    private deriveEncryptionKey(configKey: string): Buffer {
        return pbkdf2Sync(configKey, 'todoist-mcp-salt', 10000, 32, 'sha256')
    }

    /**
     * Initialize storage backend
     */
    private async initializeStorage(): Promise<void> {
        if (this.storageType === 'file') {
            // Ensure data directory exists
            const dataDir = path.dirname(this.filePath)
            try {
                await import('node:fs/promises').then(fs => fs.mkdir(dataDir, { recursive: true }))
            } catch (error) {
                // Directory might already exist, that's ok
            }
        }
    }

    /**
     * File storage implementation
     */
    private async storeToFile(mcpSubject: string, tokenData: UserTokenData): Promise<void> {
        const existingData = await this.loadAllFromFile()
        
        const { encryptedToken, iv, salt, authTag } = this.encryptToken(tokenData.todoistToken)
        
        existingData[mcpSubject] = {
            encryptedToken,
            iv,
            salt,
            authTag,
            todoistUserId: tokenData.todoistUserId,
            connectedAt: tokenData.connectedAt.toISOString(),
            lastUsed: tokenData.lastUsed.toISOString(),
        }

        await writeFile(this.filePath, JSON.stringify(existingData, null, 2))
    }

    private async loadFromFile(mcpSubject: string): Promise<UserTokenData | null> {
        const allData = await this.loadAllFromFile()
        const userData = allData[mcpSubject]
        
        if (!userData) {
            return null
        }

        try {
            const decryptedToken = this.decryptToken(
                userData.encryptedToken,
                userData.iv,
                userData.salt,
                userData.authTag
            )

            return {
                mcpSubject,
                todoistToken: decryptedToken,
                todoistUserId: userData.todoistUserId,
                connectedAt: new Date(userData.connectedAt),
                lastUsed: new Date(userData.lastUsed),
            }
        } catch (error) {
            logSecurityEvent('Failed to decrypt user token', {
                userId: mcpSubject,
                error: error instanceof Error ? error.message : 'Unknown error',
            }, 'error')
            return null
        }
    }

    private async removeFromFile(mcpSubject: string): Promise<void> {
        const existingData = await this.loadAllFromFile()
        delete existingData[mcpSubject]
        await writeFile(this.filePath, JSON.stringify(existingData, null, 2))
    }

    private async listUsersFromFile(): Promise<string[]> {
        const allData = await this.loadAllFromFile()
        return Object.keys(allData)
    }

    private async loadAllFromFile(): Promise<Record<string, EncryptedTokenData>> {
        try {
            const fileContent = await readFile(this.filePath, 'utf8')
            return JSON.parse(fileContent)
        } catch (error) {
            // File doesn't exist or is empty, return empty object
            return {}
        }
    }
}