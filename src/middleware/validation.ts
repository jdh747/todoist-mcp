import type { NextFunction, Request, Response } from 'express'
import { z } from 'zod'
import { ERROR_CODES, SECURITY_EVENT_TYPES } from '../constants/security.js'
import { logSecurityEvent } from '../utils/logger.js'
import { sendSecurityError } from '../utils/security-responses.js'

// JSON-RPC 2.0 schema validation using Zod
const jsonRpcSchema = z.object({
    jsonrpc: z.literal('2.0'),
    method: z.string().min(1).max(100),
    id: z.union([z.string(), z.number(), z.null()]).optional(),
    params: z.record(z.unknown()).optional(),
})

// Security validation for payloads (structural validation only)
function validatePayloadSecurity(payload: unknown): void {
    // Check for deeply nested objects (potential DoS)
    function checkDepth(obj: unknown, depth = 0): void {
        if (depth > 10) {
            throw new Error('Request payload too deeply nested')
        }
        if (typeof obj === 'object' && obj !== null) {
            if (Array.isArray(obj)) {
                for (const item of obj) {
                    checkDepth(item, depth + 1)
                }
            } else {
                for (const value of Object.values(obj)) {
                    checkDepth(value, depth + 1)
                }
            }
        }
    }

    checkDepth(payload)
}

// Validation middleware for MCP requests
export function validateMCPRequest(req: Request, res: Response, next: NextFunction): void {
    try {
        // Validate JSON-RPC structure
        const validatedData = jsonRpcSchema.parse(req.body)

        // Security validation
        validatePayloadSecurity(req.body)

        // Store validated data
        req.body = validatedData

        next()
    } catch (error) {
        const errorMessage = error instanceof Error ? error.message : 'Validation failed'

        logSecurityEvent(SECURITY_EVENT_TYPES.VALIDATION_ERROR, {
            ip: req.ip,
            error: errorMessage,
            body: req.body,
            url: req.url,
        })

        sendSecurityError(res, 400, ERROR_CODES.VALIDATION_ERROR, 'Invalid params', {
            details: errorMessage,
        })
    }
}

// Input sanitization for JSON-RPC requests
export function sanitizeInput(req: Request, _res: Response, next: NextFunction): void {
    if (req.body && typeof req.body === 'object') {
        req.body = sanitizeObject(req.body)
    }

    next()
}

function sanitizeObject(obj: unknown): unknown {
    if (typeof obj !== 'object' || obj === null) {
        return obj
    }

    if (Array.isArray(obj)) {
        return obj.map(sanitizeObject)
    }

    const sanitized: Record<string, unknown> = {}
    for (const [key, value] of Object.entries(obj)) {
        // Remove potentially dangerous properties
        if (key.startsWith('__') || key === 'constructor' || key === 'prototype') {
            continue
        }

        // For JSON-RPC, we don't need HTML encoding as this isn't web content
        // Just pass through the values after prototype pollution checks
        sanitized[key] = sanitizeObject(value)
    }

    return sanitized
}
