import type { NextFunction, Request, Response } from 'express'
import { z } from 'zod'
import { SECURITY_CONFIG } from '../config/security.js'
import { logSecurityEvent } from '../utils/logger.js'

// JSON-RPC 2.0 schema validation using Zod
const jsonRpcSchema = z.object({
    jsonrpc: z.literal('2.0'),
    method: z.string().min(1).max(100),
    id: z.union([z.string(), z.number(), z.null()]).optional(),
    params: z.record(z.unknown()).optional(),
})

// Security validation for payloads
function validatePayloadSecurity(payload: unknown): void {
    const jsonString = JSON.stringify(payload)

    // Check payload size (50KB limit)
    if (jsonString.length > SECURITY_CONFIG.MAX_REQUEST_PAYLOAD_SIZE) {
        throw new Error('Request payload too large')
    }

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

        logSecurityEvent('Input validation failed', {
            ip: req.ip,
            error: errorMessage,
            body: req.body,
            url: req.url,
        })

        res.status(400).json({
            jsonrpc: '2.0',
            error: {
                code: -32602,
                message: 'Invalid params',
                data: { details: errorMessage },
            },
            id: req.body?.id || null,
        })
    }
}

// Request size limiting middleware
export function limitRequestSize(req: Request, res: Response, next: NextFunction): void {
    // Check Content-Length header for early rejection
    const contentLength = req.get('Content-Length')

    if (
        contentLength &&
        Number.parseInt(contentLength, 10) > SECURITY_CONFIG.MAX_REQUEST_PAYLOAD_SIZE
    ) {
        logSecurityEvent('Request size exceeded', {
            ip: req.ip,
            contentLength,
            url: req.url,
        })

        res.status(413).json({
            jsonrpc: '2.0',
            error: {
                code: -32000,
                message: 'Request entity too large',
            },
            id: null,
        })

        return
    }

    next()
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
