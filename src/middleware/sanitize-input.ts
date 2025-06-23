import type { NextFunction, Request, Response } from 'express'

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
