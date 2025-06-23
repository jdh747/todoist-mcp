import type { Response } from 'express'
import { ERROR_CODES } from '../constants/security.js'

export interface JsonRpcError {
    jsonrpc: '2.0'
    error: {
        code: number
        message: string
        data?: unknown
    }
    id: null
}

export interface SecurityEventData {
    ip?: string
    userAgent?: string
    url?: string
    method?: string
    origin?: string
    [key: string]: unknown
}

export function createJsonRpcError(code: number, message: string, data?: unknown): JsonRpcError {
    const error: JsonRpcError['error'] = {
        code,
        message,
    }

    if (data !== undefined) {
        error.data = data
    }

    return {
        jsonrpc: '2.0',
        error,
        id: null,
    }
}

export function sendSecurityError(
    res: Response,
    statusCode: number,
    errorCode: number,
    message: string,
    data?: unknown,
): void {
    if (!res.headersSent) {
        res.status(statusCode).json(createJsonRpcError(errorCode, message, data))
    }
}

export function sendRateLimitError(res: Response): void {
    sendSecurityError(
        res,
        429,
        ERROR_CODES.RATE_LIMIT_EXCEEDED,
        'Too many requests, please try again later',
    )
}

export function sendTimeoutError(res: Response): void {
    sendSecurityError(res, 408, ERROR_CODES.REQUEST_TIMEOUT, 'Request timeout')
}

export function sendCorsError(res: Response): void {
    sendSecurityError(res, 403, ERROR_CODES.CORS_VIOLATION, 'Not allowed by CORS')
}

export function sendPayloadTooLargeError(res: Response): void {
    sendSecurityError(res, 413, ERROR_CODES.PAYLOAD_TOO_LARGE, 'Request payload too large')
}

export function sendMethodNotAllowedError(res: Response): void {
    sendSecurityError(res, 405, ERROR_CODES.METHOD_NOT_ALLOWED, 'Method not allowed')
}

export function sendAuthenticationError(res: Response, message = 'Authentication failed'): void {
    sendSecurityError(res, 401, ERROR_CODES.UNAUTHORIZED, message)
}

export function sendJwtError(res: Response, errorCode: number, message: string): void {
    sendSecurityError(res, 401, errorCode, message)
}

export function sendJwtAuthError(res: Response, message = 'Authentication failed'): void {
    sendSecurityError(res, 401, ERROR_CODES.UNAUTHORIZED, message)
}

export function sendInternalServerError(res: Response): void {
    sendSecurityError(res, 500, ERROR_CODES.INTERNAL_ERROR, 'Internal server error')
}
