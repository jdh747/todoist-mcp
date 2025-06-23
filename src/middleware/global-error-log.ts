import type { NextFunction, Request, Response } from 'express'
import { logger } from '../utils/logger.js'

export function globalErrorLog(
    err: Error | string | unknown,
    req: Request,
    res: Response,
    next: NextFunction,
) {
    let errorMessage: string
    let errorStack: string | undefined

    if (err instanceof Error) {
        errorMessage = err.message
        errorStack = err.stack
    } else if (typeof err === 'string') {
        errorMessage = err
    } else {
        errorMessage = 'Unknown error'
    }

    logger.error('Unhandled error:', {
        error: errorMessage,
        stack: errorStack,
        url: req.url,
        method: req.method,
        ip: req.ip,
    })

    if (!res.headersSent) {
        res.status(500).json({
            jsonrpc: '2.0',
            error: {
                code: -32603,
                message: 'Internal server error',
            },
            id: null,
        })
    }

    next()
}
