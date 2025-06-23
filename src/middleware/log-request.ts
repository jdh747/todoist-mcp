import type { NextFunction, Request, Response } from 'express'
import { logger } from '../utils/logger.js'

export function logRequest(req: Request, res: Response, next: NextFunction): void {
    const start = Date.now()

    res.on('finish', () => {
        const duration = Date.now() - start
        logger.info('Request completed', {
            method: req.method,
            url: req.url,
            statusCode: res.statusCode,
            duration: `${duration}ms`,
            userAgent: req.get('User-Agent'),
            ip: req.ip || req.socket?.remoteAddress,
        })
    })

    next()
}
