import type { NextFunction, Request, Response } from 'express'
import winston from 'winston'
import { SECURITY_CONFIG } from '../config/security.js'

// Custom formatter for better error stack trace display
const customConsoleFormat = winston.format.printf(
    ({ level, message, timestamp, stack, ...meta }) => {
        let log = `${timestamp} [${level}]: ${message}`

        // If there's a stack trace, format it properly with newlines
        if (stack) {
            log += `\n${stack}`
        }

        // Add any additional metadata
        const metaStr = Object.keys(meta).length ? `\n${JSON.stringify(meta, null, 2)}` : ''
        return log + metaStr
    },
)

// Create logger instance
export const logger = winston.createLogger({
    level: SECURITY_CONFIG.LOG_LEVEL,
    format: winston.format.combine(
        winston.format.timestamp(),
        winston.format.errors({ stack: true }),
        SECURITY_CONFIG.NODE_ENV === 'production'
            ? winston.format.json()
            : winston.format.combine(winston.format.colorize(), customConsoleFormat),
    ),
    defaultMeta: { service: 'todoist-mcp' },
    transports: [
        new winston.transports.Console(),
        // In production, you might want to add file transports
        ...(SECURITY_CONFIG.NODE_ENV === 'production'
            ? [
                  new winston.transports.File({ filename: 'error.log', level: 'error' }),
                  new winston.transports.File({ filename: 'combined.log' }),
              ]
            : []),
    ],
})

// Security event logging
export function logSecurityEvent(
    event: string,
    details: Record<string, unknown>,
    level: 'warn' | 'error' = 'warn',
) {
    logger.log(level, `SECURITY EVENT: ${event}`, {
        timestamp: new Date().toISOString(),
        event,
        ...details,
    })
}

// Request logging middleware
export function logRequest(req: Request, res: Response, next: NextFunction) {
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
