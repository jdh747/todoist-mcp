import type { Request, Response } from 'express'
import { SECURITY_CONFIG } from '../../config/security.js'
import { SECURITY_EVENT_TYPES } from '../../constants/security.js'
import type { RateLimitConfig } from '../../types/security.js'
import { logSecurityEvent } from '../../utils/logger.js'
import { sendRateLimitError } from '../../utils/security-responses.js'

export const rateLimitConfig: RateLimitConfig = {
    windowMs: SECURITY_CONFIG.RATE_LIMIT_WINDOW_MS,
    max: SECURITY_CONFIG.RATE_LIMIT_MAX_REQUESTS,
    message: {}, // Will be handled by custom handler
    standardHeaders: true,
    legacyHeaders: false,
    handler: (req: Request, res: Response) => {
        logSecurityEvent(SECURITY_EVENT_TYPES.RATE_LIMIT_EXCEEDED, {
            ip: req.ip,
            userAgent: req.get('User-Agent'),
            url: req.url,
            method: req.method,
        })
        sendRateLimitError(res)
    },
}
