import type { NextFunction, Request, Response } from 'express'
import { SECURITY_CONFIG } from '../../config/security.js'
import { SECURITY_EVENT_TYPES } from '../../constants/security.js'
import type { SecurityMiddleware } from '../../types/security.js'
import { logSecurityEvent } from '../../utils/logger.js'
import { sendTimeoutError } from '../../utils/security-responses.js'

export const requestTimeout: SecurityMiddleware = (
    req: Request,
    res: Response,
    next: NextFunction,
) => {
    const timeout = setTimeout(() => {
        if (!res.headersSent) {
            logSecurityEvent(SECURITY_EVENT_TYPES.REQUEST_TIMEOUT, {
                ip: req.ip,
                url: req.url,
                method: req.method,
                timeout: SECURITY_CONFIG.REQUEST_TIMEOUT_MS,
            })
            sendTimeoutError(res)
        }
    }, SECURITY_CONFIG.REQUEST_TIMEOUT_MS)

    const cleanup = () => {
        clearTimeout(timeout)
    }

    res.on('finish', cleanup)
    res.on('close', cleanup)
    res.on('error', cleanup)

    next()
}
