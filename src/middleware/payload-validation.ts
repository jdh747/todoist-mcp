import type { NextFunction, Request, Response } from 'express'
import { SECURITY_CONFIG } from '../config/security.js'
import { SECURITY_EVENT_TYPES } from '../constants/security.js'
import { logSecurityEvent } from '../utils/logger.js'
import { sendPayloadTooLargeError } from '../utils/security-responses.js'

export function validatePayloadSize(req: Request, res: Response, next: NextFunction): void {
    const contentLength = req.get('content-length')

    if (contentLength) {
        const payloadSize = Number.parseInt(contentLength, 10)

        if (payloadSize > SECURITY_CONFIG.MAX_REQUEST_PAYLOAD_SIZE) {
            logSecurityEvent(SECURITY_EVENT_TYPES.PAYLOAD_TOO_LARGE, {
                ip: req.ip,
                userAgent: req.get('User-Agent'),
                url: req.url,
                method: req.method,
                payloadSize,
                maxPayloadSize: SECURITY_CONFIG.MAX_REQUEST_PAYLOAD_SIZE,
            })

            sendPayloadTooLargeError(res)
            return
        }
    }

    next()
}
