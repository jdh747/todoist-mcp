import type { NextFunction, Request, Response } from 'express'
import { SECURITY_CONFIG } from '../config/security.js'
import { SECURITY_EVENT_TYPES } from '../constants/security.js'
import { logSecurityEvent } from '../utils/logger.js'
import { sendPayloadTooLargeError } from '../utils/security-responses.js'

/**
 * Post-parsing payload size validation middleware
 *
 * This validates the actual parsed size after Express body parsing,
 * catching edge cases like:
 * - Compressed content that expands during parsing
 * - Missing or incorrect Content-Length headers
 * - Requests that bypass the Content-Length header check
 */
export function validatePostParseSize(req: Request, res: Response, next: NextFunction): void {
    if (req.body) {
        const serializedSize = JSON.stringify(req.body).length

        if (serializedSize > SECURITY_CONFIG.MAX_REQUEST_PAYLOAD_SIZE) {
            logSecurityEvent(SECURITY_EVENT_TYPES.PAYLOAD_TOO_LARGE, {
                ip: req.ip,
                userAgent: req.get('User-Agent'),
                url: req.url,
                method: req.method,
                parsedPayloadSize: serializedSize,
                maxPayloadSize: SECURITY_CONFIG.MAX_REQUEST_PAYLOAD_SIZE,
                contentLength: req.get('content-length'),
            })

            sendPayloadTooLargeError(res)
            return
        }
    }

    next()
}
