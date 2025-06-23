import cors from 'cors'
import type { Express } from 'express'
import rateLimit from 'express-rate-limit'
import helmet from 'helmet'
import { SECURITY_CONFIG } from '../../config/security.js'
import { validatePayloadSize } from '../payload-validation.js'
import { corsOptions } from './cors-options.js'
import { helmetConfig } from './helmet-config.js'
import { rateLimitConfig } from './rate-limit-config.js'
import { requestTimeout } from './request-timeout.js'

// Apply all security middleware
export function applySecurity(app: Express): void {
    // Disable X-Powered-By header first
    app.disable('x-powered-by')

    // Trust proxy (if behind reverse proxy)
    if (SECURITY_CONFIG.NODE_ENV === 'production') {
        app.set('trust proxy', 1)
    }

    // Basic security headers
    if (SECURITY_CONFIG.ENABLE_HELMET) {
        app.use(helmet(helmetConfig))
    }

    // CORS configuration
    app.use(cors(corsOptions))

    // Request payload size validation
    app.use(validatePayloadSize)

    // Rate limiting
    app.use(rateLimit(rateLimitConfig))

    // Request timeout
    app.use(requestTimeout)
}
