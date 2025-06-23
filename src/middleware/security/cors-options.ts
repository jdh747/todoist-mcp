import { SECURITY_CONFIG } from '../../config/security.js'
import { ALLOWED_HTTP_METHODS, SECURITY_EVENT_TYPES } from '../../constants/security.js'
import type { CorsOptions } from '../../types/security.js'
import { logSecurityEvent } from '../../utils/logger.js'

export const corsOptions: CorsOptions = {
    origin: (
        origin: string | undefined,
        callback: (err: Error | null, allow?: boolean) => void,
    ) => {
        // Allow requests with no origin (like mobile apps or curl requests)
        if (!origin) return callback(null, true)

        // Check for wildcard in production
        if (
            SECURITY_CONFIG.NODE_ENV === 'production' &&
            SECURITY_CONFIG.ALLOWED_ORIGINS.includes('*')
        ) {
            console.warn('WARNING: CORS wildcard (*) is not recommended in production')
        }

        if (
            SECURITY_CONFIG.ALLOWED_ORIGINS.includes('*') ||
            SECURITY_CONFIG.ALLOWED_ORIGINS.includes(origin)
        ) {
            callback(null, true)
        } else {
            logSecurityEvent(SECURITY_EVENT_TYPES.CORS_VIOLATION, {
                origin,
                allowedOrigins: SECURITY_CONFIG.ALLOWED_ORIGINS,
            })
            callback(new Error('Not allowed by CORS'))
        }
    },
    credentials: true,
    optionsSuccessStatus: 200,
    methods: [...ALLOWED_HTTP_METHODS],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-API-Key'],
}
