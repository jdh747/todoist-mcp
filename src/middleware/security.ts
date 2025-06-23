import cors from 'cors'
import type { Express, NextFunction, Request, Response } from 'express'
import rateLimit from 'express-rate-limit'
import helmet from 'helmet'
import { SECURITY_CONFIG } from '../config/security.js'
import {
    ALLOWED_HTTP_METHODS,
    SECURITY_DEFAULTS,
    SECURITY_EVENT_TYPES,
} from '../constants/security.js'
import type { CorsOptions, RateLimitConfig, SecurityMiddleware } from '../types/security.js'
import { logSecurityEvent } from '../utils/logger.js'
import { sendRateLimitError, sendTimeoutError } from '../utils/security-responses.js'
import { validatePayloadSize } from './payload-validation.js'

// Configure CORS
const corsOptions: CorsOptions = {
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

// Rate limiting configuration
const rateLimitConfig: RateLimitConfig = {
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

// Helmet security headers configuration
const helmetConfig = {
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            scriptSrc: ["'self'"],
            styleSrc: ["'self'", "'unsafe-inline'"],
            imgSrc: ["'self'", 'data:', 'https:'],
            connectSrc: ["'self'", 'https://api.todoist.com'],
            fontSrc: ["'self'"],
            objectSrc: ["'none'"],
            mediaSrc: ["'self'"],
            frameSrc: ["'none'"],
        },
    },
    crossOriginEmbedderPolicy: false,
    hsts: {
        maxAge: SECURITY_DEFAULTS.HSTS_MAX_AGE,
        includeSubDomains: true,
        preload: true,
    },
}

// Request timeout middleware
const requestTimeoutMiddleware: SecurityMiddleware = (
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
    app.use(requestTimeoutMiddleware)
}
