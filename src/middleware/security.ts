import cors from 'cors'
import type { Express, NextFunction, Request, Response } from 'express'
import rateLimit from 'express-rate-limit'
import helmet from 'helmet'
import { SECURITY_CONFIG } from '../config/security.js'
import { logSecurityEvent } from '../utils/logger.js'

// Configure CORS
const corsOptions = {
    origin: (
        origin: string | undefined,
        callback: (err: Error | null, allow?: boolean) => void,
    ) => {
        // Allow requests with no origin (like mobile apps or curl requests)
        if (!origin) return callback(null, true)

        if (SECURITY_CONFIG.ALLOWED_ORIGINS.includes(origin)) {
            callback(null, true)
        } else {
            logSecurityEvent('CORS violation', {
                origin,
                allowedOrigins: SECURITY_CONFIG.ALLOWED_ORIGINS,
            })
            callback(new Error('Not allowed by CORS'))
        }
    },
    credentials: true,
    optionsSuccessStatus: 200,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-API-Key'],
}

// Rate limiting configuration
const rateLimitConfig = rateLimit({
    windowMs: SECURITY_CONFIG.RATE_LIMIT_WINDOW_MS,
    max: SECURITY_CONFIG.RATE_LIMIT_MAX_REQUESTS,
    message: {
        jsonrpc: '2.0',
        error: {
            code: -32000,
            message: 'Too many requests, please try again later',
        },
        id: null,
    },
    standardHeaders: true,
    legacyHeaders: false,
    handler: (req, res) => {
        logSecurityEvent('Rate limit exceeded', {
            ip: req.ip,
            userAgent: req.get('User-Agent'),
            url: req.url,
        })
        res.status(429).json({
            jsonrpc: '2.0',
            error: {
                code: -32000,
                message: 'Too many requests, please try again later',
            },
            id: null,
        })
    },
})

// Helmet security headers configuration
const helmetConfig = helmet({
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
        maxAge: 31536000,
        includeSubDomains: true,
        preload: true,
    },
})

// Request timeout middleware
function requestTimeout(req: Request, res: Response, next: NextFunction) {
    const timeout = setTimeout(() => {
        if (!res.headersSent) {
            logSecurityEvent('Request timeout', {
                ip: req.ip,
                url: req.url,
                method: req.method,
                timeout: SECURITY_CONFIG.REQUEST_TIMEOUT_MS,
            })

            res.status(408).json({
                jsonrpc: '2.0',
                error: {
                    code: -32000,
                    message: 'Request timeout',
                },
                id: null,
            })
        }
    }, SECURITY_CONFIG.REQUEST_TIMEOUT_MS)

    res.on('finish', () => {
        clearTimeout(timeout)
    })

    next()
}

// Apply all security middleware
export function applySecurity(app: Express) {
    // Basic security headers
    if (SECURITY_CONFIG.ENABLE_HELMET) {
        app.use(helmetConfig)
    }

    // CORS
    app.use(cors(corsOptions))

    // Rate limiting
    app.use(rateLimitConfig)

    // Request timeout
    app.use(requestTimeout)

    // Disable X-Powered-By header
    app.disable('x-powered-by')

    // Trust proxy (if behind reverse proxy)
    if (SECURITY_CONFIG.NODE_ENV === 'production') {
        app.set('trust proxy', 1)
    }
}
