import type { NextFunction, Request, Response } from 'express'
import type { SECURITY_EVENT_TYPES } from '../constants/security.js'

export interface SecurityEventData {
    ip?: string
    userAgent?: string
    url?: string
    method?: string
    origin?: string
    timeout?: number
    allowedOrigins?: string[]
    payloadSize?: number
    maxPayloadSize?: number
    [key: string]: unknown
}

export type SecurityEventType = (typeof SECURITY_EVENT_TYPES)[keyof typeof SECURITY_EVENT_TYPES]

export interface SecurityEvent {
    type: SecurityEventType
    data: SecurityEventData
    timestamp: Date
}

export type SecurityMiddleware = (req: Request, res: Response, next: NextFunction) => void

export interface SecurityConfig {
    rateLimitWindowMs: number
    rateLimitMaxRequests: number
    requestTimeoutMs: number
    allowedOrigins: string[]
    enableHelmet: boolean
    maxRequestSize: string
    maxRequestPayloadSize: number
    nodeEnv: string
}

export interface CorsOptions {
    origin: (
        origin: string | undefined,
        callback: (err: Error | null, allow?: boolean) => void,
    ) => void
    credentials: boolean
    optionsSuccessStatus: number
    methods: string[]
    allowedHeaders: string[]
}

export interface RateLimitConfig {
    windowMs: number
    max: number
    message: object
    standardHeaders: boolean
    legacyHeaders: boolean
    handler: (req: Request, res: Response) => void
}
