import type { Server } from 'node:http'
import { logger } from '../utils/logger.js'

export function registerSignalHandlers(server: Server) {
    process.on('SIGTERM', () => {
        logger.info('SIGTERM received, shutting down gracefully')
        server.close(() => {
            logger.info('Server closed')
            process.exit(0)
        })
    })

    process.on('SIGINT', () => {
        logger.info('SIGINT received, shutting down gracefully')
        server.close(() => {
            logger.info('Server closed')
            process.exit(0)
        })
    })
}
