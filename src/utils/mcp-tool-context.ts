/**
 * MCP Tool Context Utilities
 *
 * Provides context and utilities for MCP tools to access per-user Todoist API clients.
 * This replaces the static API instance pattern with dynamic per-user token management.
 */

import type { Request } from 'express'
import type { TodoistApi } from '@doist/todoist-api-typescript'
import { TodoistApiManager } from './todoist-api-manager.js'

// Global API manager instance
const todoistApiManager = new TodoistApiManager()

/**
 * MCP Tool Context
 * 
 * Provides access to user-specific Todoist API and request information
 * within MCP tool handlers.
 */
export interface McpToolContext {
    api: TodoistApi
    userId: string
    todoistUserId: string
    request: Request
}

/**
 * Create MCP tool context from Express request
 * 
 * Extracts user authentication information and provides Todoist API client.
 * Must be called within an MCP tool handler where the request has been
 * processed by OAuth authentication middleware.
 */
export async function createToolContext(req: Request): Promise<McpToolContext> {
    // Get user-specific Todoist API client
    const api = await todoistApiManager.getApiForUser(req)

    if (!req.mcpAuth?.identifier) {
        throw new Error('User not authenticated')
    }

    if (!req.todoistAuth?.todoistUserId) {
        throw new Error('Todoist account not connected')
    }

    return {
        api,
        userId: req.mcpAuth.identifier,
        todoistUserId: req.todoistAuth.todoistUserId,
        request: req,
    }
}

/**
 * Get the global Todoist API manager instance
 */
export function getTodoistApiManager(): TodoistApiManager {
    return todoistApiManager
}

/**
 * Middleware injection helper for MCP tools
 * 
 * This function returns a handler that can be used in MCP tool registrations
 * to automatically inject the tool context.
 */
export function withToolContext<TArgs, TResult>(
    toolHandler: (args: TArgs, context: McpToolContext) => Promise<TResult>
): (args: TArgs) => Promise<TResult> {
    return async (args: TArgs): Promise<TResult> => {
        // Access the current request through a thread-local storage pattern
        // Note: This requires the request to be available in the execution context
        const req = getCurrentRequest()
        if (!req) {
            throw new Error('No request context available for MCP tool')
        }

        const context = await createToolContext(req)
        return toolHandler(args, context)
    }
}

// Thread-local storage for current request (Node.js AsyncLocalStorage pattern)
import { AsyncLocalStorage } from 'node:async_hooks'

const requestStorage = new AsyncLocalStorage<Request>()

/**
 * Set current request in async local storage
 * This should be called by the MCP request handler
 */
export function setCurrentRequest(req: Request): void {
    requestStorage.enterWith(req)
}

/**
 * Get current request from async local storage
 */
export function getCurrentRequest(): Request | undefined {
    return requestStorage.getStore()
}