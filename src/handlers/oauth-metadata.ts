import type { Request, Response } from 'express'
import { OAUTH_CONFIG } from '../config/oauth.js'

/**
 * OAuth 2.0 Protected Resource Metadata Handler
 * 
 * Implements RFC 9728 - OAuth 2.0 Protected Resource Metadata
 * This endpoint provides metadata about the protected resource (MCP server)
 * to inform clients about authorization requirements and capabilities.
 */
export function handleProtectedResourceMetadata(req: Request, res: Response): void {
    const metadata = {
        // Required fields per RFC 9728
        resource: OAUTH_CONFIG.AUDIENCE,
        authorization_servers: [OAUTH_CONFIG.AUTHORIZATION_SERVER_URL],
        
        // Optional fields for enhanced client integration
        scopes_supported: OAUTH_CONFIG.REQUIRED_SCOPES,
        bearer_methods_supported: ['header'], // Only Authorization header, not query string
        resource_documentation: `${OAUTH_CONFIG.SERVER_URL}/docs`,
        
        // Token introspection support
        introspection_endpoint: OAUTH_CONFIG.INTROSPECTION_ENDPOINT,
        introspection_endpoint_auth_methods_supported: ['client_secret_basic', 'client_secret_post'],
        
        // Security features
        tls_client_certificate_bound_access_tokens: false,
        authorization_details_types_supported: ['mcp_todoist_access'],
        
        // MCP-specific metadata
        mcp_version: '1.0',
        mcp_capabilities: {
            tools: true,
            resources: true,
            prompts: false,
            sampling: false
        },
        
        // Todoist integration metadata
        todoist_oauth_supported: true,
        todoist_scopes_required: ['data:read', 'data:read_write', 'task:add', 'project:delete']
    }

    res.setHeader('Content-Type', 'application/json')
    res.setHeader('Cache-Control', 'public, max-age=3600') // Cache for 1 hour
    res.json(metadata)
}

/**
 * OAuth Authorization Server Metadata Handler
 * 
 * Provides basic redirect to the actual authorization server's metadata
 * since we're acting as a resource server, not an authorization server.
 */
export function handleAuthorizationServerMetadata(req: Request, res: Response): void {
    res.redirect(`${OAUTH_CONFIG.AUTHORIZATION_SERVER_URL}/.well-known/oauth-authorization-server`)
}