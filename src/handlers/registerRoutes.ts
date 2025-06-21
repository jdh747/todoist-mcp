import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js'
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js'
import type { Express, Request, RequestHandler, Response } from 'express'

export function registerRoutes(httpServer: Express, createMcpServer: () => McpServer) {
    httpServer.post('/mcp', handlePost())
    httpServer.get('/mcp', handleGet())
    httpServer.delete('/mcp', handleDelete())

    function handlePost(): RequestHandler {
        return async (req: Request, res: Response) => {
            console.log('Received POST MCP request')

            // In stateless mode, create a new instance of transport and server for each request
            // to ensure complete isolation. A single instance would cause request ID collisions
            // when multiple clients connect concurrently.
            try {
                const mcpServer = createMcpServer()
                const transport: StreamableHTTPServerTransport = new StreamableHTTPServerTransport({
                    sessionIdGenerator: undefined,
                })

                res.on('close', () => {
                    console.log('Request closed')

                    transport.close()
                    mcpServer.close()
                })

                await mcpServer.connect(transport)
                await transport.handleRequest(req, res, req.body)
            } catch (error) {
                console.error('Error handling MCP request:', error)

                if (!res.headersSent) {
                    res.status(500).json({
                        jsonrpc: '2.0',
                        error: {
                            code: -32603,
                            message: 'Internal server error',
                        },
                        id: null,
                    })
                }
            }
        }
    }

    function handleGet(): RequestHandler {
        return async (_req: Request, res: Response) => {
            console.log('Received GET MCP request')

            res.writeHead(405).end(
                JSON.stringify({
                    jsonrpc: '2.0',
                    error: {
                        code: -32000,
                        message: 'Method not allowed.',
                    },
                    id: null,
                }),
            )
        }
    }

    function handleDelete(): RequestHandler {
        return async (_req: Request, res: Response) => {
            console.log('Received DELETE MCP request')

            res.writeHead(405).end(
                JSON.stringify({
                    jsonrpc: '2.0',
                    error: {
                        code: -32000,
                        message: 'Method not allowed.',
                    },
                    id: null,
                }),
            )
        }
    }
}
