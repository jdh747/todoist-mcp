import type { TodoistApi } from '@doist/todoist-api-typescript'
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js'
import { z } from 'zod'

export function registerGetProjectComments(server: McpServer, api: TodoistApi) {
    server.tool(
        'get-project-comments',
        'Get comments from a project in Todoist',
        { projectId: z.string() },
        async ({ projectId }) => {
            let response = await api.getComments({ projectId })
            const comments = response.results
            while (response.nextCursor) {
                response = await api.getComments({ projectId, cursor: response.nextCursor })
                comments.push(...response.results)
            }
            return {
                content: comments.map((comment) => ({
                    type: 'text',
                    text: JSON.stringify(comment, null, 2),
                })),
            }
        },
    )
}
