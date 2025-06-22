import type { TodoistApi } from '@doist/todoist-api-typescript'
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js'
import { z } from 'zod'

export function registerGetProjectCollaborators(server: McpServer, api: TodoistApi) {
    server.tool(
        'get-project-collaborators',
        'Get all collaborators from a project in Todoist',
        {
            projectId: z.string(),
        },
        async ({ projectId }) => {
            let response = await api.getProjectCollaborators(projectId)
            const collaborators = response.results
            while (response.nextCursor) {
                response = await api.getProjectCollaborators(projectId, {
                    cursor: response.nextCursor,
                })
                collaborators.push(...response.results)
            }
            return {
                content: collaborators.map((collaborator) => ({
                    type: 'text',
                    text: JSON.stringify(collaborator, null, 2),
                })),
            }
        },
    )
}
