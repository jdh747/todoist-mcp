import type { TodoistApi } from '@doist/todoist-api-typescript'
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js'
import { z } from 'zod'

export function registerGetSections(server: McpServer, api: TodoistApi) {
    server.tool(
        'get-sections',
        'Get all sections from a project in Todoist',
        {
            projectId: z.string(),
        },
        async ({ projectId }) => {
            let response = await api.getSections({ projectId })
            const sections = response.results
            while (response.nextCursor) {
                response = await api.getSections({ projectId, cursor: response.nextCursor })
                sections.push(...response.results)
            }
            return {
                content: sections.map((section) => ({
                    type: 'text',
                    text: JSON.stringify(section, null, 2),
                })),
            }
        },
    )
}
