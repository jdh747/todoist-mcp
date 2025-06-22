import type { TodoistApi } from '@doist/todoist-api-typescript'
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js'
import { z } from 'zod'

export function registerGetSharedLabels(server: McpServer, api: TodoistApi) {
    server.tool(
        'get-shared-labels',
        'Retrieves a list of shared labels in Todoist',
        {
            omitPersonal: z.boolean().optional(),
        },
        async ({ omitPersonal }) => {
            let response = await api.getSharedLabels({ omitPersonal })
            const labels = response.results
            while (response.nextCursor) {
                response = await api.getSharedLabels({ omitPersonal, cursor: response.nextCursor })
                labels.push(...response.results)
            }
            return {
                content: labels.map((label) => ({
                    type: 'text',
                    text: JSON.stringify(label, null, 2),
                })),
            }
        },
    )
}
