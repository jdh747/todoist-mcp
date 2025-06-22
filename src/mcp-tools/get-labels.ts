import type { TodoistApi } from '@doist/todoist-api-typescript'
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js'

export function registerGetLabels(server: McpServer, api: TodoistApi) {
    server.tool('get-labels', 'Get all labels in Todoist', {}, async () => {
        let response = await api.getLabels()
        const labels = response.results
        while (response.nextCursor) {
            response = await api.getLabels({ cursor: response.nextCursor })
            labels.push(...response.results)
        }
        return {
            content: labels.map((label) => ({
                type: 'text',
                text: JSON.stringify(label, null, 2),
            })),
        }
    })
}
