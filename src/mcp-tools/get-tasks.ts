import type { TodoistApi } from '@doist/todoist-api-typescript'
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js'
import { z } from 'zod'

export function registerGetTasks(server: McpServer, api: TodoistApi) {
    server.tool(
        'get-tasks',
        'Get all tasks from Todoist',
        {
            projectId: z.string().optional(),
        },
        async ({ projectId }) => {
            let response = await api.getTasks({ projectId })
            const tasks = response.results
            while (response.nextCursor) {
                response = await api.getTasks({ projectId, cursor: response.nextCursor })
                tasks.push(...response.results)
            }
            return {
                content: tasks.map((task) => ({
                    type: 'text',
                    text: JSON.stringify(task, null, 2),
                })),
            }
        },
    )
}
