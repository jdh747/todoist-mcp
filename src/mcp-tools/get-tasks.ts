import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js'
import { z } from 'zod'
import { withToolContext } from '../utils/mcp-tool-context.js'

export function registerGetTasks(server: McpServer) {
    server.tool(
        'get-tasks',
        'Get all tasks from Todoist',
        {
            projectId: z.string().optional(),
        },
        withToolContext(async ({ projectId }, context) => {
            let response = await context.api.getTasks({ projectId })
            const tasks = response.results
            while (response.nextCursor) {
                response = await context.api.getTasks({ projectId, cursor: response.nextCursor })
                tasks.push(...response.results)
            }
            return {
                content: tasks.map((task) => ({
                    type: 'text',
                    text: JSON.stringify(task, null, 2),
                })),
            }
        }),
    )
}
