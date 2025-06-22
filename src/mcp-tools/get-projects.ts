import type { TodoistApi } from '@doist/todoist-api-typescript'
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js'

export function registerGetProjects(server: McpServer, api: TodoistApi) {
    server.tool('get-projects', 'Get all projects from Todoist', {}, async () => {
        let response = await api.getProjects()
        const projects = response.results
        while (response.nextCursor) {
            response = await api.getProjects({ cursor: response.nextCursor })
            projects.push(...response.results)
        }
        return {
            content: projects.map((project) => ({
                type: 'text',
                text: JSON.stringify(project, null, 2),
            })),
        }
    })
}
