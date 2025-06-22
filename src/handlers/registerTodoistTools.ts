import { TodoistApi } from '@doist/todoist-api-typescript'
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js'
import { registerAddComment } from '../mcp-tools/add-comment.js'
import { registerAddLabel } from '../mcp-tools/add-label.js'
import { registerAddProject } from '../mcp-tools/add-project.js'
import { registerAddSection } from '../mcp-tools/add-section.js'
import { registerAddTask } from '../mcp-tools/add-task.js'
import { registerCloseTask } from '../mcp-tools/close-task.js'
import { registerDeleteComment } from '../mcp-tools/delete-comment.js'
import { registerDeleteLabel } from '../mcp-tools/delete-label.js'
import { registerDeleteProject } from '../mcp-tools/delete-project.js'
import { registerDeleteSection } from '../mcp-tools/delete-section.js'
import { registerDeleteTask } from '../mcp-tools/delete-task.js'
import { registerGetComment } from '../mcp-tools/get-comment.js'
import { registerGetComments } from '../mcp-tools/get-comments.js'
import { registerGetLabel } from '../mcp-tools/get-label.js'
import { registerGetLabels } from '../mcp-tools/get-labels.js'
import { registerGetProductivityStats } from '../mcp-tools/get-productivity-stats.js'
import { registerGetProjectCollaborators } from '../mcp-tools/get-project-collaborators.js'
import { registerGetProjectComments } from '../mcp-tools/get-project-comments.js'
import { registerGetProject } from '../mcp-tools/get-project.js'
import { registerGetProjects } from '../mcp-tools/get-projects.js'
import { registerGetSection } from '../mcp-tools/get-section.js'
import { registerGetSections } from '../mcp-tools/get-sections.js'
import { registerGetSharedLabels } from '../mcp-tools/get-shared-labels.js'
import { registerGetTaskComments } from '../mcp-tools/get-task-comments.js'
import { registerGetTask } from '../mcp-tools/get-task.js'
import { registerGetTasksByFilter } from '../mcp-tools/get-tasks-by-filter.js'
import { registerGetTasksCompletedByCompletionDate } from '../mcp-tools/get-tasks-completed-by-completion-date.js'
import { registerGetTasksCompletedByDueDate } from '../mcp-tools/get-tasks-completed-by-due-date.js'
import { registerGetTasks } from '../mcp-tools/get-tasks.js'
import { registerMoveTasks } from '../mcp-tools/move-tasks.js'
import { registerQuickAddTask } from '../mcp-tools/quick-add-task.js'
import { registerRemoveSharedLabel } from '../mcp-tools/remove-shared-label.js'
import { registerRenameSharedLabel } from '../mcp-tools/rename-shared-label.js'
import { registerReopenTask } from '../mcp-tools/reopen-task.js'
import { registerUpdateComment } from '../mcp-tools/update-comment.js'
import { registerUpdateLabel } from '../mcp-tools/update-label.js'
import { registerUpdateProject } from '../mcp-tools/update-project.js'
import { registerUpdateSection } from '../mcp-tools/update-section.js'
import { registerUpdateTask } from '../mcp-tools/update-task.js'

export function registerTodoistTools(server: McpServer) {
    if (!process.env.TODOIST_API_KEY) {
        throw new Error('TODOIST_API_KEY environment variable is required')
    }

    const api = new TodoistApi(process.env.TODOIST_API_KEY)

    /* Projects */
    registerAddProject(server, api)
    registerGetProjects(server, api)
    registerGetProject(server, api)
    registerUpdateProject(server, api)
    registerDeleteProject(server, api)

    /* Collaborators */
    registerGetProjectCollaborators(server, api)

    /* Tasks */
    registerAddTask(server, api)
    registerQuickAddTask(server, api)
    registerGetTask(server, api)
    registerGetTasks(server, api)
    registerGetTasksCompletedByCompletionDate(server, api)
    registerGetTasksCompletedByDueDate(server, api)
    registerGetProductivityStats(server, api)
    registerUpdateTask(server, api)
    registerCloseTask(server, api)
    registerMoveTasks(server, api)
    registerDeleteTask(server, api)
    registerReopenTask(server, api)
    registerGetTasksByFilter(server, api)

    /* Sections */
    registerAddSection(server, api)
    registerGetSection(server, api)
    registerGetSections(server, api)
    registerUpdateSection(server, api)
    registerDeleteSection(server, api)

    /* Comments */
    registerAddComment(server, api)
    registerGetComment(server, api)
    registerGetComments(server, api)
    registerUpdateComment(server, api)
    registerDeleteComment(server, api)
    registerGetTaskComments(server, api)
    registerGetProjectComments(server, api)

    /* Labels */
    registerAddLabel(server, api)
    registerDeleteLabel(server, api)
    registerUpdateLabel(server, api)
    registerGetLabel(server, api)
    registerGetLabels(server, api)
    registerGetSharedLabels(server, api)
    registerRemoveSharedLabel(server, api)
    registerRenameSharedLabel(server, api)
}
