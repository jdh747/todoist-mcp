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
    // OAuth-based registration - no static API key required
    // Individual tools will get per-user API clients dynamically

    /* Projects */
    registerAddProject(server)
    registerGetProjects(server)
    registerGetProject(server)
    registerUpdateProject(server)
    registerDeleteProject(server)

    /* Collaborators */
    registerGetProjectCollaborators(server)

    /* Tasks */
    registerAddTask(server)
    registerQuickAddTask(server)
    registerGetTask(server)
    registerGetTasks(server)
    registerGetTasksCompletedByCompletionDate(server)
    registerGetTasksCompletedByDueDate(server)
    registerGetProductivityStats(server)
    registerUpdateTask(server)
    registerCloseTask(server)
    registerMoveTasks(server)
    registerDeleteTask(server)
    registerReopenTask(server)
    registerGetTasksByFilter(server)

    /* Sections */
    registerAddSection(server)
    registerGetSection(server)
    registerGetSections(server)
    registerUpdateSection(server)
    registerDeleteSection(server)

    /* Comments */
    registerAddComment(server)
    registerGetComment(server)
    registerGetComments(server)
    registerUpdateComment(server)
    registerDeleteComment(server)
    registerGetTaskComments(server)
    registerGetProjectComments(server)

    /* Labels */
    registerAddLabel(server)
    registerDeleteLabel(server)
    registerUpdateLabel(server)
    registerGetLabel(server)
    registerGetLabels(server)
    registerGetSharedLabels(server)
    registerRemoveSharedLabel(server)
    registerRenameSharedLabel(server)
}
