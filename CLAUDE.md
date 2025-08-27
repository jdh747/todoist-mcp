# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is a **Todoist MCP (Model Context Protocol) Server** that provides secure API access to Todoist functionality for LLMs. The server implements comprehensive Todoist operations including task management, project management, labels, comments, and collaboration features.

## Development Commands

### Build & Development
```bash
bun install              # Install dependencies
bun run dev             # Development mode with file watching
bun run build           # Full build (TypeScript compilation + permissions)
bun run build-tsc       # TypeScript compilation only
bun run start           # Start production server
bun run start:prod      # Start with NODE_ENV=production
bun run clean           # Clean build directory
bun run prebuild        # Clean, typecheck before build
bun run prepare         # Install Husky hooks and build
```

### Code Quality
```bash
bun run lint            # Check code with Biome (linting + formatting)
bun run format          # Auto-fix formatting issues
bun run format:fix      # Auto-fix with more aggressive fixes
bun run typecheck       # TypeScript type checking
bun run test            # Run tests with Bun
```

### Security & Debug
```bash
bun run setup-security  # Generate JWT secrets and environment template
bunx @modelcontextprotocol/inspector  # Debug MCP server with inspector
```

### Docker Development
```bash
docker compose up -d                    # Run production service
docker compose --profile dev up         # Run development service with hot reload
```

## Architecture

### Core Structure
- **Entry Point**: `src/index.ts` - Main server initialization with security validation
- **Server Creation**: 
  - `src/utils/createHttpServer.ts` - Express HTTP server with layered middleware
  - `src/utils/create-mcp-server.ts` - MCP protocol server initialization
- **Tool Registration**: `src/handlers/register-todoist-tools.ts` - Registers all 35 Todoist API operations

### Security Architecture
This is a **security-first implementation** with enterprise-grade features:

#### Configuration & Validation
- **Security Config**: `src/config/security.ts` - Centralized configuration with validation
- **Environment Validation**: Required JWT_SECRET (min 32 chars), TODOIST_API_KEY, and ALLOWED_USER_ID on startup

#### Middleware Pipeline (Applied in Order)
1. **Security Headers**: `src/middleware/security/security.ts` - Orchestrates security middleware
   - `src/middleware/security/helmet-config.ts` - CSP, HSTS, security headers
   - `src/middleware/security/cors-options.ts` - CORS with origin validation and logging
   - `src/middleware/security/rate-limit-config.ts` - Rate limiting configuration
   - `src/middleware/security/request-timeout.ts` - Request timeout handling
2. **Authentication**: `src/middleware/auth.ts` - JWT Bearer tokens validation
3. **Authorization**: `src/middleware/authorize-user.ts` - User-specific access control
4. **Request Processing**:
   - `src/middleware/log-request.ts` - Request logging
   - `src/middleware/json-body-parser.ts` - JSON parsing
   - `src/middleware/url-encoded-parser.ts` - URL-encoded parsing
   - `src/middleware/post-parse-validation.ts` - Post-parsing size validation
   - `src/middleware/sanitize-input.ts` - Input sanitization
   - `src/middleware/validate-mcp-request.ts` - MCP request validation
5. **Route Handling**: `src/handlers/register-routes.ts` - Secure route registration
6. **Error Handling**: `src/middleware/global-error-log.ts` - Global error logging

#### Security Utilities
- **Token Management**: `src/utils/token-blacklist.ts` - JWT token blacklisting
- **Logging**: `src/utils/logger.ts` - Winston-based security event logging
- **Auth Utils**: `src/utils/auth.ts` - Authentication utilities
- **Security Responses**: `src/utils/security-responses.ts` - Standardized security responses

### MCP Tools Structure
The `src/mcp-tools/` directory contains 35 individual tool implementations for each Todoist API operation:

#### Tasks (14 tools)
- add-task, quick-add-task, get-task, get-tasks, get-tasks-by-filter
- get-tasks-completed-by-completion-date, get-tasks-completed-by-due-date
- get-productivity-stats, update-task, close-task, reopen-task, move-tasks, delete-task

#### Projects (5 tools)
- add-project, get-project, get-projects, update-project, delete-project

#### Sections (5 tools)
- add-section, get-section, get-sections, update-section, delete-section

#### Comments (7 tools)
- add-comment, get-comment, get-comments, update-comment, delete-comment
- get-task-comments, get-project-comments

#### Labels (6 tools)
- add-label, get-label, get-labels, update-label, delete-label
- get-shared-labels, remove-shared-label, rename-shared-label

#### Collaboration (1 tool)
- get-project-collaborators

## Environment Configuration

### Required Variables
```env
JWT_SECRET=your_jwt_secret_here              # Min 32 characters, 512-bit recommended
TODOIST_API_KEY=your_todoist_api_key_here    # From Todoist developer settings
ALLOWED_USER_ID=your_user_id_here            # User ID authorized to access MCP endpoint
```

### Optional Configuration
```env
# Server
PORT=3000
NODE_ENV=development

# Rate Limiting
RATE_LIMIT_WINDOW_MS=900000                  # 15 minutes
RATE_LIMIT_MAX_REQUESTS=100
FAILED_LOGIN_RATE_LIMIT_WINDOW_MS=300000     # 5 minutes
FAILED_LOGIN_RATE_LIMIT_MAX_REQUESTS=5

# CORS
ALLOWED_ORIGINS=http://localhost:3001,https://yourdomain.com

# Security
ENABLE_HELMET=true
REQUEST_TIMEOUT_MS=30000                     # 30 seconds
MAX_REQUEST_SIZE=10mb
MAX_REQUEST_PAYLOAD_SIZE=50000               # 50KB

# JWT
JWT_EXPIRES_IN=24h

# Logging
LOG_LEVEL=info
```

### Security Setup Process
1. Run `bun run setup-security` to generate secure tokens and environment template
2. Copy output to `.env` file
3. Add your Todoist API key from [Todoist Developer Settings](https://app.todoist.com/app/settings/integrations/developer)
4. Server validates configuration on startup and exits if invalid

## Technology Stack

- **Runtime**: Bun (development), Node.js (production compatible)
- **Language**: TypeScript with ES2022 target, Node16 module resolution
- **Security**: JWT, helmet, express-rate-limit, bcrypt, cors
- **MCP SDK**: @modelcontextprotocol/sdk v1.13.0
- **Todoist API**: @doist/todoist-api-typescript v5.0.1
- **Code Quality**: Biome (linting + formatting), Husky (git hooks), lint-staged
- **Logging**: Winston with structured logging
- **Validation**: Zod schemas, express-validator

## Development Notes

### Code Style (Biome Configuration)
- **Indentation**: 4 spaces
- **Quotes**: Single quotes
- **Line Width**: 100 characters
- **Trailing Commas**: Always
- **Semicolons**: As needed
- **Module System**: ES modules with .js imports (Node16 resolution)

### Security Requirements
- All endpoints require authentication (JWT Bearer token)
- MCP endpoint restricted to single authorized user (ALLOWED_USER_ID)
- No anonymous access permitted
- Comprehensive input validation and sanitization
- Rate limiting on all routes with failed login tracking
- Security event logging for monitoring

### Development Workflow
- **Hot Reload**: `bun run dev` watches for file changes
- **Type Safety**: TypeScript strict mode enabled
- **Git Hooks**: Husky runs formatting on commit via lint-staged
- **Testing**: Bun test runner for fast execution

### Docker Support
- **Production**: Self-contained image build
- **Development**: Volume-mounted with hot reload
- Both services support environment variable configuration