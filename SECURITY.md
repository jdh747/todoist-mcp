# Security Guide for Todoist MCP Server

## Overview

This Todoist MCP (Model Context Protocol) server has been secured with enterprise-grade security measures to protect your personal Todoist data. The server now requires authentication and implements multiple layers of security.

## 🔐 Security Features

### Authentication

- **JWT Bearer Token Authentication**: Stateless authentication using JSON Web Tokens
- **API Key Authentication**: Simple API key-based authentication
- **Multi-method Support**: Supports both JWT and API key authentication methods

### Security Middleware

- **Rate Limiting**: Prevents abuse with configurable rate limits
- **CORS Protection**: Configurable cross-origin resource sharing
- **Security Headers**: Helmet.js for security headers (CSP, HSTS, etc.)
- **Input Validation**: Comprehensive request validation and sanitization
- **Request Timeout**: Prevents hanging requests
- **Body Size Limits**: Prevents large payload attacks

### Logging & Monitoring

- **Security Event Logging**: All security events are logged with context
- **Request Logging**: Detailed request logging for monitoring
- **Structured Logging**: JSON structured logs for production environments

## 🚀 Quick Setup

### 1. Install Dependencies

```bash
npm install
```

### 2. Generate Security Tokens

```bash
npm run setup-security
```

This will generate secure JWT secrets and API keys. Copy the output to your `.env` file.

### 3. Configure Environment Variables

Copy `.env.example` to `.env` and update with your secure tokens:

```env
# Required Security Configuration
JWT_SECRET=your_generated_jwt_secret_here
TODOIST_API_KEY=your_todoist_api_key_here

# Optional Configuration
PORT=3000
NODE_ENV=production
ALLOWED_ORIGINS=https://yourdomain.com
```

### 4. Start the Server

```bash
npm run start:prod
```

## 🔑 Authentication Methods

### Method 1: JWT Bearer Token

```bash
# Generate a token (development only)
curl -X POST http://localhost:3000/auth/token \
  -H "Content-Type: application/json" \
  -d '{"username": "user", "password": "pass"}'

# Use the token
curl -X POST http://localhost:3000/mcp \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc": "2.0", "method": "tools/list", "id": 1}'
```

### Method 2: API Key

```bash
curl -X POST http://localhost:3000/mcp \
  -H "X-API-Key: YOUR_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc": "2.0", "method": "tools/list", "id": 1}'
```

## 📊 Security Configuration

### Environment Variables

| Variable                  | Description                               | Required | Default               |
| ------------------------- | ----------------------------------------- | -------- | --------------------- |
| `JWT_SECRET`              | JWT signing secret (min 32 chars)         | Yes      | -                     |
| `MCP_API_KEY`             | API key for authentication (min 16 chars) | Yes      | -                     |
| `TODOIST_API_KEY`         | Your Todoist API key                      | Yes      | -                     |
| `PORT`                    | Server port                               | No       | 3000                  |
| `NODE_ENV`                | Environment (development/production)      | No       | development           |
| `RATE_LIMIT_WINDOW_MS`    | Rate limit window in milliseconds         | No       | 900000 (15 min)       |
| `RATE_LIMIT_MAX_REQUESTS` | Max requests per window                   | No       | 100                   |
| `ALLOWED_ORIGINS`         | Comma-separated CORS origins              | No       | http://localhost:3001 |
| `LOG_LEVEL`               | Logging level (error/warn/info/debug)     | No       | info                  |
| `REQUEST_TIMEOUT_MS`      | Request timeout in milliseconds           | No       | 30000                 |
| `MAX_REQUEST_SIZE`        | Maximum request body size                 | No       | 10mb                  |
| `ENABLE_HELMET`           | Enable security headers                   | No       | true                  |

### Rate Limiting

- Default: 100 requests per 15 minutes per IP
- Configurable via `RATE_LIMIT_WINDOW_MS` and `RATE_LIMIT_MAX_REQUESTS`
- Returns 429 status code when exceeded

### CORS Configuration

- Configurable allowed origins via `ALLOWED_ORIGINS`
- Supports credentials
- Validates origin for security

## 🛡️ Security Best Practices

### Production Deployment

1. **Use HTTPS**: Always use HTTPS in production
2. **Reverse Proxy**: Use nginx or similar reverse proxy
3. **Firewall**: Restrict access to known IP addresses
4. **Monitoring**: Monitor logs for security events
5. **Regular Updates**: Keep dependencies updated

### Token Management

1. **Rotate Secrets**: Regularly rotate JWT secrets and API keys
2. **Secure Storage**: Store secrets securely (not in code)
3. **Environment Separation**: Use different secrets for different environments
4. **Minimal Permissions**: Use least privilege principle

### Network Security

1. **Private Network**: Deploy on private network when possible
2. **VPN Access**: Use VPN for remote access
3. **IP Whitelisting**: Restrict access to known IP addresses
4. **DDoS Protection**: Use DDoS protection services

## 📝 Security Logging

### Logged Security Events

- Authentication failures
- Rate limit violations
- CORS violations
- Input validation failures
- Suspicious request patterns

### Log Format

```json
{
  "timestamp": "2024-01-01T00:00:00.000Z",
  "level": "warn",
  "message": "SECURITY EVENT: JWT auth failed",
  "event": "JWT auth failed",
  "reason": "invalid_token",
  "ip": "192.168.1.100",
  "service": "todoist-mcp"
}
```

## 🔍 Monitoring & Alerting

### Key Metrics to Monitor

- Authentication failure rates
- Rate limit violations
- Error rates
- Response times
- Unusual request patterns

### Recommended Alerts

- High authentication failure rate
- Repeated rate limit violations from same IP
- Unusual request patterns
- Server errors or downtime

## 🚨 Incident Response

### Security Incident Checklist

1. **Identify**: Determine the nature of the security incident
2. **Contain**: Block malicious IPs, rotate compromised keys
3. **Investigate**: Analyze logs to understand the scope
4. **Remediate**: Fix vulnerabilities, update security measures
5. **Document**: Document the incident and lessons learned

### Emergency Actions

- Rotate all API keys and JWT secrets
- Block suspicious IP addresses
- Temporarily disable the service if necessary
- Review and update security configurations

## 📞 Support

For security-related questions or to report security vulnerabilities, please:

1. Review this documentation
2. Check the logs for security events
3. Ensure your configuration follows best practices
4. Report any security issues responsibly

## 🔄 Updates

This security implementation will be regularly updated to address new threats and vulnerabilities. Always keep your server and dependencies updated to the latest versions.
