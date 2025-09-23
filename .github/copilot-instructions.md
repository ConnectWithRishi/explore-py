# Copilot Instructions for FastAPI Azure Entra Authentication System

## Project Overview
This project implements a FastAPI-based authentication system that integrates with Microsoft Azure Entra ID (formerly Azure AD) to provide secure API access for React applications. The system supports both direct token validation and On-Behalf-Of (OBO) flow for long-running tasks.

## Architecture Patterns

### Pattern A: Direct Token Validation
- React app uses MSAL.js for client-side OAuth with Microsoft Entra
- React sends access tokens as `Authorization: Bearer <token>` to FastAPI endpoints
- FastAPI validates tokens using Microsoft's JWKS (JSON Web Key Set)
- No refresh token handling on backend - React manages token lifecycle

### Pattern B: On-Behalf-Of (OBO) Flow
- FastAPI acts as confidential client with client credentials
- Exchanges user's access token for backend-managed tokens
- Enables long-running tasks that outlast browser token expiry
- Backend can call Microsoft Graph API or other downstream services

## Key Components

### Authentication Flow
1. **User Login**: React → Azure Entra → Access Token
2. **API Calls**: React → FastAPI (with Bearer token)
3. **Token Validation**: FastAPI validates against Entra JWKS
4. **User Info Extraction**: Extract claims from validated token
5. **OBO Flow** (Pattern B): Exchange tokens for downstream API access

### User Information Mapping
Always extract user information using this exact mapping:
- `id` → `oid` claim (Azure object ID)
- `name` → `name` claim (display name)
- `email` → `preferred_username` or `upn` claim
- `roles` → `roles` claim (if app roles assigned)

### Required Environment Variables
```bash
AZURE_TENANT_ID=<tenant-guid>
AZURE_CLIENT_ID=<app-registration-client-id>
AZURE_CLIENT_SECRET=<confidential-client-secret>
API_AUDIENCE=api://<client-id>  # for token audience validation
```

## Implementation Guidelines

### Token Validation Requirements
- Verify JWT signature using Microsoft JWKS
- Validate issuer: `https://login.microsoftonline.com/{tenant_id}/v2.0`
- Validate audience matches your API client ID
- Check token expiration (`exp` claim)
- Handle validation errors with HTTP 401 responses

### Error Handling
- **Token Expired**: Return 401 with "Token expired" message
- **Invalid Signature**: Return 401 with "Invalid token" message
- **Missing Authorization**: Return 401 with "Authorization header missing"
- **OBO Failures**: Return 403 with descriptive error message

### Security Best Practices
- Use HttpOnly cookies for session management when applicable
- Cache JWKS with appropriate TTL (default: 3600 seconds)
- Store client secrets securely (environment variables, Key Vault)
- Never expose client secrets to frontend
- Implement proper CORS configuration
- Use HTTPS in production

### Long-Running Task Support
- Implement background job system (Celery, RQ, or FastAPI BackgroundTasks)
- Use OBO flow to acquire fresh tokens for job execution
- Store job status/progress for frontend polling
- Consider WebSocket/SSE for real-time progress updates

## Code Patterns

### Dependency Injection Pattern
```python
async def require_valid_token(token: str = Depends(get_bearer_token)):
    # Validate token and extract user info
    # Return structured user context
```

### User Context Structure
```python
user_context = {
    "user": {
        "id": claims.get("oid"),
        "name": claims.get("name"), 
        "email": claims.get("preferred_username") or claims.get("upn"),
        "roles": claims.get("roles", [])
    },
    "claims": decoded_token,
    "raw_token": original_token
}
```

### Endpoint Patterns
- **Pattern A Endpoints**: `/api/protected` - Simple token validation
- **Pattern B Endpoints**: `/api/obo/graph` - OBO flow for downstream APIs
- **Job Endpoints**: `/api/jobs/start`, `/api/jobs/status/{id}` - Long-running tasks

## Testing Strategy

### Azure Setup for Testing
- Create test users in Azure Entra tenant
- Configure app registration with appropriate scopes
- Set up both SPA and confidential client redirect URIs
- Test with MSAL device code flow before full integration

### Common Test Scenarios
- Valid token authentication
- Expired token handling
- Invalid token rejection
- Role-based access control
- OBO flow for Graph API calls
- Long-running job execution with token refresh

## Dependencies
- `fastapi` - Web framework
- `msal` - Microsoft Authentication Library
- `PyJWT` - JWT token validation
- `jwcrypto` - Cryptographic operations
- `httpx` - HTTP client for API calls
- `redis` - Session storage (optional)
- `celery` - Background tasks (optional)

## Development Workflow
1. Set up Azure Entra app registration
2. Configure environment variables
3. Implement token validation middleware
4. Create protected endpoints with user context
5. Add OBO flow for downstream API access
6. Implement background job system if needed
7. Test with React MSAL.js integration

## Troubleshooting
- Verify JWKS endpoint accessibility
- Check token audience and issuer claims
- Validate app registration permissions
- Ensure proper scope configuration
- Monitor token expiration timing
- Debug OBO flow with detailed error messages

When implementing features, always prioritize security, follow the user info extraction mapping exactly, and support both Pattern A and Pattern B depending on the endpoint requirements.