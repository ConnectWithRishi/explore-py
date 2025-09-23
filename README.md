# FastAPI Azure Entra Authentication System

A comprehensive FastAPI-based authentication system that integrates with Microsoft Azure Entra ID (formerly Azure AD) to provide secure API access for React applications.

## Architecture

This workspace implements a clean architecture with shared packages and focused applications:

### Packages

- **`packages/auth-core/`** - Core authentication utilities for Azure Entra token validation
- **`packages/entra-client/`** - On-Behalf-Of (OBO) flow and Microsoft Graph API integration
- **`packages/common-models/`** - Shared Pydantic models for consistent data structures

### Applications

- **`apps/fastapi-auth/`** - Main FastAPI authentication service

## Authentication Patterns

### Pattern A: Direct Token Validation

- React app uses MSAL.js for client-side OAuth with Microsoft Entra
- React sends access tokens as `Authorization: Bearer <token>` to FastAPI endpoints
- FastAPI validates tokens using Microsoft's JWKS (JSON Web Key Set)
- No refresh token handling on backend - React manages token lifecycle

### Pattern B: On-Behalf-Of (OBO) Flow

- FastAPI acts as confidential client with client credentials
- Exchanges user's access token for backend-managed tokens
- Enables tasks that outlast browser token expiry
- Backend can call Microsoft Graph API or other downstream services

## Quick Start

### Prerequisites

- Python 3.12.10+
- Azure Entra ID app registration (both SPA and confidential client)

### Setup

1. **Clone and install dependencies:**

```bash
uv sync
```

2. **Configure environment:**

```bash
cp .env.example .env
# Edit .env with your Azure app registration details
```

3. **Run the FastAPI application:**

```bash
cd apps/fastapi-auth
uv run uvicorn src.fastapi_auth.main:app --reload
```

## API Endpoints

### Authentication Endpoints (Pattern A)

- `GET /protected` - Simple protected endpoint requiring valid token
- `GET /me` - Get current user information from token claims
- `GET /roles` - Get user roles (requires role-based access)

### OBO Flow Endpoints (Pattern B)

- `GET /obo/graph/me` - Get user profile via Microsoft Graph API
- `POST /obo/long-task` - Start a task using OBO flow
- `GET /obo/jobs/{job_id}` - Get task status

## Configuration

### Required Environment Variables

```bash
AZURE_TENANT_ID=<tenant-guid>
AZURE_CLIENT_ID=<app-registration-client-id>
AZURE_CLIENT_SECRET=<confidential-client-secret>
API_AUDIENCE=api://<client-id>
```

### Azure Setup

1. Create app registration in Azure Entra
2. Configure both SPA and confidential client redirect URIs
3. Add necessary API permissions for Microsoft Graph
4. Generate client secret for confidential client

## Development

### Testing

```bash
uv run pytest
```

### Code Quality

```bash
uv run black .
uv run isort .
uv run mypy .
```

### Package Development

The workspace uses uv for dependency management with shared packages:

- Packages are linked via workspace sources
- Run commands from root or specific package directories
- Changes to packages are immediately available to dependent apps

## Security Features

- JWT signature validation using Microsoft JWKS
- Token expiration checking
- Audience and issuer validation
- CORS configuration for React apps
- Secure client secret handling
- OBO flow for downstream API access
