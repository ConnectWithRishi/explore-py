"""Test configuration and fixtures for FastAPI Azure Entra authentication."""

import os
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, Generator, AsyncGenerator

import pytest
import jwt
import httpx
from fastapi.testclient import TestClient
from unittest.mock import MagicMock, patch

from fastapi_auth.main import app
from fastapi_auth.config import settings


# Test environment variables
os.environ.setdefault("AZURE_TENANT_ID", "test-tenant-id")
os.environ.setdefault("AZURE_CLIENT_ID", "test-client-id")
os.environ.setdefault("AZURE_CLIENT_SECRET", "test-client-secret")
os.environ.setdefault("API_AUDIENCE", "api://test-client-id")


@pytest.fixture
def test_client() -> Generator[TestClient, None, None]:
    """FastAPI TestClient for synchronous tests."""
    with TestClient(app) as client:
        yield client


@pytest.fixture
async def async_client() -> AsyncGenerator[httpx.AsyncClient, None]:
    """Async HTTP client for testing FastAPI app."""
    async with httpx.AsyncClient(base_url="http://testserver") as client:
        yield client


@pytest.fixture
def mock_jwks_response() -> Dict[str, Any]:
    """Mock JWKS response from Azure."""
    return {
        "keys": [
            {
                "kty": "RSA",
                "kid": "test-key-id",
                "use": "sig",
                "alg": "RS256",
                "n": "test-modulus",
                "e": "AQAB",
            }
        ]
    }


@pytest.fixture
def mock_user_claims() -> Dict[str, Any]:
    """Mock user claims from Azure token."""
    return {
        "iss": f"https://login.microsoftonline.com/{settings.azure_tenant_id}/v2.0",
        "aud": settings.api_audience,
        "sub": "test-subject-id",
        "oid": "test-user-object-id",
        "name": "Test User",
        "preferred_username": "testuser@example.com",
        "upn": "testuser@example.com",
        "roles": ["user", "admin"],
        "exp": int((datetime.now(timezone.utc) + timedelta(hours=1)).timestamp()),
        "iat": int(datetime.now(timezone.utc).timestamp()),
        "nbf": int(datetime.now(timezone.utc).timestamp()),
    }


@pytest.fixture
def valid_test_token(mock_user_claims: Dict[str, Any]) -> str:
    """Generate a valid test JWT token (unsigned for testing)."""
    return jwt.encode(mock_user_claims, "test-secret", algorithm="HS256")


@pytest.fixture
def expired_test_token(mock_user_claims: Dict[str, Any]) -> str:
    """Generate an expired test JWT token."""
    expired_claims = mock_user_claims.copy()
    expired_claims["exp"] = int(
        (datetime.now(timezone.utc) - timedelta(hours=1)).timestamp()
    )
    return jwt.encode(expired_claims, "test-secret", algorithm="HS256")


@pytest.fixture
def invalid_audience_token(mock_user_claims: Dict[str, Any]) -> str:
    """Generate a token with invalid audience."""
    invalid_claims = mock_user_claims.copy()
    invalid_claims["aud"] = "api://wrong-audience"
    return jwt.encode(invalid_claims, "test-secret", algorithm="HS256")


@pytest.fixture
def mock_azure_discovery():
    """Mock Azure discovery endpoint response."""
    with patch("httpx.AsyncClient.get") as mock_get:
        mock_response = MagicMock()
        mock_response.json.return_value = {
            "issuer": f"https://login.microsoftonline.com/{settings.azure_tenant_id}/v2.0",
            "jwks_uri": f"https://login.microsoftonline.com/{settings.azure_tenant_id}/discovery/v2.0/keys",
            "authorization_endpoint": f"https://login.microsoftonline.com/{settings.azure_tenant_id}/oauth2/v2.0/authorize",
            "token_endpoint": f"https://login.microsoftonline.com/{settings.azure_tenant_id}/oauth2/v2.0/token",
        }
        mock_response.raise_for_status = MagicMock()
        mock_get.return_value = mock_response
        yield mock_get


@pytest.fixture
def mock_jwks_endpoint(mock_jwks_response: Dict[str, Any]):
    """Mock JWKS endpoint response."""
    with patch("httpx.AsyncClient.get") as mock_get:
        mock_response = MagicMock()
        mock_response.json.return_value = mock_jwks_response
        mock_response.raise_for_status = MagicMock()
        mock_get.return_value = mock_response
        yield mock_get


@pytest.fixture
def mock_jwt_decode():
    """Mock JWT decode to skip signature verification in tests."""
    with patch("jwt.decode") as mock_decode:

        def side_effect(token, key, algorithms, **kwargs):
            # Return decoded token without verification for testing
            return jwt.decode(token, options={"verify_signature": False})

        mock_decode.side_effect = side_effect
        yield mock_decode


@pytest.fixture
def auth_headers(valid_test_token: str) -> Dict[str, str]:
    """Authorization headers with valid token."""
    return {"Authorization": f"Bearer {valid_test_token}"}


@pytest.fixture
def mock_msal_app():
    """Mock MSAL ConfidentialClientApplication for OBO flow."""
    with patch("fastapi_auth.obo.ConfidentialClientApplication") as mock_msal:
        mock_app = MagicMock()
        mock_msal.return_value = mock_app

        # Mock successful token acquisition
        mock_app.acquire_token_on_behalf_of.return_value = {
            "access_token": "mock-obo-token",
            "token_type": "Bearer",
            "expires_in": 3600,
            "scope": "https://graph.microsoft.com/.default",
        }

        yield mock_app


# Test utilities
class TestTokenBuilder:
    """Helper class to build test tokens with custom claims."""

    def __init__(self):
        self.claims = {
            "iss": f"https://login.microsoftonline.com/{settings.azure_tenant_id}/v2.0",
            "aud": settings.api_audience,
            "sub": "test-subject",
            "oid": "test-oid",
            "name": "Test User",
            "preferred_username": "test@example.com",
            "exp": int((datetime.now(timezone.utc) + timedelta(hours=1)).timestamp()),
            "iat": int(datetime.now(timezone.utc).timestamp()),
        }

    def with_roles(self, roles: list) -> "TestTokenBuilder":
        """Add roles to token claims."""
        self.claims["roles"] = roles
        return self

    def with_user_id(self, user_id: str) -> "TestTokenBuilder":
        """Set user ID (oid claim)."""
        self.claims["oid"] = user_id
        return self

    def with_email(self, email: str) -> "TestTokenBuilder":
        """Set user email."""
        self.claims["preferred_username"] = email
        return self

    def expired(self) -> "TestTokenBuilder":
        """Make token expired."""
        self.claims["exp"] = int(
            (datetime.now(timezone.utc) - timedelta(hours=1)).timestamp()
        )
        return self

    def build(self) -> str:
        """Build the JWT token."""
        return jwt.encode(self.claims, "test-secret", algorithm="HS256")


@pytest.fixture
def token_builder() -> TestTokenBuilder:
    """Token builder fixture."""
    return TestTokenBuilder()
