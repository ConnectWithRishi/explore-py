"""FastAPI authentication endpoints using Azure Entra ID tenant-specific validation."""

import logging
from datetime import datetime, timezone
from typing import Dict, Any, Optional

import httpx
import jwt
from jwt.exceptions import InvalidTokenError, ExpiredSignatureError
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from msal import ConfidentialClientApplication
from pydantic import BaseModel

from .config import settings

logger = logging.getLogger(__name__)

# Initialize router
router = APIRouter(prefix="/auth", tags=["authentication"])

# Security scheme
security = HTTPBearer()


# Azure tenant-specific endpoints (constructed dynamically)
def get_tenant_discovery_endpoint() -> str:
    """Get tenant-specific discovery endpoint."""
    return f"https://login.microsoftonline.com/{settings.azure_tenant_id}/v2.0/.well-known/openid_configuration"


def get_tenant_jwks_endpoint() -> str:
    """Get tenant-specific JWKS endpoint."""
    return f"https://login.microsoftonline.com/{settings.azure_tenant_id}/discovery/v2.0/keys"


# MSAL app for tenant validation (lazy initialization)
_msal_app = None


def get_msal_app() -> ConfidentialClientApplication:
    """Get or create MSAL app instance."""
    global _msal_app
    if _msal_app is None:
        logger.info(f"Initializing MSAL app for tenant: {settings.azure_tenant_id}")
        _msal_app = ConfidentialClientApplication(
            client_id=settings.azure_client_id,
            client_credential=settings.azure_client_secret,
            authority=f"https://login.microsoftonline.com/{settings.azure_tenant_id}",
        )
    return _msal_app


class UserInfo(BaseModel):
    """User information extracted from Azure token."""

    id: str
    name: str
    email: str
    roles: list[str] = []


class AuthResponse(BaseModel):
    """Authentication response."""

    message: str
    user: Optional[UserInfo] = None
    timestamp: str


async def get_tenant_configuration() -> Dict[str, Any]:
    """
    Get Azure tenant-specific configuration using tenant discovery.
    If the discovery endpoint is not available, return a fallback configuration.

    Returns:
        Dict containing tenant configuration
    """
    async with httpx.AsyncClient() as client:
        try:
            # Try the v2.0 discovery endpoint first
            response = await client.get(get_tenant_discovery_endpoint(), timeout=10.0)
            response.raise_for_status()
            config = response.json()
            logger.info(
                f"Retrieved tenant configuration for tenant: {settings.azure_tenant_id}"
            )
            return config
        except Exception as e:
            logger.warning(
                f"Failed to get tenant configuration from discovery endpoint: {str(e)}"
            )

            # Fallback: construct the configuration manually based on tenant ID
            logger.info(
                f"Using fallback tenant configuration for tenant: {settings.azure_tenant_id}"
            )
            fallback_config = {
                "issuer": f"https://sts.windows.net/{settings.azure_tenant_id}/",
                "authorization_endpoint": f"https://login.microsoftonline.com/{settings.azure_tenant_id}/oauth2/v2.0/authorize",
                "token_endpoint": f"https://login.microsoftonline.com/{settings.azure_tenant_id}/oauth2/v2.0/token",
                "jwks_uri": f"https://login.microsoftonline.com/{settings.azure_tenant_id}/discovery/v2.0/keys",
                "response_types_supported": [
                    "code",
                    "id_token",
                    "code id_token",
                    "token id_token",
                    "token",
                ],
                "scopes_supported": ["openid", "profile", "email", "offline_access"],
                "id_token_signing_alg_values_supported": ["RS256"],
                "tenant_id": settings.azure_tenant_id,
                "cloud_instance_name": "microsoftonline.com",
                "msgraph_host": "graph.microsoft.com",
            }
            return fallback_config


async def get_tenant_jwks() -> Dict[str, Any]:
    """
    Get Azure tenant-specific JWKS (JSON Web Key Set).

    Returns:
        Dict containing JWKS
    """
    async with httpx.AsyncClient() as client:
        try:
            response = await client.get(get_tenant_jwks_endpoint(), timeout=10.0)
            response.raise_for_status()
            jwks = response.json()
            logger.info(f"Retrieved JWKS for tenant: {settings.azure_tenant_id}")
            return jwks
        except Exception as e:
            logger.error(f"Failed to get tenant JWKS: {str(e)}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to retrieve tenant JWKS",
            )


async def validate_token_with_azure(token: str) -> Dict[str, Any]:
    """
    Validate JWT token using Azure's JWKS (JSON Web Key Set).

    Args:
        token: The JWT access token to validate

    Returns:
        Dict containing validated token claims

    Raises:
        HTTPException: If token validation fails
    """
    # Log configuration for debugging
    logger.info("Token validation starting...")
    logger.info(f"Tenant ID: {settings.azure_tenant_id}")
    logger.info(f"Client ID: {settings.azure_client_id}")
    logger.info(f"Expected audience: {settings.api_audience_computed}")
    logger.info(f"Token length: {len(token)}")
    logger.info(f"Token preview: {token[:50]}...")

    try:
        # Decode JWT header to get the key ID (kid)
        unverified_header = jwt.get_unverified_header(token)
        kid = unverified_header.get("kid")
        logger.info(f"Token kid (key ID): {kid}")

        # Get JWKS from Azure
        jwks = await get_tenant_jwks()

        # Find the matching key
        rsa_key = None
        for key in jwks.get("keys", []):
            if key.get("kid") == kid:
                rsa_key = key
                break

        if rsa_key is None:
            logger.warning(f"No matching key found for kid: {kid}")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token signature",
                headers={"WWW-Authenticate": "Bearer"},
            )

        logger.info("Found matching RSA key, validating token...")

        # Validate JWT token - Azure tokens can have different issuer formats
        expected_issuer_v1 = f"https://sts.windows.net/{settings.azure_tenant_id}/"
        expected_issuer_v2 = (
            f"https://login.microsoftonline.com/{settings.azure_tenant_id}/v2.0"
        )

        # First decode token without verification to see what's inside
        unverified_payload = jwt.decode(token, options={"verify_signature": False})
        actual_issuer = unverified_payload.get("iss")
        actual_audience = unverified_payload.get("aud")

        logger.info(f"Token actual issuer: {actual_issuer}")
        logger.info(f"Token actual audience: {actual_audience}")
        logger.info(f"Expected issuer v1: {expected_issuer_v1}")
        logger.info(f"Expected issuer v2: {expected_issuer_v2}")
        logger.info(f"Expected audience: {settings.api_audience_computed}")

        # Determine which issuer format to use for validation
        expected_issuer = (
            expected_issuer_v1
            if actual_issuer == expected_issuer_v1
            else expected_issuer_v2
        )

        try:
            # Decode and validate the token using PyJWT
            payload = jwt.decode(
                token,
                jwt.PyJWK(rsa_key).key,  # Convert JWKS key to PyJWT format
                algorithms=["RS256"],
                audience=settings.api_audience_computed,
                issuer=expected_issuer,
                options={
                    "verify_signature": True,
                    "verify_exp": True,
                    "verify_aud": True,
                    "verify_iss": True,
                },
            )

            logger.info(
                f"Token validated successfully for user: {payload.get('oid', 'unknown')}"
            )
            logger.info(f"Token claims: {list(payload.keys())}")

            return payload

        except ExpiredSignatureError:
            logger.warning("Token has expired")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token has expired",
                headers={"WWW-Authenticate": "Bearer"},
            )
        except jwt.InvalidAudienceError:
            logger.warning("Invalid audience in token")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token audience",
                headers={"WWW-Authenticate": "Bearer"},
            )
        except jwt.InvalidIssuerError:
            logger.warning("Invalid issuer in token")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token issuer",
                headers={"WWW-Authenticate": "Bearer"},
            )
        except InvalidTokenError as e:
            logger.warning(f"Invalid token: {str(e)}")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token",
                headers={"WWW-Authenticate": "Bearer"},
            )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Token validation error: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Token validation service error",
        )


async def validate_azure_token(
    credentials: HTTPAuthorizationCredentials = Depends(security),
) -> Dict[str, Any]:
    """
    Validate Azure Entra ID token using tenant-specific Azure services.

    Args:
        credentials: HTTP Authorization credentials containing the Bearer token

    Returns:
        Dict containing validated token claims

    Raises:
        HTTPException: If token is invalid, expired, or malformed
    """
    token = credentials.credentials

    try:
        # Use Azure's tenant-specific validation
        token_claims = await validate_token_with_azure(token)
        return token_claims

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Unexpected token validation error: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Token validation failed",
        )


def extract_user_info(token_payload: Dict[str, Any]) -> UserInfo:
    """
    Extract user information from validated Azure token payload.

    Args:
        token_payload: Validated Azure token payload

    Returns:
        UserInfo object with user details
    """
    return UserInfo(
        id=token_payload.get("oid", ""),
        name=token_payload.get("name", ""),
        email=token_payload.get("preferred_username") or token_payload.get("upn", ""),
        roles=token_payload.get("roles", []),
    )


@router.get("/protected")
async def protected_endpoint(
    token_payload: Dict[str, Any] = Depends(validate_azure_token),
) -> AuthResponse:
    """
    Protected endpoint that requires valid Azure Entra ID token.

    Returns:
        AuthResponse with success message and user info
    """
    user_info = extract_user_info(token_payload)

    return AuthResponse(
        message="Access granted to protected resource",
        user=user_info,
        timestamp=datetime.now(timezone.utc).isoformat(),
    )


@router.get("/me", response_model=UserInfo)
async def get_current_user(
    token_payload: Dict[str, Any] = Depends(validate_azure_token),
) -> UserInfo:
    """
    Get current user information from validated Azure token.

    Returns:
        UserInfo object with current user details
    """
    return extract_user_info(token_payload)


@router.get("/roles")
async def get_user_roles(
    token_payload: Dict[str, Any] = Depends(validate_azure_token),
) -> Dict[str, list[str]]:
    """
    Get current user's roles from validated Azure token.

    Returns:
        Dictionary containing user roles
    """
    roles = token_payload.get("roles", [])
    return {"roles": roles}


@router.get("/tenant-info")
async def get_tenant_info() -> Dict[str, Any]:
    """
    Get Azure tenant configuration information.

    Returns:
        Dictionary with tenant configuration
    """
    config = await get_tenant_configuration()

    return {
        "tenant_id": settings.azure_tenant_id,
        "issuer": config.get("issuer"),
        "authorization_endpoint": config.get("authorization_endpoint"),
        "token_endpoint": config.get("token_endpoint"),
        "jwks_uri": config.get("jwks_uri"),
        "response_types_supported": config.get("response_types_supported"),
        "scopes_supported": config.get("scopes_supported"),
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@router.get("/token-info")
async def get_token_info(
    token_payload: Dict[str, Any] = Depends(validate_azure_token),
) -> Dict[str, Any]:
    """
    Get detailed information about the current Azure token.

    Returns:
        Dictionary with token information
    """
    return {
        "token_info": {
            "oid": token_payload.get("oid"),
            "name": token_payload.get("name"),
            "preferred_username": token_payload.get("preferred_username"),
            "tid": token_payload.get("tid"),
            "aud": token_payload.get("aud"),
            "iss": token_payload.get("iss"),
            "app_displayname": token_payload.get("app_displayname"),
            "appid": token_payload.get("appid"),
        },
        "validation_info": {
            "tenant_id": settings.azure_tenant_id,
            "client_id": settings.azure_client_id,
            "expected_audience": settings.api_audience_computed,
        },
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
