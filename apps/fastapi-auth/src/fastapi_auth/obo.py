"""FastAPI On-Behalf-Of (OBO) flow endpoints for Azure Entra ID."""

import logging
from datetime import datetime, timezone
from typing import Dict, Any, Optional

import httpx
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from msal import ConfidentialClientApplication
from pydantic import BaseModel

from .auth import validate_azure_token
from .config import settings

logger = logging.getLogger(__name__)

# Initialize router
router = APIRouter(prefix="/obo", tags=["on-behalf-of"])

# Security scheme
security = HTTPBearer()

# MSAL Confidential Client for OBO flow
# Initialize this lazily to avoid startup issues
msal_app = None


def get_msal_app():
    """Get or create MSAL confidential client application."""
    global msal_app
    if msal_app is None:
        logger.info(f"Initializing OBO MSAL app for tenant: {settings.azure_tenant_id}")
        msal_app = ConfidentialClientApplication(
            client_id=settings.azure_client_id,
            client_credential=settings.azure_client_secret,
            authority=f"https://login.microsoftonline.com/{settings.azure_tenant_id}",
        )
    return msal_app


class OBOResponse(BaseModel):
    """OBO flow response."""

    success: bool
    message: str
    data: Optional[Dict[str, Any]] = None
    timestamp: str


async def get_obo_token(user_token: str, scopes: list[str]) -> str:
    """
    Exchange user token for OBO token with specified scopes.

    Args:
        user_token: User's access token
        scopes: List of scopes to request for OBO token

    Returns:
        OBO access token

    Raises:
        HTTPException: If OBO token acquisition fails
    """
    try:
        msal_app = get_msal_app()
        result = msal_app.acquire_token_on_behalf_of(
            user_assertion=user_token, scopes=scopes
        )

        if "access_token" in result:
            logger.info(f"OBO token acquired successfully for scopes: {scopes}")
            return result["access_token"]
        else:
            error_msg = result.get(
                "error_description", "Unknown error during OBO token acquisition"
            )
            logger.error(f"OBO token acquisition failed: {error_msg}")
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Failed to acquire OBO token: {error_msg}",
            )

    except Exception as e:
        logger.error(f"OBO token acquisition error: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="OBO token acquisition failed",
        )


@router.get("/graph/me")
async def get_graph_me(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    token_payload: Dict[str, Any] = Depends(validate_azure_token),
) -> OBOResponse:
    """
    Use OBO flow to call Microsoft Graph /me endpoint.

    Returns:
        OBOResponse with user's Graph profile information
    """
    user_token = credentials.credentials
    graph_scopes = ["https://graph.microsoft.com/User.Read"]

    try:
        # Get OBO token for Microsoft Graph
        obo_token = await get_obo_token(user_token, graph_scopes)

        # Call Microsoft Graph API
        async with httpx.AsyncClient() as client:
            response = await client.get(
                "https://graph.microsoft.com/v1.0/me",
                headers={
                    "Authorization": f"Bearer {obo_token}",
                    "Content-Type": "application/json",
                },
                timeout=30.0,
            )

            if response.status_code == 200:
                graph_data = response.json()
                logger.info(
                    f"Graph API call successful for user: {graph_data.get('id', 'unknown')}"
                )

                return OBOResponse(
                    success=True,
                    message="Successfully retrieved user profile from Microsoft Graph",
                    data=graph_data,
                    timestamp=datetime.now(timezone.utc).isoformat(),
                )
            else:
                logger.error(
                    f"Graph API call failed: {response.status_code} - {response.text}"
                )
                raise HTTPException(
                    status_code=status.HTTP_502_BAD_GATEWAY,
                    detail=f"Microsoft Graph API error: {response.status_code}",
                )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Graph API call error: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to call Microsoft Graph API",
        )


@router.get("/graph/profile")
async def get_graph_profile(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    token_payload: Dict[str, Any] = Depends(validate_azure_token),
) -> OBOResponse:
    """
    Use OBO flow to get extended user profile from Microsoft Graph.

    Returns:
        OBOResponse with extended user profile information
    """
    user_token = credentials.credentials
    graph_scopes = ["https://graph.microsoft.com/User.Read"]

    try:
        # Get OBO token for Microsoft Graph
        obo_token = await get_obo_token(user_token, graph_scopes)

        # Call Microsoft Graph API for extended profile
        async with httpx.AsyncClient() as client:
            response = await client.get(
                "https://graph.microsoft.com/v1.0/me?$select=id,displayName,mail,userPrincipalName,jobTitle,department,officeLocation,businessPhones,mobilePhone",
                headers={
                    "Authorization": f"Bearer {obo_token}",
                    "Content-Type": "application/json",
                },
                timeout=30.0,
            )

            if response.status_code == 200:
                profile_data = response.json()
                logger.info(
                    f"Graph profile API call successful for user: {profile_data.get('id', 'unknown')}"
                )

                return OBOResponse(
                    success=True,
                    message="Successfully retrieved extended user profile from Microsoft Graph",
                    data=profile_data,
                    timestamp=datetime.now(timezone.utc).isoformat(),
                )
            else:
                logger.error(
                    f"Graph profile API call failed: {response.status_code} - {response.text}"
                )
                raise HTTPException(
                    status_code=status.HTTP_502_BAD_GATEWAY,
                    detail=f"Microsoft Graph API error: {response.status_code}",
                )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Graph profile API call error: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to call Microsoft Graph API",
        )


@router.post("/long-task")
async def start_long_running_task(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    token_payload: Dict[str, Any] = Depends(validate_azure_token),
) -> OBOResponse:
    """
    Start a long-running background task using OBO token.
    This demonstrates how OBO tokens can be used for tasks that outlast the original user session.

    Returns:
        OBOResponse with task information
    """
    user_token = credentials.credentials
    graph_scopes = ["https://graph.microsoft.com/User.Read"]

    try:
        # Get OBO token for long-running task
        obo_token = await get_obo_token(user_token, graph_scopes)

        # In a real implementation, you would:
        # 1. Store the OBO token securely
        # 2. Queue the background task
        # 3. Return a task ID for status checking

        # For demo purposes, we'll just verify the token works
        async with httpx.AsyncClient() as client:
            response = await client.get(
                "https://graph.microsoft.com/v1.0/me?$select=id,displayName",
                headers={
                    "Authorization": f"Bearer {obo_token}",
                    "Content-Type": "application/json",
                },
                timeout=30.0,
            )

            if response.status_code == 200:
                user_data = response.json()
                task_id = f"task_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{user_data.get('id', 'unknown')[:8]}"

                return OBOResponse(
                    success=True,
                    message="Long-running task started successfully",
                    data={
                        "task_id": task_id,
                        "user": user_data,
                        "status": "started",
                        "estimated_completion": "2-5 minutes",
                    },
                    timestamp=datetime.now(timezone.utc).isoformat(),
                )
            else:
                raise HTTPException(
                    status_code=status.HTTP_502_BAD_GATEWAY,
                    detail="Failed to verify OBO token for long-running task",
                )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Long-running task start error: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to start long-running task",
        )


@router.get("/job/{job_id}")
async def get_job_status(
    job_id: str, token_payload: Dict[str, Any] = Depends(validate_azure_token)
) -> OBOResponse:
    """
    Get status of a long-running job.

    Args:
        job_id: ID of the job to check

    Returns:
        OBOResponse with job status information
    """
    # In a real implementation, you would:
    # 1. Query your job storage/database
    # 2. Return actual job status and results

    # For demo purposes, return mock status
    return OBOResponse(
        success=True,
        message="Job status retrieved successfully",
        data={
            "job_id": job_id,
            "status": "completed",
            "progress": 100,
            "result": "Job completed successfully",
            "completed_at": datetime.now(timezone.utc).isoformat(),
        },
        timestamp=datetime.now(timezone.utc).isoformat(),
    )
