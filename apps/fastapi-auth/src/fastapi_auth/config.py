"""Application configuration using Pydantic Settings."""

import logging
from pathlib import Path
from typing import List, Optional
from pydantic_settings import BaseSettings, SettingsConfigDict
from dotenv import load_dotenv

# Explicitly load .env file
env_path = Path(__file__).parent.parent.parent / ".env"
if env_path.exists():
    load_dotenv(env_path)
    print(f"Loaded .env from: {env_path}")
else:
    print(f"No .env file found at: {env_path}")
    # Try current directory
    if Path(".env").exists():
        load_dotenv(".env")
        print("Loaded .env from current directory")


class Settings(BaseSettings):
    """Application settings with Azure Entra configuration."""

    model_config = SettingsConfigDict(
        env_file=[
            Path(__file__).parent.parent.parent / ".env",  # apps/fastapi-auth/.env
            ".env",  # current directory
        ],
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # Azure Entra settings (with defaults to avoid startup errors)
    azure_tenant_id: str = "00000000-0000-0000-0000-000000000000"
    azure_client_id: str = "00000000-0000-0000-0000-000000000000"
    azure_client_secret: str = "placeholder"
    api_audience: Optional[str] = None

    # Application settings
    app_name: str = "FastAPI Azure Entra Auth"
    app_version: str = "0.1.0"
    debug: bool = False

    # API settings
    api_prefix: str = "/api/v1"
    cors_origins: List[str] = ["http://localhost:3000", "http://localhost:5173"]
    cors_allow_credentials: bool = True
    cors_allow_methods: List[str] = ["GET", "POST", "PUT", "DELETE", "OPTIONS"]
    cors_allow_headers: List[str] = ["*"]

    # Token settings
    jwks_cache_ttl: int = 3600  # seconds

    @property
    def api_audience_computed(self) -> str:
        """Compute API audience if not explicitly set."""
        return self.api_audience or f"api://{self.azure_client_id}"

    @property
    def authority(self) -> str:
        """Azure Entra authority URL."""
        return f"https://login.microsoftonline.com/{self.azure_tenant_id}"


# Global settings instance
settings = Settings()

# Debug: Log loaded configuration (without secrets)
logger = logging.getLogger(__name__)
logger.info(f"Loaded config - Tenant ID: {settings.azure_tenant_id}")
logger.info(f"Loaded config - Client ID: {settings.azure_client_id}")
logger.info(f"Loaded config - API Audience: {settings.api_audience_computed}")
logger.info(f"Loaded config - Debug: {settings.debug}")
