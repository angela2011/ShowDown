from pydantic_settings import BaseSettings
from pydantic import Field


class Settings(BaseSettings):
    database_url: str
    redis_url: str
    scan_queue_name: str = "scan_jobs"
    api_secret_key: str = "dev"  # Legacy setting; opaque sessions do not use signing keys.
    auth_session_hours: int = Field(default=8, ge=1, le=168)
    rate_limit_per_minute: int = 30

    class Config:
        env_file = ".env"


settings = Settings()
