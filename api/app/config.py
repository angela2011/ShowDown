from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    database_url: str
    redis_url: str
    scan_queue_name: str = "scan_jobs"
    api_secret_key: str = "dev"
    rate_limit_per_minute: int = 30

    class Config:
        env_file = ".env"


settings = Settings()
