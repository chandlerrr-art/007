from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    database_url: str = "postgresql+psycopg://007:007-local-only@localhost:5432/007"
    allowed_target_origins: str = "http://demo-app:8080"
    allowed_staging_origins: str = ""
    staging_request_budget: int = 10
    credential_encryption_key: str = ""
    jira_base_url: str = ""
    jira_email: str = ""
    jira_api_token: str = ""
    jira_project_key: str = ""
    github_owner: str = ""
    github_repo: str = ""
    github_token: str = ""
    enterprise_auth_enabled: bool = True
    enterprise_auth_secret: str = ""
    master_kek_secret: str = ""
    master_kek_key_id: str = "env-v1"
    redis_url: str = "redis://redis:6379/0"
    celery_always_eager: bool = False
    celery_scan_soft_time_limit: int = 900
    celery_scan_time_limit: int = 960
    celery_patch_soft_time_limit: int = 180
    celery_patch_time_limit: int = 210
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")


settings = Settings()
