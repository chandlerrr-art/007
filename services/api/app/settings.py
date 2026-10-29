from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    database_url: str = "postgresql+psycopg://007:007-local-only@localhost:5432/007"
    allowed_target_origins: str = "http://demo-app:8080"
    allowed_staging_origins: str = ""
    staging_request_budget: int = 10
    credential_encryption_key: str = "007-staging-secret-encryption-master-key-v1"
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")


settings = Settings()
