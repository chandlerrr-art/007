from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    database_url: str = "postgresql+psycopg://sentinelflow:sentinelflow-local-only@localhost:5432/sentinelflow"
    allowed_target_origins: str = "http://demo-app:8080"
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")


settings = Settings()
