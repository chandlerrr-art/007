from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    database_url: str = "postgresql+psycopg://007:007-local-only@localhost:5432/007"
    allowed_target_origins: str = "http://demo-app:8080"
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")


settings = Settings()
