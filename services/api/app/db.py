from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, sessionmaker
from fastapi import Request

from app.settings import settings


class Base(DeclarativeBase):
    pass


engine = create_engine(settings.database_url, pool_pre_ping=True)
SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)


def get_db(request: Request):
    with SessionLocal() as session:
        # Liveness remains available; all data routes require a signed workspace identity by default.
        if settings.enterprise_auth_enabled and request.url.path != "/api/health":
            from app.auth.rbac import resolve_workspace_context
            context = resolve_workspace_context(request.headers.get("authorization"), session)
            session.info["organization_id"] = context.organization_id
            session.info["workspace_permissions"] = context.permissions
        yield session
