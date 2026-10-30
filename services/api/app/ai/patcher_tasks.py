"""Celery worker for generating and persisting reviewed patch candidates."""
from celery.exceptions import SoftTimeLimitExceeded
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from app.ai.patcher import PatchGenerationError, generate_patch
from app.auth.rbac import ensure_vulnerability_access, require_permission, resolve_workspace_context
from app.core.celery_app import celery_app
from app.db import SessionLocal
from app.models import CodePatch, Endpoint, EndpointParameter
from app.safety.credentials import decrypt_secret
from app.settings import settings


def _result(patch: CodePatch, organization_id: int, strategy: str = "", rationale: str = "") -> dict:
    return {"patch_id": patch.id, "vulnerability_id": patch.vulnerability_id,
            "organization_id": organization_id, "status": patch.status,
            "ai_confidence_score": patch.ai_confidence_score,
            "target_file_path": patch.target_file_path,
            "strategy": strategy, "rationale": rationale}


@celery_app.task(bind=True, name="app.ai.patcher_tasks.generate_patch_task",
                 acks_late=True, reject_on_worker_lost=True,
                 soft_time_limit=settings.celery_patch_soft_time_limit,
                 time_limit=settings.celery_patch_time_limit)
def generate_patch_task(self, vulnerability_id: int, target_file_path: str,
                        encrypted_source_code: str, organization_id: int,
                        authorization_header: str, db_dialect: str | None = None) -> dict:
    """Generate a candidate in a worker session after rechecking tenant and role."""
    with SessionLocal() as db:
        db.info["organization_id"] = organization_id
        try:
            clear_header = decrypt_secret(authorization_header)
            context = resolve_workspace_context(clear_header, db)
            if context.organization_id != organization_id:
                raise PermissionError("Task workspace does not match the authenticated workspace.")
            require_permission(context, "patches.generate")
            db.info["workspace_permissions"] = context.permissions
            existing = db.scalar(select(CodePatch).where(CodePatch.celery_task_id == self.request.id))
            if existing is not None:
                return _result(existing, organization_id)
            vulnerability = ensure_vulnerability_access(db, vulnerability_id, context)
            endpoint = db.get(Endpoint, vulnerability.endpoint_id)
            parameter = db.get(EndpointParameter, vulnerability.parameter_id) if vulnerability.parameter_id else None
            source_code = decrypt_secret(encrypted_source_code)
            candidate = generate_patch(vulnerability, target_file_path, source_code,
                                       db_dialect=db_dialect,
                                       endpoint_parameter=parameter.name if parameter else None)
            patch = CodePatch(vulnerability_id=vulnerability.id,
                              celery_task_id=self.request.id,
                              target_file_path=candidate.target_file_path,
                              unified_diff=candidate.unified_diff,
                              ai_confidence_score=candidate.confidence,
                              status="generated")
            db.add(patch)
            try:
                db.commit()
            except IntegrityError:
                db.rollback()
                existing = db.scalar(select(CodePatch).where(CodePatch.celery_task_id == self.request.id))
                if existing is not None:
                    return _result(existing, organization_id)
                raise
            db.refresh(patch)
            return _result(patch, organization_id, candidate.strategy, candidate.rationale)
        except SoftTimeLimitExceeded:
            db.rollback()
            raise RuntimeError("Patch generation exceeded its worker time limit.") from None
        except Exception as exc:
            db.rollback()
            safe_error = str(exc)
            if len(safe_error) > 500 or "\n" in safe_error:
                safe_error = "Patch generation task failed."
            raise RuntimeError(safe_error or "Patch generation task failed.") from None
