from typing import Protocol, runtime_checkable

from sqlalchemy.orm import Session

from app.models import Scan, Target
from app.safety.policy import supports_demo_executor
from app.scans.staging_executor import StagingTargetExecutor


@runtime_checkable
class BaseScanExecutor(Protocol):
    name: str

    def supports(self, target: Target) -> bool: ...

    def run(
        self,
        db: Session,
        scan: Scan,
        target: Target,
        retest_finding_id: int | None = None,
    ) -> tuple[bool, str]: ...


class LocalDemoExecutor:
    """Wraps the existing local-demo IDOR check without touching or altering its logic."""
    name: str = "local_demo"

    def supports(self, target: Target) -> bool:
        return supports_demo_executor(target)

    def run(
        self,
        db: Session,
        scan: Scan,
        target: Target,
        retest_finding_id: int | None = None,
    ) -> tuple[bool, str]:
        # Delegate to orchestrator's existing local-demo check
        from app.scans.orchestrator import _run_access_control_check
        from app.models import Endpoint
        from sqlalchemy import select

        endpoint = db.execute(
            select(Endpoint).where(Endpoint.target_id == target.id, Endpoint.path == "/api/v1/bookings/{booking_id}")
        ).scalars().first()
        return _run_access_control_check(db, scan, target, endpoint, retest_finding_id)


class ExecutorRegistry:
    def __init__(self) -> None:
        self._executors: dict[str, BaseScanExecutor] = {}

    def register(self, executor: BaseScanExecutor) -> None:
        self._executors[executor.name] = executor

    def unregister(self, name: str) -> None:
        self._executors.pop(name, None)

    def get(self, name: str) -> BaseScanExecutor | None:
        return self._executors.get(name)

    def get_for_target(self, target: Target) -> BaseScanExecutor | None:
        for executor in self._executors.values():
            if executor.supports(target):
                return executor
        return None

    def list_all(self) -> list[BaseScanExecutor]:
        return list(self._executors.values())


executor_registry = ExecutorRegistry()
executor_registry.register(LocalDemoExecutor())
executor_registry.register(StagingTargetExecutor())
