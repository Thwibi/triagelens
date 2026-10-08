from __future__ import annotations

import asyncio
import contextlib
from typing import Any

from app.models.job import JobRecord


class ProgressBus:
    def __init__(self) -> None:
        self._subscribers: set[asyncio.Queue[dict[str, Any]]] = set()

    def subscribe(self) -> asyncio.Queue[dict[str, Any]]:
        queue: asyncio.Queue[dict[str, Any]] = asyncio.Queue()
        self._subscribers.add(queue)
        return queue

    def unsubscribe(self, queue: asyncio.Queue[dict[str, Any]]) -> None:
        self._subscribers.discard(queue)

    async def publish(self, payload: dict[str, Any]) -> None:
        for queue in list(self._subscribers):
            with contextlib.suppress(asyncio.QueueFull):
                queue.put_nowait(payload)

    async def job_update(self, job: JobRecord) -> None:
        await self.publish({"type": "job.update", "job": job.model_dump(mode="json")})

    async def job_stage(  # noqa: PLR0917
        self,
        job_id: str,
        stage: str,
        progress: float,
        events: int = 0,
        errors: int = 0,
        rate_eps: int = 0,
        case_id: str | None = None,
    ) -> None:
        await self.publish(
            {
                "type": "job.stage",
                "job_id": job_id,
                # Carried so a case subscription can filter without a lookup. Extra
                # fields are additive: spec 06's example shows the required ones.
                "case_id": case_id,
                "stage": stage,
                "progress": max(0.0, min(1.0, float(progress))),
                "events": events,
                "errors": errors,
                "rate_eps": rate_eps,
            }
        )

    async def source_update(self, source: dict[str, Any], *, job_id: str | None = None) -> None:
        await self.publish({"type": "source.update", "source": source, "job_id": job_id})

    async def needs_input(
        self,
        job_id: str,
        source_id: str,
        candidates: list[dict[str, Any]],
        case_id: str | None = None,
    ) -> None:
        await self.publish(
            {
                "type": "needs_input",
                "job_id": job_id,
                "case_id": case_id,
                "source_id": source_id,
                "candidates": candidates,
            }
        )

    async def error(self, code: str, message: str) -> None:
        await self.publish({"type": "error", "code": code, "message": message})


__all__ = ["ProgressBus"]
