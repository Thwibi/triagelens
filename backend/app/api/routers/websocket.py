"""WebSocket progress subscriptions (spec 06 sections 3 and 4).

Two endpoints, both server-push only:

* ``/api/ws/jobs/{job_id}`` - everything about one job and the sources it owns.
* ``/api/ws/cases/{case_id}`` - everything about one case.

Both filter. An unfiltered subscription would send every case's alerts to every
analyst's browser, which is a data leak rather than a performance problem, so the
filter is applied here rather than left to the client.

The 30 second read timeout doubles as the liveness check: if nothing matched the
filter, a ping goes out, so a client watching an idle case still learns the socket
is alive.
"""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from typing import Any

from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from starlette.websockets import WebSocketState

from app.jobs.progress import ProgressBus

router = APIRouter()

#: How long a subscription waits for a matching message before pinging.
IDLE_PING_SECONDS = 30


def _job_filter(job_id: str) -> Callable[[dict[str, Any]], bool]:
    """True for messages that belong to one job."""

    def matches(message: dict[str, Any]) -> bool:
        if message.get("job_id") == job_id:
            return True
        job = message.get("job")
        return isinstance(job, dict) and job.get("id") == job_id

    return matches


def _case_filter(case_id: str) -> Callable[[dict[str, Any]], bool]:
    """True for messages that belong to one case."""

    def matches(message: dict[str, Any]) -> bool:
        if message.get("case_id") == case_id:
            return True
        for key in ("source", "job"):
            payload = message.get(key)
            if isinstance(payload, dict) and payload.get("case_id") == case_id:
                return True
        return False

    return matches


async def _heartbeat(ws: WebSocket) -> None:
    """Ping every 20 seconds so idle sockets are not reaped by proxies."""
    try:
        while True:
            await asyncio.sleep(20)
            if ws.client_state != WebSocketState.CONNECTED:
                return
            await ws.send_json({"type": "ping"})
    except (WebSocketDisconnect, RuntimeError):
        return


async def _pump(
    ws: WebSocket,
    bus: ProgressBus,
    matches: Callable[[dict[str, Any]], bool],
) -> None:
    """Forward matching messages until the client goes away."""
    queue = bus.subscribe()
    heartbeat = asyncio.create_task(_heartbeat(ws))
    try:
        await ws.send_json({"type": "ping"})
        while ws.client_state == WebSocketState.CONNECTED:
            try:
                message = await asyncio.wait_for(queue.get(), timeout=IDLE_PING_SECONDS)
            except TimeoutError:
                await ws.send_json({"type": "ping"})
                continue
            if matches(message):
                await ws.send_json(message)
    except (TimeoutError, WebSocketDisconnect, RuntimeError):
        return
    finally:
        heartbeat.cancel()
        bus.unsubscribe(queue)


@router.websocket("/ws/jobs/{job_id}")
async def ws_job(job_id: str, websocket: WebSocket) -> None:
    """Progress for one job and the sources it owns."""
    await websocket.accept()
    bus: ProgressBus = websocket.app.state.progress
    await _pump(websocket, bus, _job_filter(job_id))


@router.websocket("/ws/cases/{case_id}")
async def ws_case(case_id: str, websocket: WebSocket) -> None:
    """Progress and alert changes for one case."""
    await websocket.accept()
    bus: ProgressBus = websocket.app.state.progress
    await _pump(websocket, bus, _case_filter(case_id))


__all__ = ["router"]
