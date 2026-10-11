"""End-to-end ingest through the API (Phase 1 acceptance, spec 11).

These tests drive the real pipeline: a real HTTP upload, a real worker process, a
real writer thread and the real database. Nothing is stubbed, because what is worth
testing here is exactly the boundaries between those pieces: a batch crossing a
process boundary, a cancel arriving through a shared event, a worker dying
mid-parse.

The helpers at the top build the fixtures the acceptance criteria name: an ECS
NDJSON file and a ZIP containing three files.
"""

from __future__ import annotations

import asyncio
import hashlib
import io
import json
import os
import socket
import sqlite3
import stat
import threading
import time
import zipfile
from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

import httpx
import pytest
import uvicorn
from fastapi.testclient import TestClient
from websockets.sync.client import connect

from app.config import Settings
from app.jobs.parsing import TAG_BATCH, ParseBatch, ParseRequest, parse_and_emit
from app.main import create_app

#: How long to wait for a background job before declaring it stuck. Generous,
#: because a worker process on a loaded machine is slow, but bounded so a broken
#: pipeline fails instead of hanging the suite.
JOB_TIMEOUT_SECONDS = 60.0

#: Terminal job states, as strings from the jobs table. ``needs_input`` is one of
#: them: the job stopped and is waiting on the operator.
TERMINAL = {"done", "failed", "cancelled", "needs_input"}


@pytest.fixture
def client(settings: Settings) -> Iterator[TestClient]:
    """A client with the full lifespan, so the worker pool really starts."""
    with TestClient(create_app(settings), base_url="http://127.0.0.1:8787") as test_client:
        yield test_client


@pytest.fixture
def case_id(client: TestClient) -> str:
    """A case to upload into."""
    response = client.post("/api/cases", json={"name": "acceptance"})
    assert response.status_code == 201, response.text
    payload: dict[str, Any] = response.json()
    return str(payload["id"])


def ecs_lines(count: int, *, host: str = "web-01") -> str:
    """``count`` ECS records as NDJSON, one per line."""
    records = [
        {
            "@timestamp": f"2024-01-01T00:00:{second:02d}.000Z",
            "ecs": {"version": "8.11.0"},
            "host": {"name": host},
            "log": {"level": "info"},
            "message": f"request {second} handled",
            "process": {"name": "nginx", "pid": 1000 + second},
            "event": {"category": "web", "dataset": "nginx.access"},
        }
        for second in range(count)
    ]
    return "".join(json.dumps(record) + "\n" for record in records)


def zip_bytes(members: list[tuple[str, bytes]]) -> bytes:
    """A ZIP archive containing exactly the named members."""
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        for member_name, payload in members:
            archive.writestr(member_name, payload)
    return buffer.getvalue()


def zip_with_three_files() -> bytes:
    """The ZIP from the acceptance criteria: three NDJSON members."""
    return zip_bytes(
        [
            ("one.ndjson", ecs_lines(3).encode()),
            ("two.ndjson", ecs_lines(2).encode()),
            ("three.ndjson", ecs_lines(1).encode()),
        ]
    )


def hostile_zip(member: str, payload: bytes = b"", *, symlink: bool = False) -> bytes:
    """A ZIP whose single member carries a hostile name, or is a symlink.

    ``zipfile`` refuses to build most of these, so a placeholder entry is written
    and its name is rewritten afterwards -- which is exactly what a real malicious
    archive looks like to the extractor.

    The placeholder is the *same byte length* as the hostile name and the member
    is stored uncompressed. Both matter: a ZIP's central directory records byte
    offsets, so a longer or shorter name would shift them and produce a corrupt
    archive that gets rejected for the wrong reason, and deflated bytes could
    happen to contain the placeholder text and be rewritten too.
    """
    target = member.encode("utf-8")
    placeholder = b"x" * len(target)
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_STORED) as archive:
        info = zipfile.ZipInfo(placeholder.decode())
        if symlink:
            info.create_system = 3  # Unix, so external_attr carries the mode
            info.external_attr = (stat.S_IFLNK | 0o777) << 16
        else:
            info.external_attr = 0o644 << 16
        archive.writestr(info, payload)
    return buffer.getvalue().replace(placeholder, target)


def zip_bomb(members: int = 40, payload_bytes: int = 512_000) -> bytes:
    """A ZIP that expands far past its own size.

    Forty members of half a megabyte of zeros compress to almost nothing, which is
    the shape a real bomb has: a small upload, a very large extraction.
    """
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        for index in range(members):
            archive.writestr(f"member{index:03d}.ndjson", b"0" * payload_bytes)
    return buffer.getvalue()


def upload(client: TestClient, case_id: str, *files: tuple[str, bytes], **form: str) -> Any:
    """POST a multipart upload and return the decoded body."""
    handles = [
        ("files", (name, io.BytesIO(payload), "application/octet-stream"))
        for name, payload in files
    ]
    try:
        response = client.post(f"/api/cases/{case_id}/sources", files=handles, data=form or None)
    finally:
        for _, stream in handles:
            stream[1].close()
    assert response.status_code == 202, response.text
    return response.json()


def wait_for_job(client: TestClient, job_id: str, *, expect: str | None = None) -> dict[str, Any]:
    """Poll a job until it reaches a terminal state.

    Polling rather than subscribing because these tests assert on the persisted
    result; the WebSocket path is covered on its own.
    """
    deadline = time.monotonic() + JOB_TIMEOUT_SECONDS
    last: dict[str, Any] = {}
    while time.monotonic() < deadline:
        response = client.get(f"/api/jobs/{job_id}")
        assert response.status_code == 200, response.text
        last = response.json()
        if expect is not None and last["status"] == expect:
            return last
        if last["status"] in TERMINAL:
            return last
        time.sleep(0.05)
    pytest.fail(f"job {job_id} never finished; last status was {last!r}")


def source_state(client: TestClient, source_id: str) -> dict[str, Any]:
    """The source row as the API reports it."""
    response = client.get(f"/api/sources/{source_id}")
    assert response.status_code == 200, response.text
    result: dict[str, Any] = response.json()
    return result


class _CapturingBridge:
    """A stand-in channel that keeps the worker's messages instead of a queue.

    The worker only ever calls ``put``, ``cancel`` and ``is_cancelled`` on the
    bridge, so this exercises the real :func:`parse_and_emit` while letting the
    test inspect every batch that would have crossed a process boundary.
    """

    def __init__(self) -> None:
        self.messages: list[tuple[str, Any]] = []

    def put(self, tag: str, payload: Any) -> None:
        self.messages.append((tag, payload))

    def cancel(self) -> None:
        """Nothing to signal: this bridge never reports itself cancelled."""

    def is_cancelled(self) -> bool:
        return False


class TestNdjsonIngest:
    """An ECS NDJSON upload ingests every event with a correct hash."""

    def test_upload_returns_202_with_a_job_and_a_source(
        self, client: TestClient, case_id: str
    ) -> None:
        body = upload(client, case_id, ("access.ndjson", ecs_lines(5).encode()))

        assert list(body) == ["jobs", "sources"]
        assert len(body["jobs"]) == 1
        assert len(body["sources"]) == 1
        assert body["jobs"][0]["status"] == "queued"
        assert body["sources"][0]["status"] == "queued"
        assert body["sources"][0]["filename"] == "access.ndjson"

    def test_events_are_stored_and_counted(self, client: TestClient, case_id: str) -> None:
        body = upload(client, case_id, ("access.ndjson", ecs_lines(5).encode()))
        job = wait_for_job(client, body["jobs"][0]["id"], expect="done")

        assert job["status"] == "done"
        source = source_state(client, body["sources"][0]["id"])
        assert source["status"] == "done"
        assert source["event_count"] == 5
        assert source["error_count"] == 0
        assert source["first_event_ms"] is not None
        assert source["last_event_ms"] >= source["first_event_ms"]

    def test_a_file_crossing_the_batch_boundary_stores_each_event_once(
        self, client: TestClient, case_id: str
    ) -> None:
        """More events than one batch, so the batch is emptied mid-file.

        The batch hand-off used to leave the source batch full, so every record
        after the first flush was emitted again: a file this size stored every
        event twice and reported a doubled count. Evidence is counted once, and
        this is the size where that only shows up if the boundary is crossed.
        """
        count = 5_001  # one past the 5,000-event batch
        body = upload(client, case_id, ("long.ndjson", ecs_lines(count).encode()))
        wait_for_job(client, body["jobs"][0]["id"], expect="done")

        source = source_state(client, body["sources"][0]["id"])
        assert source["status"] == "done"
        assert source["event_count"] == count

    def test_sha256_is_recorded_and_the_download_matches(
        self, client: TestClient, case_id: str
    ) -> None:
        payload = ecs_lines(4).encode()
        body = upload(client, case_id, ("access.ndjson", payload))
        wait_for_job(client, body["jobs"][0]["id"], expect="done")

        source = source_state(client, body["sources"][0]["id"])
        assert source["sha256"] == hashlib.sha256(payload).hexdigest()

        download = client.get(f"/api/sources/{source['id']}/download")
        assert download.status_code == 200
        assert download.headers["X-SHA256"] == source["sha256"]
        assert download.content == payload

    def test_malformed_records_become_parse_errors_not_a_failed_source(
        self, client: TestClient, case_id: str
    ) -> None:
        payload = (ecs_lines(3) + '{"not": "a log line"}\n').encode()
        body = upload(client, case_id, ("mixed.ndjson", payload))
        job = wait_for_job(client, body["jobs"][0]["id"], expect="done")

        assert job["status"] == "done"
        source_id = body["sources"][0]["id"]
        source = source_state(client, source_id)
        assert source["status"] == "done"
        assert source["event_count"] == 3
        assert source["error_count"] >= 1

        listing = client.get(f"/api/sources/{source_id}/parse-errors").json()
        assert listing["total"] >= 1
        assert listing["items"][0]["reason"]

    def test_several_uploads_of_one_case_are_ingested_each(
        self, client: TestClient, case_id: str
    ) -> None:
        first = upload(client, case_id, ("a.ndjson", ecs_lines(2).encode()))
        second = upload(client, case_id, ("b.ndjson", ecs_lines(3).encode()))
        wait_for_job(client, first["jobs"][0]["id"], expect="done")
        wait_for_job(client, second["jobs"][0]["id"], expect="done")

        listed = client.get(f"/api/cases/{case_id}/sources").json()
        assert listed["total"] == 2
        assert sum(int(item["event_count"]) for item in listed["items"]) == 5


class TestZipIngest:
    """A ZIP becomes one source per member and every member is ingested."""

    def test_each_member_becomes_a_source(self, client: TestClient, case_id: str) -> None:
        body = upload(client, case_id, ("bundle.zip", zip_with_three_files()))

        assert len(body["sources"]) == 3
        assert {item["filename"] for item in body["sources"]} == {
            "one.ndjson",
            "two.ndjson",
            "three.ndjson",
        }

    def test_members_are_ingested_with_their_own_counts(
        self, client: TestClient, case_id: str
    ) -> None:
        body = upload(client, case_id, ("bundle.zip", zip_with_three_files()))
        job = wait_for_job(client, body["jobs"][0]["id"], expect="done")

        assert job["status"] == "done"
        by_name = {item["filename"]: item for item in body["sources"]}
        for name, count in {"one.ndjson": 3, "two.ndjson": 2, "three.ndjson": 1}.items():
            source = source_state(client, by_name[name]["id"])
            assert source["status"] == "done", name
            assert source["event_count"] == count, name

    def test_members_point_at_their_container(self, client: TestClient, case_id: str) -> None:
        body = upload(client, case_id, ("bundle.zip", zip_with_three_files()))
        wait_for_job(client, body["jobs"][0]["id"], expect="done")

        parents = {item["parent_source_id"] for item in body["sources"]}
        assert len(parents) == 1
        container = parents.pop()
        # The container is not one of the member sources: the archive itself is
        # stored but never parsed.
        assert container is not None
        assert container not in {item["id"] for item in body["sources"]}

    def test_deleting_the_container_removes_its_members(
        self, client: TestClient, case_id: str
    ) -> None:
        """The bundle is one deletable unit, which is what the FK cascade is for."""
        body = upload(client, case_id, ("bundle.zip", zip_with_three_files()))
        wait_for_job(client, body["jobs"][0]["id"], expect="done")
        container = body["sources"][0]["parent_source_id"]
        member_ids = [item["id"] for item in body["sources"]]

        deleted = client.delete(f"/api/sources/{container}")
        assert deleted.status_code == 200, deleted.text

        for member_id in member_ids:
            assert client.get(f"/api/sources/{member_id}").status_code == 404
        assert client.get(f"/api/cases/{case_id}/sources").json()["total"] == 0


def _die_in_worker() -> None:
    """Kill the worker process outright, the way a segfault or OOM kill does.

    Module level so the child process can unpickle it, and it must not raise:
    the point is that nothing in this process gets to report anything.
    """
    os._exit(17)


class TestWorkerCrash:
    """A dead worker fails its own job and nothing else (spec 11 phase 1).

    The acceptance criteria call for surviving a worker crash, which has two
    halves. The crash itself is a hard ``os._exit``, not an exception, because an
    exception would leave the pool usable and would prove nothing. The recovery
    matters just as much: ``ProcessPoolExecutor`` stays broken once a worker dies,
    so the pool has to be rebuilt or every later job fails too.
    """

    @staticmethod
    def _crash_one_worker(client: TestClient) -> None:
        """Run a job whose worker dies, and wait for the failure to land."""
        manager = client.app.state.job_manager  # type: ignore[attr-defined]
        finished: list[BaseException | None] = []

        async def crasher(item: dict[str, Any]) -> None:
            try:
                await asyncio.wrap_future(manager.submit(_die_in_worker))
            except BaseException as error:  # recorded so the test can assert on what happened
                finished.append(error)

        manager.register_handler("test-crasher", crasher)
        assert client.portal is not None
        client.portal.call(manager.enqueue, "crash-job", {"kind": "test-crasher"})

        deadline = time.monotonic() + JOB_TIMEOUT_SECONDS
        while time.monotonic() < deadline and not finished:
            time.sleep(0.01)
        assert finished, "the crashing worker never reported a failure"

    def test_a_dead_worker_is_reported_and_the_pool_is_rebuilt(
        self, client: TestClient, case_id: str
    ) -> None:
        self._crash_one_worker(client)

        # The pool is poisoned after a hard worker death, so this upload only
        # succeeds if a fresh pool was built for it.
        body = upload(client, case_id, ("after-crash.ndjson", ecs_lines(3).encode()))
        job = wait_for_job(client, body["jobs"][0]["id"], expect="done")
        assert job["status"] == "done"

        source = source_state(client, body["sources"][0]["id"])
        assert source["status"] == "done"
        assert source["event_count"] == 3

    def test_the_server_is_healthy_after_a_worker_death(self, client: TestClient) -> None:
        self._crash_one_worker(client)

        health = client.get("/api/health")
        assert health.status_code == 200, health.text
        body = health.json()
        # The API process answers with real numbers, not a stub: the crash took a
        # worker process, not the server holding the case.
        assert body["sqlite_version"]
        assert body["workers"] >= 1


class TestCancellation:
    """A cancelled job stops and leaves nothing half-ingested (spec 06 jobs).

    Cancellation is the one thing a user can do while a large file is being
    parsed, so it has to work at both moments that matter: while the job is still
    queued, and while its worker is mid-file.
    """

    @staticmethod
    def _block_dispatcher(client: TestClient) -> threading.Event:
        """Occupy the single dispatcher so a real job waits behind it.

        The queue is deliberately sequential, so holding the dispatcher is what
        makes "cancelled while queued" reproducible instead of a race against a
        fast worker. Returns the event that releases it.
        """
        release = threading.Event()
        started = threading.Event()

        async def blocker(item: dict[str, Any]) -> None:
            started.set()
            # Wait on the thread event off-loop rather than polling, so the
            # dispatcher parks here until the test releases it.
            await asyncio.to_thread(release.wait)

        manager = client.app.state.job_manager  # type: ignore[attr-defined]
        manager.register_handler("test-blocker", blocker)
        assert client.portal is not None
        client.portal.call(manager.enqueue, "blocker-job", {"kind": "test-blocker"})
        assert started.wait(5.0), "the blocker job never started"
        return release

    def test_cancelling_a_queued_job_stops_it_before_any_work(
        self, client: TestClient, case_id: str
    ) -> None:
        release = self._block_dispatcher(client)
        try:
            body = upload(client, case_id, ("queued.ndjson", ecs_lines(5).encode()))
            job_id = body["jobs"][0]["id"]
            source_id = body["sources"][0]["id"]
            assert client.get(f"/api/jobs/{job_id}").json()["status"] == "queued"

            response = client.delete(f"/api/jobs/{job_id}")
            assert response.status_code == 200, response.text
            assert response.json() == {"id": job_id, "cancelling": True}
        finally:
            release.set()

        job = wait_for_job(client, job_id, expect="cancelled")
        assert job["status"] == "cancelled"
        assert job["started_at"] is None
        # Nothing was parsed, so the source is cancelled with no events rather than
        # left queued for a job that will never come.
        source = source_state(client, source_id)
        assert source["status"] == "cancelled"
        assert source["event_count"] == 0

    def test_cancelling_mid_parse_discards_the_events_already_stored(
        self, client: TestClient, case_id: str
    ) -> None:
        """Cancelling while the worker is mid-file removes its partial events."""
        # Big enough that the cancel lands while the worker is still reading: a
        # small file finishes before the request can be made.
        body = upload(client, case_id, ("long.ndjson", ecs_lines(20_000).encode()))
        job_id = body["jobs"][0]["id"]
        source_id = body["sources"][0]["id"]

        deadline = time.monotonic() + JOB_TIMEOUT_SECONDS
        while time.monotonic() < deadline:
            job = client.get(f"/api/jobs/{job_id}").json()
            if job["status"] == "running":
                break
            if job["status"] in TERMINAL:
                pytest.fail(f"job finished before it could be cancelled: {job!r}")
            time.sleep(0.01)

        response = client.delete(f"/api/jobs/{job_id}")
        assert response.status_code == 200, response.text

        job = wait_for_job(client, job_id, expect="cancelled")
        assert job["status"] == "cancelled"
        source = source_state(client, source_id)
        assert source["status"] == "cancelled"
        # Partial evidence is worse than none: a cancelled source stores nothing.
        assert source["event_count"] == 0
        assert source["error_count"] == 0
        assert source["first_event_ms"] is None

    def test_cancelling_a_finished_job_is_a_conflict(
        self, client: TestClient, case_id: str
    ) -> None:
        body = upload(client, case_id, ("quick.ndjson", ecs_lines(2).encode()))
        job_id = body["jobs"][0]["id"]
        wait_for_job(client, job_id, expect="done")

        response = client.delete(f"/api/jobs/{job_id}")
        assert response.status_code == 409, response.text
        assert response.json()["error"]["code"] == "CONFLICT"

    def test_cancelling_an_unknown_job_is_not_found(self, client: TestClient) -> None:
        response = client.delete("/api/jobs/does-not-exist")
        assert response.status_code == 404, response.text
        assert response.json()["error"]["code"] == "NOT_FOUND"


class TestWorkerBatchBoundaries:
    """The worker emits every record exactly once, whatever the batch size.

    This is the boundary the duplication bug lived on, so it is tested at the
    worker entry point with small batch sizes: the same hand-off is exercised
    hundreds of times in milliseconds, and the sizes that straddle the boundary
    are the ones that matter.
    """

    @staticmethod
    def _run(path: Path, *, batch_size: int, records: int) -> list[ParseBatch]:
        """Parse ``path`` through the real worker function, collecting batches."""
        bridge = _CapturingBridge()
        parse_and_emit(
            ParseRequest(
                case_id="case",
                source_id="source",
                path=str(path),
                filename=path.name,
                log_type="generic_json",
                max_line_bytes=1_000_000,
                batch_size=batch_size,
            ),
            bridge,  # type: ignore[arg-type]
        )
        del records
        return [payload for tag, payload in bridge.messages if tag == TAG_BATCH]

    @pytest.mark.parametrize(
        ("records", "batch_size"),
        [
            (1, 5),
            (5, 5),  # exactly one batch, no hand-off
            (6, 5),  # one over: a second batch of one
            (20, 5),
            (5000, 5000),  # exactly the production batch size
            (5001, 5000),  # one over the production batch size
        ],
    )
    def test_each_record_is_emitted_exactly_once(
        self, tmp_path: Path, records: int, batch_size: int
    ) -> None:
        path = tmp_path / f"{records}-{batch_size}.ndjson"
        path.write_text(ecs_lines(records), encoding="utf-8")

        batches = self._run(path, batch_size=batch_size, records=records)

        emitted = [event.message for batch in batches for event in batch.events]
        assert len(emitted) == records
        assert len(set(emitted)) == records
        assert all(len(batch.events) <= batch_size for batch in batches)

    def test_failures_are_batched_and_counted_once(self, tmp_path: Path) -> None:
        """A file of nothing but malformed records still crosses in batches."""
        records = 250
        path = tmp_path / "bad.ndjson"
        path.write_text('{"not": "a log line"}\n' * records, encoding="utf-8")

        batches = self._run(path, batch_size=100, records=records)

        failures = [failure for batch in batches for failure in batch.failures]
        assert len(failures) == records
        assert all(not batch.events for batch in batches)


class TestHostileArchives:
    """zip-slip, symlink and bomb fixtures are rejected at upload (spec 11 phase 1).

    Each of these is a way a real archive has escaped a destination directory or
    filled a disk, so the rejection has to happen at the API boundary: by the time
    intake returns, nothing hostile may have been written.
    """

    def _reject(
        self, client: TestClient, case_id: str, payload: bytes, code: str
    ) -> dict[str, Any]:
        """Upload an archive that must be refused, and assert the specific reason.

        The code is asserted rather than merely "some 4xx": a bomb caught by the
        upload-size limit instead of the expansion limit is still a rejection, but
        it is a different one, and these tests exist to pin down which defence
        actually fired.
        """
        response = client.post(
            f"/api/cases/{case_id}/sources",
            files=[("files", ("evil.zip", io.BytesIO(payload), "application/zip"))],
        )
        assert response.status_code >= 400, response.text
        body: dict[str, Any] = response.json()
        assert body["error"]["code"] == code, body
        return body

    @pytest.mark.parametrize(
        ("member", "code"),
        [
            ("../escape.ndjson", "FORBIDDEN_PATH"),
            ("../../etc/cron.d/evil", "FORBIDDEN_PATH"),
            ("/etc/passwd", "FORBIDDEN_PATH"),
            ("sub/../../escape.ndjson", "FORBIDDEN_PATH"),
            ("C:/Windows/evil.ndjson", "FORBIDDEN_PATH"),
            ("//server/share/evil.ndjson", "FORBIDDEN_PATH"),
            ("nested/../../../escape.ndjson", "FORBIDDEN_PATH"),
        ],
    )
    def test_zip_slip_is_refused(
        self, client: TestClient, case_id: str, member: str, code: str
    ) -> None:
        body = self._reject(client, case_id, hostile_zip(member, ecs_lines(1).encode()), code)
        assert body["error"]["message"]

    def test_symlink_member_is_refused(self, client: TestClient, case_id: str) -> None:
        """A symlink to a path outside the destination is refused, not followed."""
        payload = hostile_zip("link.ndjson", b"../../etc/passwd", symlink=True)
        self._reject(client, case_id, payload, "FORBIDDEN_PATH")

    def test_expansion_bomb_is_refused(self, client: TestClient, case_id: str) -> None:
        """A small archive that expands to many megabytes is refused before writing."""
        payload = zip_bomb()
        # The fixture only means anything if it really is a bomb: a few hundred bytes
        # of highly compressible data expanding to tens of megabytes.
        assert len(payload) < 200_000
        self._reject(client, case_id, payload, "ARCHIVE_LIMIT_EXCEEDED")

    def test_nothing_is_stored_when_an_archive_is_refused(
        self, client: TestClient, case_id: str
    ) -> None:
        """A refused upload leaves no source row and no job behind."""
        self._reject(
            client,
            case_id,
            hostile_zip("../escape.ndjson", ecs_lines(1).encode()),
            "FORBIDDEN_PATH",
        )

        assert client.get(f"/api/cases/{case_id}/sources").json()["total"] == 0
        assert client.get(f"/api/cases/{case_id}/jobs").json()["total"] == 0

    def test_the_server_is_still_healthy_after_a_bomb(
        self, client: TestClient, case_id: str
    ) -> None:
        """A rejected bomb must not have taken the request thread with it."""
        self._reject(client, case_id, zip_bomb(), "ARCHIVE_LIMIT_EXCEEDED")

        assert client.get("/api/health").status_code == 200
        body = upload(client, case_id, ("after.ndjson", ecs_lines(2).encode()))
        wait_for_job(client, body["jobs"][0]["id"], expect="done")
        assert source_state(client, body["sources"][0]["id"])["event_count"] == 2


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


class LiveServer:
    """A real uvicorn server plus a real WebSocket client.

    The ASGI transport behind ``TestClient`` cannot complete the WebSocket
    handshake in this Starlette release, so progress subscriptions are exercised
    the way an analyst's browser does it: over a socket, against a running server.
    """

    def __init__(self, settings: Settings) -> None:
        self.port = _free_port()
        resolved = settings.model_copy(
            update={"server": settings.server.model_copy(update={"port": self.port})}
        )
        self.settings = resolved
        self.base_url = f"http://127.0.0.1:{self.port}"
        self._server = uvicorn.Server(
            uvicorn.Config(
                create_app(resolved),
                host="127.0.0.1",
                port=self.port,
                log_level="critical",
            )
        )
        self._thread = threading.Thread(target=self._server.run, daemon=True)

    @property
    def ws_url(self) -> str:
        return f"ws://127.0.0.1:{self.port}/api"

    def start(self) -> None:
        self._thread.start()
        deadline = time.monotonic() + 30
        while not self._server.started and time.monotonic() < deadline:
            time.sleep(0.05)
        assert self._server.started, "uvicorn did not start in time"

    def stop(self) -> None:
        self._server.should_exit = True
        self._thread.join(timeout=30)

    def client(self) -> httpx.Client:
        return httpx.Client(base_url=self.base_url, timeout=30)

    def connect(self, path: str) -> Any:
        """Open a subscription and return the socket with a short read timeout."""
        # ``legacy=True`` because the socket is used directly rather than as a
        # context manager; websockets 17 otherwise warns on every read.
        socket_ = connect(f"{self.ws_url}{path}", open_timeout=20, legacy=True)
        socket_.timeout = 2  # type: ignore[attr-defined]  # present at runtime, absent from the stubs
        return socket_

    def drain(self, socket_: Any, seconds: float = 2.0) -> list[dict[str, Any]]:
        """Read frames until the socket goes quiet for a moment."""
        frames: list[dict[str, Any]] = []
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            try:
                remaining = max(0.1, deadline - time.monotonic())
                frames.append(json.loads(socket_.recv(timeout=remaining)))
            except TimeoutError:
                break
        return frames


@pytest.fixture
def live_server(settings: Settings) -> Iterator[LiveServer]:
    server = LiveServer(settings)
    server.start()
    try:
        yield server
    finally:
        server.stop()


def live_upload(client: httpx.Client, case_id: str, name: str, text: str) -> Any:
    response = client.post(
        f"/api/cases/{case_id}/sources",
        files={"files": (name, text, "application/octet-stream")},
    )
    assert response.status_code == 202, response.text
    return response.json()


def live_wait(client: httpx.Client, job_id: str, expect: str | None = None) -> dict[str, Any]:
    deadline = time.monotonic() + JOB_TIMEOUT_SECONDS
    last: dict[str, Any] = {}
    while time.monotonic() < deadline:
        response = client.get(f"/api/jobs/{job_id}")
        assert response.status_code == 200, response.text
        last = response.json()
        if expect is not None and last["status"] == expect:
            return last
        if last["status"] in TERMINAL:
            return last
        time.sleep(0.05)
    pytest.fail(f"job {job_id} never finished; last status was {last!r}")


class TestWebSocketProgress:
    """An analyst watching a case sees its jobs move, and only its own."""

    def test_case_socket_reports_the_job_lifecycle(self, live_server: LiveServer) -> None:
        with live_server.client() as client:
            case_id = client.post("/api/cases", json={"name": "ws"}).json()["id"]
            socket_ = live_server.connect(f"/ws/cases/{case_id}")
            try:
                body = live_upload(client, case_id, "access.ndjson", ecs_lines(400))
                job = live_wait(client, body["jobs"][0]["id"], expect="done")
                frames = live_server.drain(socket_)
            finally:
                socket_.close()

        assert job["status"] == "done"
        assert frames, "the subscription delivered nothing"
        assert frames[0] == {"type": "ping"}

        stages = [f["stage"] for f in frames if f.get("type") == "job.stage"]
        assert "parsing" in stages
        assert "finalizing" in stages

        updates = [f["job"] for f in frames if f.get("type") == "job.update"]
        assert updates, "no job.update frame arrived"
        assert updates[0]["status"] == "running"
        assert updates[-1]["status"] == "done"
        assert all(update["id"] == job["id"] for update in updates)

        # The counting frames must describe the whole ingest, not just the first batch.
        parsed = [f for f in frames if f.get("type") == "job.stage" and f.get("events")]
        assert max(frame["events"] for frame in parsed) == 400

    def test_job_socket_ignores_another_cases_job(self, live_server: LiveServer) -> None:
        with live_server.client() as client:
            mine = client.post("/api/cases", json={"name": "mine"}).json()["id"]
            theirs = client.post("/api/cases", json={"name": "theirs"}).json()["id"]
            first = live_upload(client, mine, "a.ndjson", ecs_lines(10))
            live_wait(client, first["jobs"][0]["id"], expect="done")

            socket_ = live_server.connect(f"/ws/jobs/{first['jobs'][0]['id']}")
            try:
                second = live_upload(client, theirs, "b.ndjson", ecs_lines(30))
                live_wait(client, second["jobs"][0]["id"], expect="done")
                frames = live_server.drain(socket_)
            finally:
                socket_.close()

        leaked = [f for f in frames if second["jobs"][0]["id"] in json.dumps(f)]
        assert not leaked, f"another case's job leaked onto this subscription: {leaked}"
        # Nothing at all is expected: the watched job finished before we subscribed.
        assert [f for f in frames if f.get("type") != "ping"] == []


def prose_file(lines: int = 20) -> bytes:
    """A file no parser claims: plain sentences, one per line.

    Distinct lines matter: the count that reaches the parser after a forced
    resolve is the number of lines, and a single run-on line is one failure.
    """
    return "\n".join(f"analyst note {index}, not a log line" for index in range(lines)).encode()


class TestNeedsInput:
    """A file no parser can read parks the source instead of failing the case."""

    def test_unparseable_file_parks_the_job_and_source(
        self, client: TestClient, case_id: str
    ) -> None:
        body = upload(client, case_id, ("notes.txt", prose_file()))

        job = wait_for_job(client, body["jobs"][0]["id"], expect="needs_input")
        assert job["finished_at"] is not None
        assert job["source_id"] == body["sources"][0]["id"]

        source = source_state(client, body["sources"][0]["id"])
        assert source["status"] == "needs_input"
        assert source["event_count"] == 0
        assert source["log_type"] is None

    def test_a_needs_input_job_is_finished_so_it_cannot_be_cancelled(
        self, client: TestClient, case_id: str
    ) -> None:
        body = upload(client, case_id, ("notes.txt", prose_file()))
        wait_for_job(client, body["jobs"][0]["id"], expect="needs_input")

        response = client.delete(f"/api/jobs/{body['jobs'][0]['id']}")
        assert response.status_code == 409, response.text
        assert response.json()["error"]["code"] == "CONFLICT"

    def test_resolving_with_a_parser_ingests_the_parked_source(
        self, client: TestClient, case_id: str
    ) -> None:
        body = upload(client, case_id, ("notes.txt", prose_file()))
        parked = wait_for_job(client, body["jobs"][0]["id"], expect="needs_input")
        source_id = body["sources"][0]["id"]

        response = client.post(
            f"/api/sources/{source_id}/resolve", json={"log_type": "generic_json"}
        )
        assert response.status_code == 202, response.text
        resolved = response.json()

        assert resolved["job"]["id"] != parked["id"]
        assert resolved["job"]["source_id"] == source_id
        job = wait_for_job(client, resolved["job"]["id"], expect="done")
        assert job["status"] == "done"

        source = source_state(client, source_id)
        assert source["status"] == "done"
        assert source["log_type"] == "generic_json"
        # Prose under a JSON parser is 20 failures, not a lost file.
        assert source["event_count"] == 0
        assert source["error_count"] == 20

        # The parked job is left as history, not rewritten.
        assert client.get(f"/api/jobs/{parked['id']}").json()["status"] == "needs_input"


class TestCasePatch:
    """PATCH /cases/{id} renames, re-describes, and re-times a case."""

    def test_rename_description_and_timezone(self, client: TestClient) -> None:
        case_id = client.post("/api/cases", json={"name": "original"}).json()["id"]
        response = client.patch(
            f"/api/cases/{case_id}",
            json={
                "name": "renamed",
                "description": "scoped",
                "default_timezone": "Europe/Berlin",
            },
        )
        assert response.status_code == 200, response.text
        detail = response.json()
        assert detail["name"] == "renamed"
        assert detail["description"] == "scoped"
        assert detail["default_timezone"] == "Europe/Berlin"

    def test_missing_case_is_404(self, client: TestClient) -> None:
        response = client.patch("/api/cases/does-not-exist", json={"name": "x"})
        assert response.status_code == 404
        assert response.json()["error"]["code"] == "NOT_FOUND"


class TestSourcePatchReparse:
    """PATCH /sources/{id}: a parsing-relevant change schedules a re-parse."""

    def test_noop_patch_returns_200_without_a_new_job(
        self, client: TestClient, case_id: str
    ) -> None:
        body = upload(client, case_id, ("a.ndjson", ecs_lines(3).encode()))
        source_id = body["sources"][0]["id"]
        wait_for_job(client, body["jobs"][0]["id"], expect="done")
        total = client.get(f"/api/cases/{case_id}/jobs").json()["total"]

        # The detected parser is already generic_json, so this changes nothing.
        response = client.patch(f"/api/sources/{source_id}", json={"log_type": "generic_json"})
        assert response.status_code == 200, response.text
        assert response.json()["status"] == "done"
        assert client.get(f"/api/cases/{case_id}/jobs").json()["total"] == total

    def test_a_hint_change_reparses_and_replaces_events(
        self, client: TestClient, case_id: str
    ) -> None:
        body = upload(client, case_id, ("a.ndjson", ecs_lines(3).encode()))
        source_id = body["sources"][0]["id"]
        wait_for_job(client, body["jobs"][0]["id"], expect="done")
        jobs_before = client.get(f"/api/cases/{case_id}/jobs").json()["total"]

        response = client.patch(f"/api/sources/{source_id}", json={"timezone": "UTC"})
        assert response.status_code == 202, response.text
        reparse = response.json()
        assert reparse["job"]["status"] == "queued"
        assert reparse["source"]["timezone"] == "UTC"

        wait_for_job(client, reparse["job"]["id"], expect="done")
        source = source_state(client, source_id)
        # The old events were replaced, not appended: the count stays exactly 3.
        assert source["status"] == "done"
        assert source["event_count"] == 3
        assert source["timezone"] == "UTC"
        assert client.get(f"/api/cases/{case_id}/jobs").json()["total"] == jobs_before + 1
        assert client.get(f"/api/jobs/{body['jobs'][0]['id']}").json()["status"] == "done"

    def test_patching_a_parked_source_with_a_parser_ingests_it(
        self, client: TestClient, case_id: str
    ) -> None:
        body = upload(client, case_id, ("notes.txt", prose_file()))
        parked = wait_for_job(client, body["jobs"][0]["id"], expect="needs_input")
        source_id = body["sources"][0]["id"]

        response = client.patch(f"/api/sources/{source_id}", json={"log_type": "generic_json"})
        assert response.status_code == 202, response.text
        job = wait_for_job(client, response.json()["job"]["id"], expect="done")
        assert job["status"] == "done"

        source = source_state(client, source_id)
        assert source["status"] == "done"
        assert source["log_type"] == "generic_json"
        assert source["event_count"] == 0
        assert source["error_count"] == 20
        assert client.get(f"/api/jobs/{parked['id']}").json()["status"] == "needs_input"

    def test_unknown_log_type_is_refused(self, client: TestClient, case_id: str) -> None:
        body = upload(client, case_id, ("a.ndjson", ecs_lines(1).encode()))
        source_id = body["sources"][0]["id"]
        wait_for_job(client, body["jobs"][0]["id"], expect="done")

        response = client.patch(f"/api/sources/{source_id}", json={"log_type": "not_a_parser"})
        assert response.status_code == 422
        assert response.json()["error"]["code"] == "UNSUPPORTED_FORMAT"


class TestFromPathRecursive:
    """from-path directories expand only when the operator asks for it."""

    def _evidence(self, settings: Settings) -> Path:
        """A directory tree under an allowed import root."""
        folder = settings.storage.resolved_data_dir / "imports" / "evidence"
        (folder / "sub").mkdir(parents=True, exist_ok=True)
        (folder / "a.ndjson").write_text(ecs_lines(2))
        (folder / "sub" / "b.ndjson").write_text(ecs_lines(3))
        (folder / "notes.txt").write_text("plain note, no parser\n")
        return folder

    def test_a_directory_without_recursive_is_refused(
        self, client: TestClient, case_id: str, settings: Settings
    ) -> None:
        folder = self._evidence(settings)
        response = client.post(
            f"/api/cases/{case_id}/sources/from-path", json={"paths": [str(folder)]}
        )
        assert response.status_code == 403
        assert response.json()["error"]["code"] == "FORBIDDEN_PATH"
        assert client.get(f"/api/cases/{case_id}/sources").json()["total"] == 0

    def test_recursive_imports_every_regular_file(
        self, client: TestClient, case_id: str, settings: Settings
    ) -> None:
        folder = self._evidence(settings)
        response = client.post(
            f"/api/cases/{case_id}/sources/from-path",
            json={"paths": [str(folder)], "recursive": True},
        )
        assert response.status_code == 202, response.text
        body = response.json()
        assert {item["filename"] for item in body["sources"]} == {
            "a.ndjson",
            "b.ndjson",
            "notes.txt",
        }
        by_name = {item["filename"]: item["id"] for item in body["sources"]}

        # Jobs and sources share position after the request is stored.
        for job, source in zip(body["jobs"], body["sources"], strict=False):
            if job["source_id"] != source["id"]:
                pytest.fail(f"job {job['id']} was matched to the wrong source")
            wait_for_job(client, job["id"], expect="done")
        assert source_state(client, by_name["a.ndjson"])["event_count"] == 2
        assert source_state(client, by_name["b.ndjson"])["event_count"] == 3

        parked = next(item for item in body["sources"] if item["filename"] == "notes.txt")
        assert source_state(client, parked["id"])["status"] == "needs_input"

        # The originals are copied, never moved.
        assert (folder / "a.ndjson").is_file()
        assert (folder / "sub" / "b.ndjson").is_file()
        assert (folder / "notes.txt").is_file()


class TestConcurrentUploads:
    """Spec 09 section 6: three uploads in flight at once each ingest cleanly."""

    def test_three_concurrent_uploads_ingest_without_losing_events(
        self, client: TestClient, case_id: str
    ) -> None:
        """Three files uploaded at the same time, onto the same case.

        Uploads share the request thread and the writer thread, so the failure
        mode worth looking for is interleaving: one source ending up with
        another's events or counters. Distinct hosts per file make that visible.
        """
        files = [
            ("concurrent-a.ndjson", ecs_lines(3, host="concurrent-a").encode()),
            ("concurrent-b.ndjson", ecs_lines(2, host="concurrent-b").encode()),
            ("concurrent-c.ndjson", ecs_lines(5, host="concurrent-c").encode()),
        ]

        with ThreadPoolExecutor(max_workers=3) as pool:
            futures = [
                pool.submit(upload, client, case_id, (name, payload)) for name, payload in files
            ]
            bodies = [future.result() for future in futures]

        for body in bodies:
            wait_for_job(client, body["jobs"][0]["id"], expect="done")

        listed = client.get(f"/api/cases/{case_id}/sources").json()
        assert listed["total"] == 3
        by_name = {item["filename"]: item for item in listed["items"]}
        assert by_name["concurrent-a.ndjson"]["event_count"] == 3
        assert by_name["concurrent-b.ndjson"]["event_count"] == 2
        assert by_name["concurrent-c.ndjson"]["event_count"] == 5


class TestFtsConsistency:
    """The FTS index is filled by the writer thread, not repaired later."""

    def test_fts_rows_are_written_with_the_event_batch(
        self, client: TestClient, case_id: str, settings: Settings
    ) -> None:
        """Every stored event has one FTS row naming it, searchable via MATCH.

        The events table and the index could disagree in two ways: the batch
        inserting events but not their FTS rows, or the FTS rowid drifting from
        the event id. Both show up here, because the FTS rowid *is* the event id
        (migration 0001, ``content_rowid='id'``).
        """
        body = upload(client, case_id, ("fts.ndjson", ecs_lines(4).encode()))
        wait_for_job(client, body["jobs"][0]["id"], expect="done")

        connection = sqlite3.connect(settings.db_path)
        try:
            by_message = dict(
                connection.execute(
                    "SELECT message, id FROM events WHERE case_id = ? AND message IS NOT NULL",
                    (case_id,),
                ).fetchall()
            )
            assert len(by_message) == 4

            fts_rows = dict(connection.execute("SELECT rowid, message FROM events_fts").fetchall())
            assert fts_rows == {event_id: message for message, event_id in by_message.items()}

            hit_ids = {
                row[0]
                for row in connection.execute(
                    "SELECT rowid FROM events_fts WHERE events_fts MATCH 'request'"
                ).fetchall()
            }
            assert hit_ids == set(by_message.values())
        finally:
            connection.close()


class TestWindowsIngest:
    """A Windows EVTX or Event XML upload reaches the database (Phase 2).

    The parser contract is proved in ``test_ingest_windows.py``; what is worth
    testing here is the seam between the detector, the worker process and the
    writer thread, on the two formats that are binary and namespace-heavy rather
    than line-oriented.
    """

    fixtures = Path(__file__).resolve().parent / "fixtures" / "evtx"

    def test_evtx_upload_is_detected_parsed_and_counted(
        self, client: TestClient, case_id: str
    ) -> None:
        payload = (self.fixtures / "security_logons.evtx").read_bytes()
        body = upload(client, case_id, ("security_logons.evtx", payload))
        job = wait_for_job(client, body["jobs"][0]["id"], expect="done")

        assert job["status"] == "done"
        source = source_state(client, body["sources"][0]["id"])
        assert source["log_type"] == "windows_evtx"
        assert source["status"] == "done"
        assert source["event_count"] == 7
        assert source["error_count"] == 0

    def test_event_xml_upload_is_detected_parsed_and_counted(
        self, client: TestClient, case_id: str
    ) -> None:
        payload = (self.fixtures / "security_logons.xml").read_bytes()
        body = upload(client, case_id, ("security_logons.xml", payload))
        wait_for_job(client, body["jobs"][0]["id"], expect="done")

        source = source_state(client, body["sources"][0]["id"])
        assert source["log_type"] == "windows_event_xml"
        assert source["status"] == "done"
        assert source["event_count"] == 11
        assert source["error_count"] == 0

    def test_evtx_events_are_stored_with_the_mapped_columns(
        self, client: TestClient, case_id: str, settings: Settings
    ) -> None:
        payload = (self.fixtures / "sysmon_attack.evtx").read_bytes()
        body = upload(client, case_id, ("sysmon_attack.evtx", payload))
        wait_for_job(client, body["jobs"][0]["id"], expect="done")

        connection = sqlite3.connect(settings.db_path)
        try:
            rows = connection.execute(
                "SELECT record_ref, event_id, ls_category, event_action, host,"
                " channel, provider, level, process_path, log_type"
                " FROM events WHERE source_id = ? ORDER BY id",
                (body["sources"][0]["id"],),
            ).fetchall()
        finally:
            connection.close()

        assert len(rows) == 120
        first = rows[0]
        assert first[0] == "1742"
        assert first[1] == 1
        assert first[2] == "process_creation"
        assert first[3] == "process_created"
        assert first[5] == "Microsoft-Windows-Sysmon/Operational"
        assert first[6] == "Microsoft-Windows-Sysmon"
        assert first[8] == "C:\\Windows\\SysWOW64\\PING.EXE"
        assert first[9] == "windows_evtx"
        assert {row[9] for row in rows} == {"windows_evtx"}

    def test_a_corrupt_evtx_keeps_its_readable_events_and_reports_the_rest(
        self, client: TestClient, case_id: str
    ) -> None:
        data = bytearray((self.fixtures / "sysmon_attack.evtx").read_bytes())
        data[0x10400:0x10410] = b"\xff" * 16
        body = upload(client, case_id, ("corrupt.evtx", bytes(data)))
        job = wait_for_job(client, body["jobs"][0]["id"])

        assert job["status"] == "done"
        source = source_state(client, body["sources"][0]["id"])
        assert source["error_count"] >= 1
        assert source["event_count"] >= 100


class TestLinuxIngest:
    """A Linux auth log reaches the database end to end (Phase 3).

    The parser contract is proved in ``test_ingest_linux.py``; what matters here
    is the seam from detection through the worker to the stored rows for the
    line-oriented Scenario A log.
    """

    fixtures = Path(__file__).resolve().parent / "fixtures" / "linux"

    def test_auth_log_upload_is_detected_parsed_and_counted(
        self, client: TestClient, case_id: str
    ) -> None:
        payload = (self.fixtures / "auth.log").read_bytes()
        body = upload(client, case_id, ("auth.log", payload))
        job = wait_for_job(client, body["jobs"][0]["id"], expect="done")

        assert job["status"] == "done"
        source = source_state(client, body["sources"][0]["id"])
        assert source["log_type"] == "linux_auth"
        assert source["status"] == "done"
        assert source["event_count"] == 21
        assert source["error_count"] == 0

    def test_scenario_a_brute_force_is_stored(
        self, client: TestClient, case_id: str, settings: Settings
    ) -> None:
        payload = (self.fixtures / "auth.log").read_bytes()
        body = upload(client, case_id, ("auth.log", payload))
        wait_for_job(client, body["jobs"][0]["id"], expect="done")

        connection = sqlite3.connect(settings.db_path)
        try:
            rows = connection.execute(
                "SELECT event_action, event_outcome, user_name, src_ip, log_type"
                " FROM events WHERE source_id = ? ORDER BY id",
                (body["sources"][0]["id"],),
            ).fetchall()
        finally:
            connection.close()

        assert len(rows) == 21
        assert {row[4] for row in rows} == {"linux_auth"}
        failed = [row for row in rows if row[0] == "ssh_failed_password"]
        assert len(failed) == 14
        assert {row[3] for row in failed} == {"185.220.101.45"}
        accepted = rows[15]
        assert accepted[0] == "ssh_accepted_login"
        assert accepted[1] == "success"
        assert "user_added" in {row[0] for row in rows}


#: Destinations the guard tolerates: the app's own multiprocessing IPC talks
#: over loopback, which never leaves the machine, so a full run still uses it.
_LOOPBACK_HOSTS = frozenset({"127.0.0.1", "::1", "localhost"})


def _peer_host(address: object) -> str:
    """The host part of a socket address, however it was spelled."""
    if isinstance(address, tuple) and address:
        return str(address[0])
    if isinstance(address, bytes):
        return address.decode("utf-8", "replace")
    return str(address)


class TestNoOutboundConnects:
    """S-05: a full ingest to report run opens no outbound socket (spec 10 1).

    The guard patches the three ways Python opens a connection and lets only
    loopback through. Every external attempt is recorded and raised, so a run
    that completes proves the enrichment-off policy held end to end: an upload
    (real worker process), a detection pass and a report render.
    """

    def _install(self, monkeypatch: pytest.MonkeyPatch) -> list[str]:
        attempts: list[str] = []
        real_connect = socket.socket.connect
        real_connect_ex = socket.socket.connect_ex
        real_create = socket.create_connection

        def guarded_connect(sock: Any, address: Any, *args: Any, **kwargs: Any) -> Any:
            host = _peer_host(address)
            if host not in _LOOPBACK_HOSTS:
                attempts.append(host)
                raise AssertionError(f"outbound connect attempted: {host}")
            return real_connect(sock, address, *args, **kwargs)

        def guarded_connect_ex(sock: Any, address: Any, *args: Any, **kwargs: Any) -> Any:
            host = _peer_host(address)
            if host not in _LOOPBACK_HOSTS:
                attempts.append(host)
                raise AssertionError(f"outbound connect_ex attempted: {host}")
            return real_connect_ex(sock, address, *args, **kwargs)

        def guarded_create(address: Any, *args: Any, **kwargs: Any) -> Any:
            host = _peer_host(address)
            if host not in _LOOPBACK_HOSTS:
                attempts.append(host)
                raise AssertionError(f"outbound create_connection attempted: {host}")
            return real_create(address, *args, **kwargs)

        monkeypatch.setattr(socket.socket, "connect", guarded_connect)
        monkeypatch.setattr(socket.socket, "connect_ex", guarded_connect_ex)
        monkeypatch.setattr(socket, "create_connection", guarded_create)
        return attempts

    def test_the_guard_fires_on_an_external_destination(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        attempts = self._install(monkeypatch)
        with pytest.raises(AssertionError):
            socket.create_connection(("93.184.216.34", 80), timeout=0.05)
        assert attempts == ["93.184.216.34"]

    def test_a_full_run_performs_zero_outbound_connects(
        self, client: TestClient, case_id: str, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        attempts = self._install(monkeypatch)

        body = upload(client, case_id, ("access.ndjson", ecs_lines(5).encode()))
        assert wait_for_job(client, body["jobs"][0]["id"], expect="done")["status"] == "done"
        assert client.get(f"/api/cases/{case_id}/events/count").json()["count"] == 5

        detect = client.post(f"/api/cases/{case_id}/detect", json={"profile": "full"})
        assert detect.status_code == 202, detect.text
        assert wait_for_job(client, detect.json()["id"], expect="done")["status"] == "done"

        report = client.post(
            f"/api/cases/{case_id}/reports", json={"title": "S-05", "format": "md"}
        )
        assert report.status_code == 202, report.text
        assert wait_for_job(client, report.json()["id"], expect="done")["status"] == "done"

        assert attempts == []
