"""Test fixtures: isolated SQLite schema per test, Redis calls stubbed."""

from __future__ import annotations

import os
import tempfile
import uuid
from collections.abc import AsyncIterator
from typing import TYPE_CHECKING

import pytest
import pytest_asyncio

if TYPE_CHECKING:
    import httpx
    from sqlalchemy.ext.asyncio import AsyncSession

os.environ.setdefault("ARGUS_ENV", "test")
os.environ.setdefault("JWT_SECRET", "test-secret-do-not-use-in-prod")
os.environ.setdefault("ARGUS_ALLOW_SETUP", "true")
os.environ.setdefault("REDIS_URL", "redis://localhost:6379/15")
os.environ.setdefault("ARGUS_SCHEDULER", "off")

_tmp = tempfile.NamedTemporaryFile(suffix=".sqlite3", delete=False)
os.environ["DATABASE_URL"] = f"sqlite+aiosqlite:///{_tmp.name}"


@pytest.fixture(autouse=True)
def _stub_redis(monkeypatch: pytest.MonkeyPatch) -> list[dict]:
    """Capture enqueued jobs / control messages instead of hitting Redis."""
    captured: list[dict] = []

    async def fake_enqueue(job_id: str, payload: dict) -> None:
        captured.append({"kind": "enqueue", "job_id": job_id, "payload": payload})

    async def fake_control(action: str, job_id: str | None = None) -> None:
        captured.append({"kind": "control", "action": action, "job_id": job_id})

    async def fake_purge(job_id: str) -> None:
        captured.append({"kind": "purge", "job_id": job_id})

    monkeypatch.setattr("app.services.scans.enqueue_job", fake_enqueue)
    monkeypatch.setattr("app.services.scans.send_control", fake_control)
    monkeypatch.setattr("app.services.scans.purge_job_keys", fake_purge)
    return captured


@pytest_asyncio.fixture
async def client() -> AsyncIterator[httpx.AsyncClient]:
    import httpx

    from app.db import Base, engine
    from app.main import create_app

    await engine.dispose()  # drop connections pooled on a prior test's loop
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)

    app = create_app()
    transport = httpx.ASGITransport(app=app)
    try:
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as c:
            yield c
    finally:
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.drop_all)
        await engine.dispose()


@pytest_asyncio.fixture
async def db_session() -> AsyncIterator[AsyncSession]:
    """A raw DB session against a fresh schema (for engine-level unit tests)."""
    from app.db import Base, SessionLocal, engine

    await engine.dispose()
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)
    async with SessionLocal() as session:
        yield session
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
    await engine.dispose()


@pytest_asyncio.fixture
async def admin_client(client):
    """A client already authenticated as a fresh org admin."""
    email = f"admin-{uuid.uuid4().hex[:8]}@test.local"
    r = await client.post(
        "/api/auth/setup",
        json={
            "org_name": "Test Org",
            "admin_email": email,
            "admin_password": "supersecret123!",
            "admin_name": "Test Admin",
        },
    )
    assert r.status_code == 201, r.text
    token = r.json()["access_token"]
    client.headers["Authorization"] = f"Bearer {token}"
    return client
