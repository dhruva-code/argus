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


@pytest_asyncio.fixture(autouse=True)
async def _clean_ratelimit_redis() -> AsyncIterator[None]:
    """app.core.ratelimit hits real Redis (db 15 here, per REDIS_URL above)
    — not stubbed like the job-queue calls above, since testing it against
    a fake would defeat the point. Under httpx.ASGITransport every test
    request resolves to the same client_ip() (no real peer address), so
    the rate-limit counter must be reset per test or one test's failed
    logins would spill into the next and cause order-dependent flakes."""
    import logging

    from app.core.redis import get_redis

    r = get_redis()
    try:
        async for key in r.scan_iter(match="argus:login_fail:*"):
            await r.delete(key)
    except Exception:  # noqa: BLE001 — no local redis available; tests that need it will fail on their own
        logging.getLogger("argus.tests").debug("could not clean rate-limit keys before test", exc_info=True)
    yield


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
    """A client already authenticated as a fresh bootstrap-style admin.

    There is no /api/auth/setup or /register endpoint anymore (single
    bootstrap-admin model — see app/bootstrap_admin.py) — create the
    org/user/membership directly, the same way bootstrap_admin.py does,
    then log in for real through /api/auth/login to exercise the actual
    auth code path.
    """
    from app.core import security
    from app.db import SessionLocal
    from app.models import Membership, Organization, Role, User
    from app.seed_profiles import ensure_builtin_profiles

    email = f"admin-{uuid.uuid4().hex[:8]}@test.local"
    password = "supersecret123!"  # noqa: S105
    async with SessionLocal() as session:
        org = Organization(name="Test Org", slug=f"test-org-{uuid.uuid4().hex[:8]}")
        session.add(org)
        await session.flush()
        user = User(
            email=email,
            full_name="Test Admin",
            password_hash=security.hash_password(password),
            is_superuser=True,
            email_verified=True,
        )
        session.add(user)
        await session.flush()
        session.add(Membership(user_id=user.id, org_id=org.id, role=Role.super_admin))
        await ensure_builtin_profiles(session, org.id)
        await session.commit()

    r = await client.post("/api/auth/login", json={"email": email, "password": password})
    assert r.status_code == 200, r.text
    token = r.json()["access_token"]
    client.headers["Authorization"] = f"Bearer {token}"
    return client
