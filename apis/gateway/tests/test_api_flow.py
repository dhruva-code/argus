"""End-to-end API flow over ASGI: setup → project → scope → job → dashboard."""

from __future__ import annotations


async def test_setup_is_single_use(client):
    body = {
        "org_name": "Acme",
        "admin_email": "a@acme.test",
        "admin_password": "supersecret123!",
        "admin_name": "A",
    }
    r1 = await client.post("/api/auth/setup", json=body)
    assert r1.status_code == 201
    r2 = await client.post("/api/auth/setup", json=body)
    assert r2.status_code == 409


async def test_login_and_me(client, admin_client):
    r = await admin_client.get("/api/auth/me")
    assert r.status_code == 200
    me = r.json()
    assert me["role"] == "org_admin"
    assert "project.write" in me["permissions"]
    assert len(me["organizations"]) == 1


async def test_builtin_profiles_seeded(admin_client):
    r = await admin_client.get("/api/scan-profiles")
    assert r.status_code == 200
    keys = {p["key"] for p in r.json()}
    assert {
        "passive_only",
        "safe_recon",
        "standard_bug_bounty",
        "deep_recon",
        "continuous_monitoring",
        "custom",
    } <= keys


async def test_project_scope_and_test(admin_client):
    r = await admin_client.post("/api/projects", json={"name": "Bug Bounty A"})
    assert r.status_code == 201, r.text
    pid = r.json()["id"]

    rules = {
        "rules": [
            {
                "effect": "allow",
                "matcher": "wildcard",
                "value": "*.example.com",
                "ports": [],
                "paths": [],
                "note": "scope",
            },
            {
                "effect": "deny",
                "matcher": "domain",
                "value": "admin.example.com",
                "ports": [],
                "paths": [],
                "note": "excluded",
            },
        ]
    }
    r = await admin_client.put(f"/api/projects/{pid}/scope", json=rules)
    assert r.status_code == 200, r.text
    assert len(r.json()) == 2

    r = await admin_client.post(f"/api/projects/{pid}/scope/test", json={"host": "api.example.com"})
    assert r.json()["allowed"] is True
    r = await admin_client.post(f"/api/projects/{pid}/scope/test", json={"host": "admin.example.com"})
    assert r.json()["allowed"] is False
    r = await admin_client.post(f"/api/projects/{pid}/scope/test", json={"host": "evil.com"})
    assert r.json()["allowed"] is False


async def test_invalid_scope_rejected(admin_client):
    r = await admin_client.post("/api/projects", json={"name": "Proj One"})
    pid = r.json()["id"]
    r = await admin_client.put(
        f"/api/projects/{pid}/scope",
        json={
            "rules": [
                {
                    "effect": "allow",
                    "matcher": "cidr",
                    "value": "not-a-cidr",
                    "ports": [],
                    "paths": [],
                    "note": "",
                }
            ]
        },
    )
    assert r.status_code == 422


async def test_job_lifecycle_and_enqueue(admin_client, _stub_redis):
    r = await admin_client.post("/api/projects", json={"name": "Proj One"})
    pid = r.json()["id"]
    r = await admin_client.post(
        f"/api/projects/{pid}/jobs",
        json={"type": "scope.selftest", "params": {"targets": [{"host": "x.example.com"}]}},
    )
    assert r.status_code == 202, r.text
    job = r.json()
    assert job["status"] == "queued"
    assert any(c["kind"] == "enqueue" and c["job_id"] == job["id"] for c in _stub_redis)

    r = await admin_client.get(f"/api/jobs/{job['id']}")
    assert r.status_code == 200

    r = await admin_client.post(f"/api/jobs/{job['id']}/cancel")
    assert r.status_code == 200
    assert r.json()["status"] == "cancelled"
    # Regression: cancelling a still-*queued* job (never claimed by any
    # orchestrator worker) must purge it from the Redis queue — otherwise
    # a worker eventually claims and actually runs it despite the DB
    # already showing it cancelled, tying up a worker slot and blocking
    # every real job queued behind it (the exact "new scan stuck in
    # queued forever" symptom this test guards against).
    assert any(c["kind"] == "purge" and c["job_id"] == job["id"] for c in _stub_redis), (
        "cancelling a queued job must purge it from Redis, or it will still get run later"
    )


async def test_dashboard_shape(admin_client):
    r = await admin_client.get("/api/dashboard")
    assert r.status_code == 200
    d = r.json()
    for key in (
        "projects",
        "active_jobs",
        "exposure_score",
        "job_status_breakdown",
        "jobs_over_time",
        "tools_ok",
    ):
        assert key in d
    assert len(d["jobs_over_time"]) == 14


async def test_viewer_cannot_write(client):
    await client.post(
        "/api/auth/setup",
        json={
            "org_name": "Acme",
            "admin_email": "admin@acme.test",
            "admin_password": "supersecret123!",
            "admin_name": "A",
        },
    )
    login = await client.post(
        "/api/auth/login", json={"email": "admin@acme.test", "password": "supersecret123!"}
    )
    admin_tok = login.json()["access_token"]
    client.headers["Authorization"] = f"Bearer {admin_tok}"

    await client.post(
        "/api/orgs/members",
        json={
            "email": "viewer@acme.test",
            "password": "viewerpass1234!",
            "full_name": "V",
            "role": "viewer",
        },
    )

    login = await client.post(
        "/api/auth/login", json={"email": "viewer@acme.test", "password": "viewerpass1234!"}
    )
    client.headers["Authorization"] = f"Bearer {login.json()['access_token']}"

    r = await client.post("/api/projects", json={"name": "nope"})
    assert r.status_code == 403


async def test_tools_catalog_and_config(admin_client):
    r = await admin_client.get("/api/tools")
    assert r.status_code == 200
    tools = r.json()
    assert {t["name"] for t in tools} >= {"subfinder", "nuclei", "httpx"}

    r = await admin_client.patch("/api/tools/subfinder", json={"enabled": False, "rate_limit_rps": 3})
    assert r.status_code == 200
    assert r.json()["enabled"] is False
    assert r.json()["rate_limit_rps"] == 3


async def test_audit_trail_records_mutations(admin_client):
    await admin_client.post("/api/projects", json={"name": "Audited"})
    r = await admin_client.get("/api/audit-logs")
    assert r.status_code == 200
    actions = {row["action"] for row in r.json()}
    assert "project.create" in actions
    assert "setup.complete" in actions
