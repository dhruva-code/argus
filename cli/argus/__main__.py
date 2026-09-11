"""`argus` command-line entrypoint.

Examples:
    argus login analyst@demo.argus.test
    argus orgs
    argus use-org <org-id>
    argus projects
    argus project create "New Program" --risk high
    argus scope <project-id>
    argus scope-test <project-id> --host api.example.com
    argus scan start <project-id> --type scope.selftest
    argus scan status <job-id>
    argus jobs
    argus tools
    argus tools check
    argus dashboard
"""

from __future__ import annotations

import argparse
import getpass
import json
import sys
import time

from argus import __version__
from argus.client import ArgusError, Client


def _print(obj) -> None:
    print(json.dumps(obj, indent=2, default=str))


def _table(rows: list[dict], cols: list[str]) -> None:
    if not rows:
        print("(none)")
        return
    widths = {c: max(len(c), *(len(str(r.get(c, ""))) for r in rows)) for c in cols}
    print("  ".join(c.ljust(widths[c]) for c in cols))
    print("  ".join("-" * widths[c] for c in cols))
    for r in rows:
        print("  ".join(str(r.get(c, "")).ljust(widths[c]) for c in cols))


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="argus", description="Argus platform CLI")
    p.add_argument("--version", action="version", version=f"argus {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    lg = sub.add_parser("login", help="authenticate and store a token")
    lg.add_argument("email")
    lg.add_argument("--password")
    lg.add_argument("--mfa")

    sub.add_parser("logout")
    sub.add_parser("whoami")
    sub.add_parser("orgs")
    uo = sub.add_parser("use-org")
    uo.add_argument("org_id")

    sub.add_parser("projects")
    pc = sub.add_parser("project", help="project subcommands")
    pcs = pc.add_subparsers(dest="sub", required=True)
    pcc = pcs.add_parser("create")
    pcc.add_argument("name")
    pcc.add_argument("--program", default="")
    pcc.add_argument("--client", default="")
    pcc.add_argument("--risk", default="moderate", choices=["low", "moderate", "high", "critical"])
    pcg = pcs.add_parser("show")
    pcg.add_argument("project_id")

    sc = sub.add_parser("scope")
    sc.add_argument("project_id")
    st = sub.add_parser("scope-test")
    st.add_argument("project_id")
    st.add_argument("--host", default="")
    st.add_argument("--ip", default="")
    st.add_argument("--port", type=int, default=0)
    st.add_argument("--path", default="")
    st.add_argument("--asn", default="")

    scan = sub.add_parser("scan")
    scans = scan.add_subparsers(dest="sub", required=True)
    ss = scans.add_parser("start")
    ss.add_argument("project_id")
    ss.add_argument("--type", default="scope.selftest", choices=["scope.selftest", "tool.health"])
    ss.add_argument("--watch", action="store_true")
    sst = scans.add_parser("status")
    sst.add_argument("job_id")
    scans.add_parser("stop-all")

    sub.add_parser("jobs")
    tl = sub.add_parser("tools")
    tls = tl.add_subparsers(dest="sub")
    tls.add_parser("check")
    sub.add_parser("dashboard")

    args = p.parse_args(argv)
    c = Client()

    try:
        return _dispatch(c, args)
    except ArgusError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


def _dispatch(c: Client, args) -> int:  # noqa: C901
    if args.cmd == "login":
        pw = args.password or getpass.getpass("Password: ")
        c.login(args.email, pw, args.mfa)
        print(f"logged in as {args.email}")
        orgs = c.get("/api/orgs")
        if orgs and not c.cfg.get("org"):
            c.use_org(orgs[0]["id"])
            print(f"active org: {orgs[0]['name']} ({orgs[0]['id']})")
        return 0

    if args.cmd == "logout":
        c.logout()
        print("logged out")
        return 0

    if args.cmd == "whoami":
        _print(c.get("/api/auth/me"))
        return 0

    if args.cmd == "orgs":
        _table(c.get("/api/orgs"), ["id", "name", "slug", "role"])
        return 0

    if args.cmd == "use-org":
        c.use_org(args.org_id)
        print(f"active org set to {args.org_id}")
        return 0

    if args.cmd == "projects":
        _table(c.get("/api/projects"), ["id", "name", "risk_profile", "scope_rule_count"])
        return 0

    if args.cmd == "project":
        if args.sub == "create":
            proj = c.post(
                "/api/projects",
                {
                    "name": args.name,
                    "program_name": args.program,
                    "client": args.client,
                    "risk_profile": args.risk,
                },
            )
            print(f"created project {proj['id']}")
            return 0
        _print(c.get(f"/api/projects/{args.project_id}"))
        return 0

    if args.cmd == "scope":
        _table(
            c.get(f"/api/projects/{args.project_id}/scope"),
            ["position", "effect", "matcher", "value", "note"],
        )
        return 0

    if args.cmd == "scope-test":
        res = c.post(
            f"/api/projects/{args.project_id}/scope/test",
            {
                "host": args.host,
                "ip": args.ip,
                "port": args.port,
                "path": args.path,
                "asn": args.asn,
            },
        )
        print(f"{'IN SCOPE' if res['allowed'] else 'OUT OF SCOPE'} — {res['reason']}")
        return 0 if res["allowed"] else 2

    if args.cmd == "scan":
        if args.sub == "start":
            params = (
                {"targets": [{"host": "www.example.com"}]}
                if args.type == "scope.selftest"
                else {}
            )
            job = c.post(
                f"/api/projects/{args.project_id}/jobs",
                {"type": args.type, "params": params, "authorization_ack": True},
            )
            print(f"queued job {job['id']}")
            if args.watch:
                _watch(c, job["id"])
            return 0
        if args.sub == "status":
            _print(c.get(f"/api/jobs/{args.job_id}"))
            return 0
        if args.sub == "stop-all":
            c.post("/api/jobs/emergency-stop")
            print("STOP ALL broadcast")
            return 0

    if args.cmd == "jobs":
        _table(
            c.get("/api/jobs"),
            ["id", "type", "status", "result_count", "error_count", "worker"],
        )
        return 0

    if args.cmd == "tools":
        if getattr(args, "sub", None) == "check":
            job = c.post("/api/tools/health-check")
            print(f"health-check job {job['id']}")
            _watch(c, job["id"])
            return 0
        _table(
            c.get("/api/tools"),
            ["name", "health", "installed_version", "enabled", "safety_class"],
        )
        return 0

    if args.cmd == "dashboard":
        _print(c.get("/api/dashboard"))
        return 0

    return 1


def _watch(c: Client, job_id: str) -> None:
    seen = 0
    for _ in range(60):
        events = c.get(f"/api/jobs/{job_id}/events")
        for e in events[seen:]:
            print(f"  [{e['level']:>7}] {e['message']}")
        seen = len(events)
        job = c.get(f"/api/jobs/{job_id}")
        if job["status"] not in ("queued", "running", "paused"):
            print(f"job {job['status']}")
            return
        time.sleep(1)


if __name__ == "__main__":
    raise SystemExit(main())
