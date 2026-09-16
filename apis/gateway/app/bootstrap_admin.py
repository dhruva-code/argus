"""Creates the single bootstrap super-admin account and organization —
the only way an Argus account is ever created (see docs/AUTHENTICATION.md;
there is no public registration or invite flow).

Run with:  python -m app.bootstrap_admin  (install.sh does this automatically)

Idempotent — safe to re-run; does nothing if the account already exists
(use --reset-password to rotate the password on an existing account
instead). Unlike app/seed.py (demo/synthetic project data, gated behind
ARGUS_ALLOW_SEED, meant for local dev only), this creates a single real
account meant to actually be used: no demo project, no fake scan history,
no fake tool-health rows.

The password comes from ARGUS_DEFAULT_ADMIN_PASSWORD if set (install.sh
sets this in .env — default "argus", so a fresh install ends with known,
documented credentials instead of a one-time value only visible in that
terminal's scrollback) — otherwise a fresh random one is generated on
every run that creates or resets the account, never hardcoded in source,
never logged. This is a bootstrap credential for initial setup, not a
secure production password — change it (Settings -> Security -> Change
Password, or enable MFA) immediately after first login.
"""

from __future__ import annotations

import argparse
import asyncio
import os
import secrets
import sys

from sqlalchemy import select

from app.core import security
from app.db import SessionLocal, create_all
from app.models import Membership, Organization, Role, User
from app.seed_profiles import ensure_builtin_profiles

DEFAULT_ORG_NAME = "Argus"
DEFAULT_ORG_SLUG = "argus"
# Login is still email-shaped (app.core.types.Email requires it — see its
# docstring on why .local is deliberately accepted), but argus@argus.local
# is as close to a bare "argus" username as that allows while keeping the
# existing, well-tested email-identified auth system unchanged.
DEFAULT_ADMIN_EMAIL = "argus@argus.local"
DEFAULT_ADMIN_NAME = "Argus Admin"


def _generate_password() -> str:
    configured = os.getenv("ARGUS_DEFAULT_ADMIN_PASSWORD", "").strip()
    if configured:
        return configured
    # 24 URL-safe chars ~= 142 bits of entropy — well above the 12-char
    # minimum the rest of the platform enforces on user-chosen passwords.
    return secrets.token_urlsafe(18)


async def bootstrap(*, reset_password: bool = False) -> None:
    await create_all()
    async with SessionLocal() as session:
        org = await session.scalar(select(Organization).where(Organization.slug == DEFAULT_ORG_SLUG))
        if org is None:
            org = Organization(name=DEFAULT_ORG_NAME, slug=DEFAULT_ORG_SLUG)
            session.add(org)
            await session.flush()
            print(f"Created organization: {DEFAULT_ORG_NAME}")

        await ensure_builtin_profiles(session, org.id)

        user = await session.scalar(select(User).where(User.email == DEFAULT_ADMIN_EMAIL))
        password: str | None = None
        if user is None:
            password = _generate_password()
            user = User(
                email=DEFAULT_ADMIN_EMAIL,
                full_name=DEFAULT_ADMIN_NAME,
                password_hash=security.hash_password(password),
                is_superuser=True,
                email_verified=True,
            )
            session.add(user)
            await session.flush()
            print(f"Created user: {DEFAULT_ADMIN_NAME} <{DEFAULT_ADMIN_EMAIL}>")
        elif reset_password:
            password = _generate_password()
            user.password_hash = security.hash_password(password)
            print(f"Password reset for: {DEFAULT_ADMIN_NAME} <{DEFAULT_ADMIN_EMAIL}>")
        else:
            print(f"Account already exists: {DEFAULT_ADMIN_NAME} <{DEFAULT_ADMIN_EMAIL}> — no changes made.")
            print("Re-run with --reset-password to rotate its password.")

        membership = await session.scalar(
            select(Membership).where(Membership.user_id == user.id, Membership.org_id == org.id)
        )
        if membership is None:
            session.add(Membership(user_id=user.id, org_id=org.id, role=Role.super_admin))

        await session.commit()

    if password:
        configured = bool(os.getenv("ARGUS_DEFAULT_ADMIN_PASSWORD", "").strip())
        print("")
        print("=" * 60)
        print("  ARGUS BOOTSTRAP ADMIN CREDENTIALS")
        print(f"  Username (email): {DEFAULT_ADMIN_EMAIL}")
        print(f"  Password:         {password}")
        if configured:
            print("")
            print("  This is a bootstrap credential for initial setup — it is NOT a")
            print("  secure production password. Change it immediately after first")
            print("  login (Settings -> Security -> Change Password), especially for")
            print("  any shared/production/internet-facing deployment.")
        else:
            print("  (freshly generated — shown once, not stored anywhere.)")
        print("=" * 60)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--reset-password",
        action="store_true",
        help="Generate and set a new password for the existing default admin account.",
    )
    args = parser.parse_args()
    asyncio.run(bootstrap(reset_password=args.reset_password))


if __name__ == "__main__":
    sys.exit(main())
